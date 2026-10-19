import threading
import unittest
from dpp import DPP, ProtectedStore, State, Denied


class DPPTests(unittest.TestCase):
    def setUp(self):
        self.now = [100.0]
        self.dpp = DPP(clock=lambda: self.now[0])
        self.store = ProtectedStore(self.dpp, {f'customer/{i}': {'id': i, 'synthetic': True} for i in range(100)})
        self.args = dict(subject='agent-1', session='session-1', audience='customer-api', resource='customer/0')
        self.token = self.dpp.issue(**self.args, operations={'read'}, ttl=60)

    def do(self, operation='read', **changes):
        params = dict(token=self.token, **self.args, operation=operation)
        params.update(changes)
        return self.store.operate(**params)

    def test_legitimate_read(self):
        self.assertEqual(self.do()['id'], 0)

    def test_compromised_agent_out_of_scope_99_records(self):
        for i in range(1, 100):
            with self.assertRaises(Denied):
                self.do(resource=f'customer/{i}')

    def test_export_and_write_denied_before_side_effects(self):
        with self.assertRaises(Denied): self.do('export')
        with self.assertRaises(Denied): self.do('write', replacement={'id': 777})
        self.assertEqual(self.store.outbound_bytes, 0)
        self.assertEqual(self.do()['id'], 0)

    def test_stolen_token_wrong_context(self):
        for field, value in [('subject', 'attacker'), ('session', 'stolen-session'),
                             ('audience', 'admin-api')]:
            with self.assertRaises(Denied): self.do(**{field: value})

    def test_expiry(self):
        self.now[0] += 60
        with self.assertRaises(Denied): self.do()

    def test_risk_revokes_and_stays_restricted_without_human(self):
        self.dpp.transition('risk')
        self.assertEqual(self.dpp.state, State.RESTRICTED)
        with self.assertRaises(Denied): self.do()
        with self.assertRaises(Denied): self.dpp.issue(**self.args, operations={'read'})
        self.assertEqual(self.dpp.state, State.RESTRICTED)

    def test_compromise_quarantine(self):
        self.dpp.transition('compromise')
        with self.assertRaises(Denied): self.do()
        self.assertEqual(self.dpp.state, State.QUARANTINED)

    def test_recovery_requires_two_independent_checks(self):
        self.dpp.transition('compromise')
        self.dpp.transition('begin_recovery')
        for approved, verified, checksum in [(False, True, self.store.baseline_digest),
                                             (True, False, self.store.baseline_digest),
                                             (True, True, '0'*64)]:
            with self.assertRaises(Denied):
                self.store.recover(independent_approval=approved, source_verified=verified, expected_digest=checksum)
        self.store.recover(independent_approval=True, source_verified=True,
                           expected_digest=self.store.baseline_digest)
        self.assertEqual(self.dpp.state, State.RESTRICTED)
        with self.assertRaises(Denied): self.do()  # old leases never resurrect
        self.dpp.transition('clearance')
        with self.assertRaises(Denied): self.do()

    def test_evidence_tampering(self):
        trusted = self.dpp.evidence.head
        self.assertTrue(self.dpp.evidence.verify(trusted))
        self.dpp.evidence.events[0]['data']['subject'] = 'tampered'
        self.assertFalse(self.dpp.evidence.verify(trusted))

    def test_revocation_precedes_future_access(self):
        self.dpp.transition('risk')
        results = []
        def attempt():
            try: self.do()
            except Denied: results.append('DENY')
        threads = [threading.Thread(target=attempt) for _ in range(25)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(results, ['DENY'] * 25)

    def test_unknown_transition_fails_closed(self):
        with self.assertRaises(Denied): self.dpp.transition('human_missing')
        self.assertEqual(self.dpp.state, State.NORMAL)


if __name__ == '__main__':
    unittest.main()
