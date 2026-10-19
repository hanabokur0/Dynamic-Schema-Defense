"""DPP v0.1 in-process prototype: not a production security boundary."""
import copy
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class State(str, Enum):
    NORMAL = 'NORMAL'
    RESTRICTED = 'RESTRICTED'
    QUARANTINED = 'QUARANTINED'
    RECOVERY_PENDING = 'RECOVERY_PENDING'


class Denied(PermissionError):
    pass


@dataclass(frozen=True)
class Lease:
    subject: str
    session: str
    audience: str
    resource: str
    operations: frozenset
    deadline: float
    generation: int


class Evidence:
    """In-memory hash chain. Verification requires separately trusted head."""
    def __init__(self):
        self.events = []
        self.head = '0' * 64

    def append(self, kind, **data):
        event = {'sequence': len(self.events), 'kind': kind, 'data': data, 'previous': self.head}
        event['hash'] = digest(event)
        self.head = event['hash']
        self.events.append(event)

    def verify(self, trusted_head):
        previous = '0' * 64
        for i, event in enumerate(self.events):
            payload = {k: v for k, v in event.items() if k != 'hash'}
            if event['sequence'] != i or event['previous'] != previous or digest(payload) != event['hash']:
                return False
            previous = event['hash']
        return hmac.compare_digest(previous, trusted_head)


class DPP:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.RLock()
        self.state = State.NORMAL
        self.generation = 0
        self.leases = {}
        self.evidence = Evidence()

    def issue(self, *, subject, session, audience, resource, operations, ttl=60):
        with self.lock:
            if self.state != State.NORMAL:
                raise Denied('STATE_BLOCKS_ISSUE')
            if not all((subject, session, audience, resource)) or ttl <= 0:
                raise ValueError('invalid lease arguments')
            if not operations or not set(operations) <= {'read', 'write', 'export'}:
                raise ValueError('invalid operations')
            token = secrets.token_urlsafe(32)
            self.leases[digest(token)] = Lease(subject, session, audience, resource,
                                               frozenset(operations), self.clock() + ttl,
                                               self.generation)
            self.evidence.append('ISSUE', subject=subject, session=session, resource=resource)
            return token

    def transition(self, event):
        transitions = {
            (State.NORMAL, 'risk'): State.RESTRICTED,
            (State.NORMAL, 'compromise'): State.QUARANTINED,
            (State.RESTRICTED, 'compromise'): State.QUARANTINED,
            (State.RESTRICTED, 'clearance'): State.NORMAL,
            (State.QUARANTINED, 'begin_recovery'): State.RECOVERY_PENDING,
            (State.RECOVERY_PENDING, 'verified_restore'): State.RESTRICTED,
        }
        with self.lock:
            target = transitions.get((self.state, event))
            if target is None:
                raise Denied('INVALID_TRANSITION')
            old = self.state
            self.state = target
            self.generation += 1
            self.leases.clear()
            self.evidence.append('STATE', before=old.value, after=target.value, event=event)
            return self.state

    def check(self, *, token, subject, session, audience, resource, operation):
        """Must be called under lock by the enforcement point."""
        lease = self.leases.get(digest(token))
        allowed = (self.state == State.NORMAL and lease is not None
                   and hmac.compare_digest(subject, lease.subject)
                   and hmac.compare_digest(session, lease.session)
                   and hmac.compare_digest(audience, lease.audience)
                   and hmac.compare_digest(resource, lease.resource)
                   and operation in lease.operations
                   and self.clock() < lease.deadline
                   and lease.generation == self.generation)
        self.evidence.append('DECISION', resource=resource, operation=operation,
                             subject=subject, result='ALLOW' if allowed else 'DENY')
        if not allowed:
            raise Denied('ACCESS_DENIED')


class ProtectedStore:
    """All protected operations route through this PEP in this toy implementation."""
    def __init__(self, dpp, records):
        self.dpp = dpp
        self._records = copy.deepcopy(records)
        self._baseline = copy.deepcopy(records)
        self.baseline_digest = digest(records)
        self.outbound_bytes = 0

    def operate(self, *, token, subject, session, audience, resource, operation, replacement=None):
        with self.dpp.lock:
            self.dpp.check(token=token, subject=subject, session=session,
                           audience=audience, resource=resource, operation=operation)
            if resource not in self._records:
                raise Denied('NO_RESOURCE')
            if operation == 'write':
                if not isinstance(replacement, dict):
                    raise ValueError('replacement must be a dict')
                self._records[resource] = copy.deepcopy(replacement)
                self.dpp.evidence.append('WRITE', resource=resource)
                return None
            result = copy.deepcopy(self._records[resource])
            if operation == 'export':
                self.outbound_bytes += len(json.dumps(result).encode())
            self.dpp.evidence.append('COMPLETE', resource=resource, operation=operation)
            return result

    def recover(self, *, independent_approval, source_verified, expected_digest):
        with self.dpp.lock:
            if self.dpp.state != State.RECOVERY_PENDING:
                raise Denied('NOT_RECOVERING')
            if not independent_approval or not source_verified:
                raise Denied('RECOVERY_AUTH_FAILED')
            if not hmac.compare_digest(digest(self._baseline), expected_digest) or not hmac.compare_digest(self.baseline_digest, expected_digest):
                raise Denied('DIGEST_MISMATCH')
            self._records = copy.deepcopy(self._baseline)
            self.dpp.evidence.append('RESTORE', baseline_digest=expected_digest)
            self.dpp.transition('verified_restore')
