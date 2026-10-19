# DSD + DPP — Threat Model v0.1

Status: **Draft — update after every adversarial test**

## 1. Assets and desired properties

Assets: customer records, data integrity, application availability, authorization policy, signing keys, audit evidence, trusted backup/recovery snapshots. Desired properties: no unauthorized reads/exports/writes; limited lateral movement; integrity-verifiable logging; controlled restoration. Availability and confidentiality may conflict and must be declared per asset.

## 2. Trust boundary

```
Untrusted callers / compromised agents
              |
     [Authenticated gateway]
              |
     [PEP — enforced on every operation]  <---  [PDP / versioned signed policy]
              |                                         |
         Protected API                            [Lease store]
              |                                         |
       Synthetic data store                      [State controller]
              |
      Independent evidence sink <--- decision / outcome events

DSD OBO / MCCP / MVPL / CHD ---> risk and verification signals ---> PDP inputs
```

The DSD signal pipeline is outside the authorization root of trust. A validator result alone cannot grant permission. The PEP, policy configuration, key material and independent evidence sink are critical trusted components; compromise there invalidates many guarantees.

## 3. Adversaries and assumptions

1. Credential thief with an otherwise valid user token.
2. Prompt-injection operator controlling input seen by an AI agent.
3. Malicious insider with bounded business privileges.
4. Exploiter of an unpatched application or API vulnerability.
5. Attacker able to interrupt the AI analyzer, identity provider or human approval channel.
6. Attacker attempting evidence deletion or backup poisoning.

Assume attackers can observe public weather data and protocol behavior, induce retries, race requests, and probe validation logic. Do not assume that schema randomization, AI hallucination traps, or publicly retrievable external anchors are secrets. A root compromise of the PEP host, stolen policy signing keys, physical access, and sophisticated supply-chain compromise are initially out of scope but explicitly tracked as residual risks.

## 4. Primary abuse cases and mitigations

| Abuse case | Required design control | Residual risk / validation |
|---|---|---|
| Stolen valid credential | Scoped short-lived lease; per-operation PEP; revocation | Approved-scope misuse before detection |
| Prompt injection into defender agent | AI signals never authorize; strict tool and capability bounds | Malicious content inside authorized outputs |
| Access-control bypass | Single guarded data path; integration and bypass testing | Direct DB/admin backdoor exposure |
| Bulk exfiltration | Export denied by default; server-side egress control and quotas | Repeated small authorized reads / screenshots |
| Unauthorized modification | Separate write capability; immutable/versioned recovery | Damage inside permitted write scope |
| Replay / race | Nonce or server-side lease binding; atomic revoke/check | Distributed race; clock skew |
| Policy / identity outage | Fail-closed for protected actions, restrict state | Legitimate work disrupted; DoS |
| Forged verification data | Trusted-source attestation; no PII fragment or weather-only authentication | Identity source compromise |
| Audit log tampering | Separate append-only integrity-checked evidence store | Evidence host or key compromise |
| Backup contamination | Versioned immutable backups; restore integrity drill | Undetected compromise before snapshot |
| Human impersonation at recovery | Independent MFA/attestation and second channel for privileged reset | Insider collusion / approval fatigue |
| DSD classification error | Conservative deterministic PDP | False denial / delayed containment |

## 5. Misuse and safety boundaries

Containment and observation occur only on systems the operator owns or has permission to defend. Never retaliate, invade attacker infrastructure, or route traffic to non-consenting third parties. Honeypots require isolated infrastructure, restricted egress and explicit authorization. Minimize personal information in telemetry and apply retention rules.

## 6. Acceptance criteria

- Prove every protected endpoint, database path and export channel passes enforcement, or document gaps.
- Demonstrate 100% denial of a **defined** test corpus of out-of-scope operations; this does not prove universal security.
- Demonstrate that AI analyzer failure and missing human approval never increase privileges.
- Show no data egress on blocked requests, including concurrency tests.
- Show evidence tampering detection from an independent verifier.
- Complete a restore drill with integrity and approval checks.
- Report latency, false positives, legitimate task completion and containment/recovery times.
- Maintain a residual-risk register and explicit scope exclusions.

## 7. Open design questions

- What is the smallest trusted enforcement boundary (API gateway, application process, DB proxy, enclave)?
- How are keys managed and rotated across hosts?
- How to handle long-lived workflows without creating reusable broad privileges?
- Which assets require availability-first emergency exception policies, and who approves them?
- How are nested agents, service accounts and delegated actions attributed?
- Which recovery operations need two independent approvers?
- How can a benchmark distinguish DPP gains from standard least-privilege controls?
