# DPP — Damage Prevention Protocol v0.1

Status: **Draft / research prototype**  
Project: Dynamic-Schema-Defense (DSD)  
Goal: **Constrain the consequences of compromise, even after an attacker has obtained a valid credential.**

## 1. Scope and non-goals

DPP is an enforcement and recovery orchestration layer placed *after* DSD observation and verification. It protects defined operations and resources; it cannot guarantee that all harm is impossible. It does not replace authentication, patching, endpoint hardening, network protection, backups, or incident response.

The v0.1 test target is a synthetic customer-record API. Every read and export must pass through a non-bypassable reference monitor. A compromised application or administrative host **outside** the trusted computing base is assumed possible; compromise of the enforcement host, policy signing keys, or independent audit infrastructure is out of scope for the first prototype and must be tested separately.

## 2. Trust boundaries and components

- **DSD inputs**: OBO observations; MCCP classifications; MVPL verification result; CHD warning signals; RNC responsibility boundary declarations. These are advisory signals, **not authorization proofs**.
- **Identity provider**: independently authenticates the caller. Avoid PII-derived knowledge-based authentication and public real-time values as secrets.
- **Policy Decision Point (PDP)**: deterministic allow/deny decisions, default-deny, with versioned signed policy.
- **Policy Enforcement Point (PEP)**: checks *every* protected operation before accessing data. Must not expose an unguarded alternative route.
- **Lease issuer**: short-lived, audience-, subject-, resource-, operation- and session-bound capabilities. Reject replay and expired leases; token lifetime is configurable, not an assurance by itself.
- **State controller**: transitions between NORMAL, RESTRICTED, QUARANTINED, RECOVERY_PENDING; all transitions are auditable.
- **Evidence service**: append-only, integrity-verified audit logs with independent storage; redact sensitive fields.
- **Recovery controller**: restores from trusted immutable snapshots and checks integrity plus appropriate human approval, without trusting the compromised session.

**Security invariant:** No DSD/AI output may expand privilege. Only the signed PDP policy and independently verified identity/context may grant capabilities. A failed, timed-out, unavailable, or ambiguous decision **cannot grant additional permission**.

## 3. State machine

| Current | Event | Next | Enforcement |
|---|---|---|---|
| NORMAL | Valid authorized request | NORMAL | Permit only requested bounded action |
| NORMAL | Risk signal or uncertain verification | RESTRICTED | Deny export and privileged writes; require revalidation |
| RESTRICTED | Confirmed compromise / repeated prohibited operation | QUARANTINED | Revoke leases, reject protected access, retain evidence |
| RESTRICTED | Independently verified clearance | NORMAL | Issue *new*, reduced-scope lease; never resurrect old tokens |
| QUARANTINED | Authorized recovery initiated | RECOVERY_PENDING | Preserve isolation; snapshot and analyze |
| RECOVERY_PENDING | Integrity + approvals pass | RESTRICTED | Re-enable read-only then graduate to NORMAL through explicit policy |
| Any state | Missing evaluator / lost human contact | Same or stricter | No fail-open and no automatic privilege expansion |

State transitions must be serialized and idempotent; stale concurrent requests cannot revive revoked grants. Deny decisions occur at the PEP even when the analyzer is unavailable. The exact handling of mission-critical availability exceptions must be pre-approved per resource and must never silently override confidentiality controls.

## 4. Authorization contract

Example request to PDP (pseudodata):

```json
{
  "principal_id": "agent-demo-1",
  "session_id": "sess-001",
  "resource": "customer-record/42",
  "operation": "read",
  "context": {"state": "RESTRICTED", "device_attested": false},
  "lease_id": "lease-123"
}
```

Example response:

```json
{
  "decision": "DENY",
  "reason_code": "STATE_RESTRICTED",
  "policy_version": "dpp-0.1",
  "evidence_id": "evt-001"
}
```

Policy rules: deny by default; exact audience/resource/operation; cryptographic signature or secure server-side lease; server-side expiration and revocation; protect against race conditions and replay; enforce per-request before side effects. Static schema rotation may raise the cost of probing, but must not substitute for cryptographic authentication or authorization.

## 5. Evidence and recovery

Log minimal actor/session pseudonyms, monotonic ordering, decision, policy hash, correlation ID, outcome and integrity link. Store in independent write-restricted infrastructure with controlled access and retention. Hash chaining alone is insufficient if the attacker controls the whole log system. Never log secrets or raw PII.

Recovery must: (1) isolate compromised credentials and runtime; (2) determine blast radius; (3) restore from independently verified clean artifacts; (4) verify record integrity and policy versions; (5) require an independent approval path for privileged restoration; (6) run in RESTRICTED before NORMAL. Human unavailability keeps the system at equal or lower privilege; do not conduct counterattacks or trace outside owned systems.

## 6. v0.1 validation suite

Use synthetic data only; compare to a baseline API with standard static roles under identical workloads.

| Test | Required assertion |
|---|---|
| Stolen valid credential | No access beyond explicit scoped lease |
| Out-of-scope record | 100% of attempted out-of-scope reads denied in the test corpus |
| Unauthorized export | Blocked before any outbound payload leaves protected boundary |
| Replayed/expired lease | Denied |
| PDP unavailable | Default-deny for protected operations |
| Concurrent revoke/read | No permitted read after revocation is committed |
| Isolated service recovery | No privileged restoration before integrity checks and independent approval |
| Tampered evidence | Detect corruption or missing events through independent verification |
| Legitimate workload | Measure false blocks, latency and recovery time; publish raw numbers |

Measure attempts, escaped data bytes, false-denial rate, p50/p95/p99 decision latency, containment time, recovery point and recovery time. Do **not** claim superior security until controlled comparisons and red-team evaluation are complete.

## 7. Integration and rollout

Phase A: in-memory Python simulation with all requests passing a PEP.  
Phase B: MVPL adapter returning risk classifications, not direct permissions.  
Phase C: cryptographic capability lease, durable revocation, independently stored audit.  
Phase D: recovery rehearsal, chaos testing and adversarial review.  

Do not deploy the prototype to production or represent it as certified security software.
