# Dynamic Schema Defense
## A Structural Response to AI-Driven Attacks

> "A moving target cannot be aimed at."

---

## The Problem with Static Protocols

Most security frameworks share a single assumption:

**There is a correct structure. Defend it.**

Attackers operate on the same assumption:

**There is a correct structure. Find it.**

Both sides are playing the same game.

When AI attack systems like Claude Mythos can scan thousands of vulnerabilities in minutes, static defense becomes a race you cannot win by running faster.

The answer is not to run faster.  
The answer is to change the track.

---

## Core Principle: The Structure Itself Must Move

This architecture is built on one foundational idea:

> If the schema changes every session, there is nothing stable to analyze.

This is not encryption.  
This is not obfuscation.  
This is **structural randomization at the protocol layer** — the verification schema itself is regenerated each session, derived from external real-time data that no model can pre-load.

---

## Architecture

<img width="1080" height="603" alt="セキュリティアーキテクチャfix" src="https://github.com/user-attachments/assets/7aaad9f1-8a77-47b0-82b3-b4cda8af3638" />



### Layer 1 — OBO: Observation Before Opinion
Observe field conditions before any judgment is made.  
No assumption. No pre-loaded schema.  
The session begins with observation, not with a fixed question.

### Layer 2 — MCCP: Memory Compression & Classification Protocol
Compress and classify what has been observed.  
Only the minimum necessary context is activated.  
Non-relevant memory layers are structurally blocked — not filtered, blocked.

### Layer 3a — MVPL: Minimal Verification Protocol Layer
The verification schema is generated per session.  
The outer frame — what fields are checked, in what combination, drawn from which positions — is randomized.  
The engine does not change. The question changes.

Example:
- Session 1: digits 2, 3, 7, 9 of ID number + first character of surname
- Session 2: digits 1, 5, 8, 12 of ID number + reading of given name
- Session 3: current temperature in Nairobi + current average temperature in northern Australia

The third example is not a joke.  
Real-time external data as a verification anchor means RAG-based attack systems must query live APIs every session.  
Pre-loaded knowledge becomes worthless.

### Layer 3b — Drift Intellect
Words and signals drift in from external streams.  
The system selects from them to construct the outer frame.  
The outer frame is never designed in advance — it emerges.

This is the origin of the entire architecture.  
Not theory first. Observation first.

### Layer 4 — RNC Validator: Responsibility Normalization Contract
Each layer owns exactly one responsibility.  
The verification engine does not own email delivery.  
Email delivery security is the responsibility of the mail provider.  
If the email is compromised, that is Google's layer, not this system's layer.

Responsibility boundaries are structural, not contractual.

---

## Hallucination as a Weapon

AI attack systems hallucinate.  
Under pressure — unknown schema, changing fields, real-time anchors — they fill gaps with plausible-sounding completions.

**CHD (Cognitive Hazard Defense)** turns this into an attack surface.

By mixing decoy patterns into the outer frame, the system induces hallucination in the attacking AI.  
The attacker confidently submits a response based on a schema that does not exist.  
CHD-P (Pattern Drift indicator) detects the divergence.  
The session is terminated. The event is logged.

The attacker's strength becomes the attack vector against them.

---

## Why RAG Fails Against This

RAG-based systems retrieve and apply pre-learned structural patterns.

Against a static protocol: effective.  
Against a schema that changes every 30 minutes using live weather data from three cities the system randomly selected 20 minutes ago: not effective.

There is no corpus to retrieve from.  
There is no pattern to match.  
There is only a live query that must be executed now, against data that will be different in 30 minutes.

---

## Responsibility Separation

| Layer | Responsibility | Owner |
|---|---|---|
| Schema generation | Randomized outer frame | This system |
| Verification engine | Condition matching | MVPL |
| Context compression | Minimum load | MCCP |
| Hazard detection | Hallucination patterns | CHD |
| Email delivery | Secure transmission | Mail provider (Google etc.) |
| ID infrastructure | Source data integrity | Government / MyNumber |

Each layer is responsible for exactly one thing.  
Failure in one layer does not cascade unless the boundary is violated.

---

## What This Is Not

This is not a prompt engineering technique.  
This is not a RAG optimization.  
This is not a stronger password policy.

This is a **schema-level dynamic defense architecture** built from two years of field observation of how information actually moves, drifts, and collapses.

Theory did not produce this.  
Field observation produced this.  
Theory confirmed it later.

---

## Origin

This architecture traces back to [drift-intellect](https://github.com/hanabokur0/drift-intellect) —  
a tool built to observe how meaning emerges from drifting words,  
without touching the API,  
without changing the engine,  
by changing only what flows through the outer frame.

The security application is the same principle.  
Different domain. Same structure.

---

## Related Repositories

- [LoPAS-Studio](https://github.com/hanabokur0/LoPAS-Studio) — Architecture design tool
- [LoPAS-MCCP](https://github.com/hanabokur0/LoPAS-MCCP) — Memory Compression & Classification Protocol
- [MVPL](https://github.com/hanabokur0/MVPL-Minimal-Verification-Protocol-Layer) — Minimal Verification Protocol Layer
- [LoPAS-CHD-Protocol](https://github.com/hanabokur0/LoPAS-CHD-Protocol) — Cognitive Hazard Defense
- [drift-intellect](https://github.com/hanabokur0/drift-intellect) — Origin of the outer frame concept

---

## Status

| Component | Status |
|---|---|
| Schema randomization principle | ✔ defined |
| MVPL outer frame | ✔ implemented |
| MCCP compression layer | ✔ implemented |
| Realtime anchor concept | ✔ defined |
| CHD hallucination trap | ⚠ experimental |
| Full integration | in progress |

---

## License

MIT  
Intended for research, defense, and infrastructure protection.

---

*Designed by Hanabokur0 as part of the LoPAS framework ecosystem.*  
*Built inductively from field observation. Not derived from theory — theory confirmed it later.*
