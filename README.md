# PIC Prototyping

**Status: Experimental / Prototyping — non-normative.**

> **Attribution Notice**
> This work is based on the **Provenance Identity Continuity (PIC) Model**, a theoretical framework created by **Nicola Gallo**.
> This repository and all related materials are published and maintained by **Nitro Agility S.r.l.**
> This repository is **non-normative**: the [PIC Specification](https://github.com/pic-protocol/pic-spec) always takes precedence.

Runnable **reference prototypes** for the **Provenance Identity Continuity (PIC) protocol** — real signed
`PCA`s, real Ed25519 signatures, real verification, no network and no server. They exist to *show* how PIC
propagates authority across services and AI agents, and how it prevents the classic Confused Deputy attack
**structurally** rather than by policy.

⚠️ This repository is **NOT** the PIC Spec and is **NOT** normative. It is a teaching / exploration tool.

---

## Quick start (a few clicks)

Everything runs through a single [Taskfile](https://taskfile.dev). No build step to remember, no config.

```sh
# 1. Install the prerequisites once (macOS / Homebrew — see "Prerequisites" for other systems)
brew install go-task go rust python3

# 2. See the whole v0.2 prototype run, end to end, with colored output
task v0-2-go-tour        # Go track
task v0-2-rust-tour      # Rust track (same output, other language)

# 3. Prove it's real: build + tests, both languages, green check
task v0-2-check
```

New here? Run `task v0-2-go-tour` first — it plays every scenario in sequence and is the fastest way to
understand what PIC does. To browse all commands: `task --list`.

---

## Which version do I follow?

This repo keeps two prototype generations side by side. **Follow `v0.2`.**

| Version    | Track(s)      | Status                      | What it is                                                                                                                                                  |
| ---------- | ------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`v0.2`** | **Go + Rust** | ✅ **Current — follow this** | The prototype that tracks the current specs (Prover/Verifier, Revocation, Sandboxed Execution). Both languages produce **byte-identical** signed artifacts. |
| `v0.1`     | Rust only     | 🗄️ Legacy — reference only | The first exploration (workload identity + a workload runner + a `core` crate). Superseded by `v0.2`; kept for history.                                     |

```text
pic-prototyping/
├── Taskfile.yml          ← every command lives here
├── v0.2/                 ← FOLLOW THIS
│   ├── golang/           ← Go reference prototype (stdlib only)
│   ├── rust/             ← Rust reference prototype (mirrors Go byte-for-byte)
│   └── fixtures/         ← shared DID identities + signed attestations (both tracks read these)
└── v0.1/
    └── rust-prototyping/ ← legacy Rust exploration
```

Unless you have a reason to look at history, ignore `v0.1` and work entirely in `v0.2`.

---

## Prerequisites

You only need these to run the `v0.2` prototype. Nothing talks to the network.

| Tool                         | Why                                     | Version               |
| ---------------------------- | --------------------------------------- | --------------------- |
| [Task](https://taskfile.dev) | runs every command in this repo         | v3                    |
| [Go](https://go.dev/dl/)     | the Go track (`v0.2/golang`)            | 1.26+                 |
| [Rust](https://rustup.rs)    | the Rust track (`v0.2/rust`, `v0.1`)    | edition 2021 (stable) |
| Python 3                     | only for `task v0-2-parity` (JSON diff) | 3.x                   |

**Install (macOS / Homebrew):**

```sh
brew install go-task go rust python3
```

**Install (other systems):**

- Task — <https://taskfile.dev/installation/> (or `go install github.com/go-task/task/v3/cmd/task@latest`)
- Go — <https://go.dev/dl/>
- Rust — `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` (<https://rustup.rs>)

**Verify:**

```sh
task --version && go version && cargo --version && python3 --version
```

You don't "install" the prototype itself — `task` compiles and runs it on demand from source.

---

## What the prototype demonstrates

The `v0.2` demo (`picdemo`) runs on shared [fixtures](v0.2/fixtures) — real DID identities and signed
attestations, loaded once into memory. Each scenario is a standalone command; the *tour* tasks play them in
sequence.

| Scenario                | Command (Go)                           | What it proves                                                                                                           |
| ----------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| **why-pic**             | `task v0-2-go-demo -- why-pic`         | Authority mixing across lineages is **inexpressible**: a buggy composition fails non-expansion.                          |
| **confused-deputy**     | `task v0-2-go-demo -- confused-deputy` | The classic cross-service attack is **structurally impossible** (see the worked example below).                          |
| **snapshot**            | `task v0-2-go-demo -- snapshot`        | Snapshot Hash Chain profile: verify `O(hops since snapshot)` instead of `O(n)` — timings shown.                          |
| **revocation**          | `task v0-2-go-demo -- revocation`      | `LINEAGE-SUFFIX` cutoff rejects a hop **and everything causally after it**; earlier hops stay valid.                     |
| **flow**                | `task v0-2-go-flow`                    | The full execution, hop by hop, colored: authority narrowing + a rogue hop getting rejected.                             |
| **Sandboxed Execution** | `task v0-2-go-exec`                    | **PIC-of-PIC**: an outer `{ENFORCE}` lineage carries a Multi-Lineage Execution; a guardrail permits/denies the crossing. |
| **dump**                | `task v0-2-go-dump`                    | The real signed PCAs as JSON, plus a **live tamper proof** (edit a byte → verification fails).                           |

The **Sandboxed Execution** viewer is interactive — drill into any lineage:

```sh
task v0-2-go-exec               # compact view: outer ENFORCE lineage carrying lineages A + B
task v0-2-go-exec -- A          # drill into one carried (inner) lineage
task v0-2-go-exec -- outer      # the outer ENFORCE lineage (PCA0-G, PCA1-G)
task v0-2-go-exec -- all --pca  # every lineage, full signed PCAs (see the multiLineage field)
task v0-2-go-exec -- --no-guardrail   # debug: inner lineages only, no enforcement
```

Everything above has a `v0-2-rust-*` twin that produces the same output.

---

## Using the Taskfile

Run `task --list` for the full, always-current menu. The headline commands:

**See it all in series (best first run):**

| Task                  | Does                                                                        |
| --------------------- | --------------------------------------------------------------------------- |
| `task v0-2-go-tour`   | Every scenario + flow + Sandboxed Execution + benchmarks (Go), in sequence. |
| `task v0-2-rust-tour` | Same guided tour, Rust track.                                               |
| `task v0-2-sandboxed` | The full Sandboxed Execution showcase in **both** languages, in sequence.   |

**Per-track building blocks (Go = `v0-2-go-*`, Rust = `v0-2-rust-*`):**

| Task suffix   | Does                                                                                          |
| ------------- | --------------------------------------------------------------------------------------------- |
| `…-demo -- X` | Run one scenario `X` (`why-pic`, `confused-deputy`, `snapshot`, `revocation`).                |
| `…-flow`      | Full execution flow, hop by hop (colored ASCII).                                              |
| `…-exec`      | Sandboxed Execution viewer (accepts `-- A`, `-- outer`, `-- all --pca`, `-- --no-guardrail`). |
| `…-dump`      | Dump real signed artifacts as JSON + tamper proof.                                            |
| `…-bench`     | Pretty benchmark report (latency, throughput, snapshot vs full-chain).                        |
| `…-test`      | Unit tests.                                                                                   |
| `…-fixtures`  | Regenerate the shared fixtures (deterministic).                                               |
| `…-check`     | Build + (vet) + test — the green check.                                                       |

**Combined & verification:**

| Task               | Does                                                                                                     |
| ------------------ | -------------------------------------------------------------------------------------------------------- |
| `task v0-2-check`  | Build + test **both** prototypes (Go and Rust).                                                          |
| `task v0-2-parity` | Cross-language proof: the outer PCA + `multiLineage` JSON key structure is **identical** in Go and Rust. |

**Legacy `v0.1` (Rust):** `task v0-1-wk-run`, `task v0-1-core-test`, `task v0-1-codegen`, `task v0-1-*-bench`.

---

## The worked example: Cross-Service Confused Deputy

The canonical example (`task v0-2-go-demo -- confused-deputy`). Three actors, authority carried **only** by
the PCA:

```text
Alice (human, OAuth: {read:/user/*, write:/user/*})
  │  OAuth token
  ▼
Gateway / Mesh  (did:web:gateway.example)   translates identity → PCA_0.  NO resource authority of its own.
  │  PCA
  ▼
Bob — Archive Service  (did:web:archive.example)   forwards the request.  NEVER adds authority.
  │  PCA
  ▼
Carol — Storage  (did:web:storage.example)   executes I/O strictly within what the PCA allows.
```

Carol never inspects the caller's identity — she enforces **only what the PCA allows**. So when Alice tries to
read `/sys/*` "through" Bob, the check is against **Alice's** origin authority, not Bob's:

| Transaction origin | read `/user/*` | read `/sys/*` | write `/user/*` |
| ------------------ | :------------: | :-----------: | :-------------: |
| Bob (service)      |       ❌        |       ✅       |        ❌        |
| Alice (user)       |       ✅        |       ❌       |        ✅        |

`{read:/sys/*} ⊄ {read:/user/*, write:/user/*}` → **denied**. Bob's `/sys/*` authority simply *does not exist*
in Alice's transaction, so no service can "help" a user do something they were never authorized to do. Run the
demo to see the honest forward succeed and the injection attempt get rejected by the Verifier's non-expansion
check — live, on real signatures.

---

## PIC for AI agents & tools (the same model)

Nothing changes for AI agents — only the *executors* change. An agent is just another executor in a PIC
transaction graph:

```text
Alice ──PCA_0──▶ AI Agent A ──PCA_1 ⊆ PCA_0──▶ Tool / API
                    │
                    └──PCA_2 ⊆ PCA_0──▶ AI Agent B ──PCA_3 ⊆ PCA_2──▶ Tool / API
```

- Each hop receives a **causally derived** PCA; authority only ever **decreases**, never expands.
- The origin (`p_0 = Alice`) is preserved throughout the whole graph.
- Agents never gain independent authority; tools execute only within Alice's original grant.

> **Mental model:** if an *API call* is safe under PIC, an *AI agent* making that call is **equally safe**.

The **Sandboxed Execution** scenario (`task v0-2-go-exec`) extends this: a guardrail can *enforce* a policy over
a multi-lineage crossing without ever holding the underlying authority itself.

---

## Relationship to the PIC Specification

The **PIC Model**, its invariants, and all compliance rules are defined **exclusively** by the PIC
Specification: [github.com/pic-protocol/pic-spec](https://github.com/pic-protocol/pic-spec). This repository
holds **experimental examples** only. **In case of conflict, the PIC Specification always takes precedence.**

Track-level detail lives in the sub-READMEs: [`v0.2/golang`](v0.2/golang/README.md),
[`v0.2/rust`](v0.2/rust/README.md), [`v0.2/fixtures`](v0.2/fixtures/README.md).

---

## Governance & contributions

Process and responsibilities are defined by: `GOVERNANCE.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
`MAINTAINERS.md`, `SECURITY.md`.

Authorship, attribution requirements, and the normative status of the PIC Model, PIC Spec, and PIC Protocol
documents are defined **exclusively** in the PIC Specification (Appendix B). In case of conflict, the applicable
`LICENSE` files and the normative text of the PIC Specification and any Official PIC Protocol specifications
take precedence over this README.
