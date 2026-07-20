<!--
SPDX-License-Identifier: Apache-2.0
Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.
-->

# PIC — Go reference prototype (v0.2)

**Status: Experimental / Prototyping — non-normative.** The [PIC Specification][spec]
takes precedence. This directory is one language track (Go) of the PIC `v0.2`
prototypes; further tracks (Rust and others) live as sibling directories under
`v0.2/` and are intentionally kept out of the `v0.2/` root.

This prototype demonstrates, with runnable code and benchmarks, the two `v0.2`
specifications:

- [PIC Prover and Verifier Specification][pv] — how a PIC **Prover** builds a
  Proof of Continuity for the next hop and how a **Verifier** validates it. It
  implements the **Snapshot Hash Chain** profile (§5.2), the profile `v0.2`
  orients on. Zero-knowledge / succinct proofs (§5.3) are intentionally out of
  scope here.
- [PIC Revocation Specification][rev] — revocation coordinates (`lineageId`,
  `lineageCounter`, `branchId`) and the native `LINEAGE-SUFFIX` causal cutoff.

It is deliberately **minimal**: the Go **standard library only**
(`crypto/ed25519`, `crypto/sha256`, `encoding/json`, `testing`), no third-party
modules, no network, no central server required by the model itself. It runs on
the shared [`v0.2/fixtures`](../fixtures) — real DID identities and signed
attestations, loaded once into memory (see [Fixtures](#fixtures)).

## What it shows

1. **Authority Mixing / cross-lineage composition** — the
   [PIC site "Why PIC"][whypic] example (and Prover/Verifier spec §1.4). Two
   lineages, `{read-foo, share-files} → {share-files}` and
   `{read-all, backup} → {read-all}`, flow through shared executors. A bug that
   composes `read-all` (from the backup lineage) into the summary lineage
   produces a PCA that fails **non-expansion**: the mixed state is inexpressible,
   while an honest continuation is accepted.
2. **Cross-Service Confused Deputy prevention** (`Alice → Archive → Storage`).
   PIC makes the attack *structurally impossible*, two ways: an honest forward
   carries only Alice's authority, so the storage PDP denies the out-of-scope
   `read:/sys/*`; and a malicious executor that tries to *inject* `/sys/*`
   authority produces a PCA that fails the Verifier's **non-expansion** check.
3. **Snapshot Hash Chain profile** (§5.2): a trusted snapshot issuer validates a
   chain up to `PCA[k]`; a downstream Verifier then validates only the hops
   *after* the snapshot — cost `O(hops since snapshot)` instead of `O(n)`. The
   demo prints both timings side by side.
4. **Revocation**: a `LINEAGE-SUFFIX(lineageId, fromCounter)` cutoff rejects a
   hop and everything causally after it, while earlier hops stay valid.
5. **Sandboxed Execution** (`guardrail`/`exec`, or `--guardrail` on any scenario):
   the canonical **PIC-of-PIC** construction of the PIC Sandboxed Execution spec.
   An authorized sandbox origin originates an **outer ENFORCE lineage** (`PCA0-G`);
   an AI agent holds the user's Lineage Execution A and its own Lineage Execution
   B and proposes the S3 write as one **Multi-Lineage Execution**. The
   **guardrail** — an ordinary executor of the outer lineage — validates every
   carried lineage, evaluates the fixture policy over the **semantic scopes**
   through a simulated PDP (the enforcement function), and on permit proves the
   next ordinary outer PCA (`PCA1-G`) carrying the signed `multiLineage` field and
   `enforcementResult`. There is no sandbox primitive and no envelope: the outer
   PCA *is* the decision. Deny, invalid-carried-lineage, bypass, and tamper cases
   are all shown live, and a receiving hop runs **enforced acceptance**.

## Requirements

- Go **1.26.3** (the version pinned in [`go.mod`](./go.mod)).

## Run

```bash
# from this directory (v0.2/golang)
go run ./cmd/picdemo            # run every scenario
go run ./cmd/picdemo why-pic    # Authority Mixing / cross-lineage composition
go run ./cmd/picdemo confused-deputy
go run ./cmd/picdemo snapshot
go run ./cmd/picdemo revocation

# visual, hop-by-hop execution flow (colored ASCII; authority narrowing + a rejected rogue)
go run ./cmd/picdemo flow
go run ./cmd/picdemo flow --only-json | jq      # the whole flow as one JSON

# colored benchmark report (latency, throughput, snapshot vs full-chain)
go run ./cmd/picdemo bench
go run ./cmd/picdemo bench --only-json | jq

# explore a Sandboxed Execution (guardrail on by default)
go run ./cmd/picdemo exec                        # compact hop diagram: PIC carrying PIC
go run ./cmd/picdemo exec A                       # drill into one carried lineage (or B, outer, all)
go run ./cmd/picdemo exec all --pca               # every lineage, full signed PCAs per hop
go run ./cmd/picdemo exec --no-guardrail          # debug: inner lineages only, no outer ENFORCE lineage

# inspect real signed artifacts + a live tamper proof
go run ./cmd/picdemo dump                        # human-readable
go run ./cmd/picdemo dump --only-json | jq       # one JSON document
go run ./cmd/picdemo dump hop1                   # only one artifact (pca0|hop0, pca1|hop1, envelope)

# Sandboxed Execution (outer ENFORCE lineage + guardrail + simulated PDP over the fixture policy)
go run ./cmd/picdemo guardrail                   # canonical Sandboxed Execution: permit, deny, invalid
go run ./cmd/picdemo all --guardrail             # every scenario, tip crossing through a Sandboxed Execution
go run ./cmd/picdemo flow --guardrail            # the flow's chain crosses a Sandboxed Execution
go run ./cmd/picdemo bench --guardrail           # + sandboxed-crossing timings, decomposed per phase

# sandboxed-execution artifacts (add selectors to filter)
go run ./cmd/picdemo dump --guardrail            # everything, incl. policy, scopes, multiLineage, outer PCA
go run ./cmd/picdemo dump --guardrail policy scopes   # the policy + the scope bindings
go run ./cmd/picdemo dump --guardrail pdp             # enforcement-function exchange: request -> decision
go run ./cmd/picdemo dump --guardrail outer multilineage   # the outer ENFORCE lineage + signed multiLineage
go run ./cmd/picdemo dump --guardrail accept denytrace     # enforced-acceptance checks + the deny case
```

Or via [Task](https://taskfile.dev) from the repository root:

```bash
task v0-2-go-demo               # go run ./cmd/picdemo
task v0-2-go-demo -- snapshot   # pass a scenario to the demo
task v0-2-go-demo -- guardrail                    # the guarded-crossing scenario
task v0-2-go-demo -- dump --guardrail pdp policy  # inspect the PDP exchange + policy
task v0-2-go-test               # go test ./...
task v0-2-go-bench              # go test -bench . -benchmem ./...
```

## Test and benchmark

```bash
go test ./...                       # unit tests
go test -bench . -benchmem ./...    # benchmarks (prove, verify, snapshot vs full-chain)
go vet ./...
```

## Layout

```text
v0.2/fixtures/             # shared DID identities + signed attestations (JSON)
v0.2/golang
├── go.mod
├── cmd/picdemo/main.go     # CLI: runs the scenarios, prints timings
├── cmd/genfixtures/main.go # deterministic generator for v0.2/fixtures
├── fixtureset/load.go      # cached (sync.Once) loader of v0.2/fixtures
├── pic/                    # the PIC library (stdlib only)
│   ├── crypto.go           # Ed25519 keys, key registry, canonical JSON, SHA-256 digest
│   ├── types.go            # PCA, PoR, Attestation, Envelope, Snapshot, Revocation
│   ├── authority.go        # operations subset, glob match, attenuation, conformance
│   ├── prover.go           # Prover: mint PCA0, build + sign successor PCA, envelope
│   ├── verifier.go         # Verifier: origin + per-hop checks (Prover/Verifier spec §3.3)
│   ├── snapshot.go         # Snapshot Hash Chain profile (§5.2)
│   ├── revocation.go       # lineageId derivation, LINEAGE-SUFFIX store and check
│   ├── sandboxed.go        # Sandboxed Execution (PIC of PIC): outer ENFORCE lineage, multiLineage, guardrail, enforced acceptance
│   ├── pic_test.go         # unit tests
│   └── bench_test.go       # benchmarks
└── scenario/               # the Why-PIC use cases, on the fixtures
    ├── authoritymixing.go  # cross-lineage composition (Why PIC; §1.4)
    ├── confuseddeputy.go   # cross-service confused deputy + chain builder
    └── guardrail.go        # canonical Sandboxed Execution (permit / deny / invalid carried lineage)
```

## Fixtures

The demos and benchmarks run on [`v0.2/fixtures`](../fixtures): real DID
identities and signed attestations, in JSON. They are loaded **once** into an
in-memory registry at startup (`fixtureset.Load()`, cached with `sync.Once`), so
benchmarks pay no per-use disk cost. Keys are deterministic (derived from the
actor name), so regeneration is reproducible:

```bash
go run ./cmd/genfixtures     # or: task v0-2-go-fixtures
```

See the [fixtures README](../fixtures/README.md) for the cast and format.

## Scope and disclaimers

This is a **reference prototype for exploration and benchmarking**, not a
production implementation and not the specification. It uses illustrative
choices allowed by the spec (canonical JSON, SHA-256, Ed25519, in-memory key
registry). It does not implement selective disclosure, transport security,
succinct proofs, or a wire format — those are out of scope for this prototype.

In case of conflict, the [PIC Specification][spec] and the applicable `LICENSE`
files take precedence over this document.

## License and attribution

Licensed under the **Apache License, Version 2.0**
(see the repository-root [`LICENSE`](../../LICENSE)).

> Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
> Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

[spec]: https://github.com/pic-protocol/pic-spec
[pv]: https://github.com/pic-protocol/pic-spec/blob/main/draft/0.2/pic-prover-verifier-spec.md
[rev]: https://github.com/pic-protocol/pic-spec/blob/main/draft/0.2/pic-revocation-spec.md
[whypic]: https://pic-protocol.github.io/docs/why-pic/authority-mixing
