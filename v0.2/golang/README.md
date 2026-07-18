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
modules, no network, no central server required by the model itself.

## What it shows

1. **Cross-Service Confused Deputy prevention** (the classic
   `Alice → Gateway → Bob (Archive) → Carol (Storage)` scenario). PIC makes the
   attack *structurally impossible*, two ways:
   - an honest forward carries only Alice's authority, so Carol's PDP denies the
     out-of-scope `read:/sys/*`;
   - a malicious executor that tries to *inject* `/sys/*` authority produces a
     PCA that fails the Verifier's **non-expansion** check — it cannot be
     validated as a conforming continuation.
2. **Snapshot Hash Chain profile** (§5.2): a trusted snapshot issuer validates a
   chain up to `PCA[k]`; a downstream Verifier then validates only the hops
   *after* the snapshot — cost `O(hops since snapshot)` instead of `O(n)`. The
   demo prints both timings side by side.
3. **Revocation**: a `LINEAGE-SUFFIX(lineageId, fromCounter)` cutoff rejects a
   hop and everything causally after it, while earlier hops stay valid.

## Requirements

- Go **1.26.3** (the version pinned in [`go.mod`](./go.mod)).

## Run

```bash
# from this directory (v0.2/golang)
go run ./cmd/picdemo            # run every scenario
go run ./cmd/picdemo confused-deputy
go run ./cmd/picdemo snapshot
go run ./cmd/picdemo revocation
```

Or via [Task](https://taskfile.dev) from the repository root:

```bash
task go-demo        # go run ./cmd/picdemo
task go-test        # go test ./...
task go-bench       # go test -bench . -benchmem ./...
```

## Test and benchmark

```bash
go test ./...                       # unit tests
go test -bench . -benchmem ./...    # benchmarks (prove, verify, snapshot vs full-chain)
go vet ./...
```

## Layout

```text
v0.2/golang
├── go.mod
├── cmd/picdemo/main.go     # CLI: runs the scenarios, prints timings
├── pic/                    # the PIC library (stdlib only)
│   ├── crypto.go           # Ed25519 keys, key registry, canonical JSON, SHA-256 digest
│   ├── types.go            # PCA, PoR, Attestation, Envelope, Snapshot, Revocation
│   ├── authority.go        # operations subset, glob match, attenuation, conformance
│   ├── prover.go           # Prover: mint PCA0, build + sign successor PCA, envelope
│   ├── verifier.go         # Verifier: origin + per-hop checks (Prover/Verifier spec §3.3)
│   ├── snapshot.go         # Snapshot Hash Chain profile (§5.2)
│   ├── revocation.go       # lineageId derivation, LINEAGE-SUFFIX store and check
│   ├── pic_test.go         # unit tests
│   └── bench_test.go       # benchmarks
└── scenario/confuseddeputy.go   # actors and the confused-deputy use cases
```

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
