<!--
SPDX-License-Identifier: Apache-2.0
Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.
-->

# PIC v0.2 fixtures

Shared, language-independent test fixtures for the `v0.2` prototypes (the Go
track under [`golang/`](../golang), and future tracks). They provide **real,
deterministic identities and signed attestations** so the demos and benchmarks
run on the same cast, in JSON.

These are **throwaway credentials for demos and tests only** — the private keys
are intentionally committed and MUST NOT be used for anything real.

## Layout

```text
identities/<actor>/did.json      # W3C DID document (Ed25519 public key)
identities/<actor>/private.jwk   # Ed25519 JWK with the private seed (d)
attestations/<executor>.json     # a signed PIC attestation (issuer: org-authority)
guardrail/policy.json            # Execution Guardrail policy (spec-shaped, CEL-like condition)
guardrail/scopes.json            # semantic-scope bindings (grantId / origin issuer -> scopes)
```

## Cast

| Actor | DID | Role |
| --- | --- | --- |
| `alice` | `did:web:alice.example` | origin principal (human user) |
| `org-authority` | `did:web:org-authority.example` | attestation issuer |
| `snapshot-issuer` | `did:web:snapshot.example` | trusted snapshot validator (§5.2) |
| `gateway` | `did:web:gateway.example` | executor (deterministic) |
| `backup-service` | `did:web:backup.example` | executor (deterministic) — Lineage 2 |
| `summary-service` | `did:web:summary.example` | executor (agentic) — Lineage 1 |
| `archive-service` | `did:web:archive.example` | executor (deterministic) |
| `storage-service` | `did:web:storage.example` | executor (deterministic) |
| `guardrail` | `did:web:guardrail.example` | Execution Guardrail (signs `guardrailProof`) |
| `sandbox` | `did:web:sandbox.example` | sandbox / forwarder (signs `forwardingProof`) |

The executor attestations carry `role`, `compliance`, `executionModel`,
`environment`, and `region`, signed by `org-authority` with a wide fixed
validity window so they verify regardless of run date.

## Execution Guardrail fixtures

`guardrail/policy.json` mirrors the Execution Guardrail spec's illustrative
policy: an `effect` and an elementary CEL-like `when` condition over the
participants' semantic scopes; the decision defaults to deny. The simulated
PDP in the prototypes evaluates exactly this file.

`guardrail/scopes.json` is the policy-controlled mapping that binds semantic
scopes to a Lineage Execution through its origin `grantId` (or origin issuer
DID as a governance fallback). Scopes are origin-bound metadata the executor
cannot self-assert, and a scope adds no authority — it only informs the
guardrail policy decision.

## Determinism and regeneration

Keys are derived deterministically from the actor name
(`sha256("PIC-v0.2-fixture-seed:" + name)`), so regenerating reproduces the
exact same files. Regenerate with:

```bash
# from v0.2/golang
go run ./cmd/genfixtures
# or, from the repository root
task v0-2-go-fixtures
```

## How the Go track uses them

The Go prototype loads these once into an in-memory registry at startup
(`fixtureset.Load()`, cached with `sync.Once`), so benchmarks pay no per-use
disk cost. The attestation signatures are verified against the loaded
`org-authority` public key.

## License

Licensed under the **Apache License, Version 2.0** (repository-root
[`LICENSE`](../../LICENSE)).

> Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
> Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.
