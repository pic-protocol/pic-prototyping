# PIC Prototyping

**Status: Experimental / Prototyping**

This repository contains **experimental examples and reference prototypes**
for the **Provenance Identity Continuity (PIC) protocol**.

Its purpose is to explore:

- PIC execution flows
- Cross-service authority propagation
- Integration with OAuth / IdP systems
- Confused Deputy prevention in real SaaS architectures

⚠️ **This repository is NOT the PIC Spec and is NOT normative.**

---

## PIC Example: Cross-Service Confused Deputy Prevention (OAuth → PCA)

This example mirrors the classic **IAM Confused Deputy** scenario, but shows
how **PIC eliminates the problem structurally**.

---

## Actors, Roles, and Identities

```text
┌───────────────────────────────┐
│            Alice              │
│         (Human User)          │
│                               │
│ Identity:                     │
│  OIDC subject: alice@idp      │
│                               │
│ Authority (via OAuth):        │
│  {read:/user/*, write:/user/*}│
└──────────────┬────────────────┘
               │ OAuth Token
               ▼
┌───────────────────────────────┐
│        Gateway / Mesh         │
│   (AuthZ Translation Layer)   │
│                               │
│ DID:                          │
│  did:web:gateway.example      │
│                               │
│ Role:                         │
│  - Validates OAuth token      │
│  - Derives PCA_0              │
│  - NO resource authority      │
└──────────────┬────────────────┘
               │ PCA
               ▼
┌───────────────────────────────┐
│             Bob               │
│        (SaaS Service)         │
│                               │
│ DID:                          │
│  did:web:billing.example      │
│                               │
│ Authority (own transactions): │
│  {read:/sys/*, write:/sys/*}  │
│                               │
│ Never executes storage I/O    │
└──────────────┬────────────────┘
               │ PCA
               ▼
┌───────────────────────────────┐
│            Carol              │
│      (Storage Service)        │
│                               │
│ DID:                          │
│  did:web:storage.example      │
│                               │
│ Executes ALL file operations  │
│ strictly based on PCA         │
└───────────────────────────────┘
```

---

## Trust Assumptions (Important)

- Alice’s identity and permissions are authenticated by an **IdP (OAuth / OIDC)**
- Bob’s and Carol’s identities are workload identities (DID, SPIFFE, mTLS, etc.)
- The **Gateway is trusted only to translate identity → PCA**
- **Authority enforcement happens exclusively via PCA**

This example focuses on **authorization semantics**, not identity proof mechanics.

---

## End-to-End Call Flow

```text
Alice
  │ HTTP request + OAuth token
  ▼
Gateway / Service Mesh
  │ validates token
  │ derives PCA_0:
  │   p_0 = Alice
  │   ops_0 = {read:/user/*, write:/user/*}
  ▼
Bob (SaaS Service)
  │ forwards request unchanged
  │ never adds authority
  ▼
Carol (Storage)
  │ enforces authority using PCA
  ▼
Result
```

---

## Carol Storage Logic (Rust, PCA-Enforced)

```rust
fn process(pca: &Pca, input_file: &str, content: &str) -> Result<String, Error> {
    let result = if exists(pca, input_file)? && can_read(pca, input_file)? {
        let data = read(pca, input_file)?;
        format!("{}\n{}", data, content)
    } else {
        content.to_string()
    };

    let output_file = format!("/user/output_{}.txt", random_id());
    write(pca, &output_file, &result)?;

    Ok(output_file)
}
```

Carol **never** checks caller identity directly.  
She enforces **only what the PCA allows**.

---

## Case 1: Bob’s Own Transaction (Legitimate)

```text
Bob starts transaction:
  PCA_0:
    p_0 = Bob
    ops_0 = {read:/sys/*, write:/sys/*}

Bob → Carol:
  process(PCA_0, "/sys/syslog.txt", "audit note")

Carol validates:
  {read:/sys/*} ⊆ ops_0 ✓

✓ Read allowed
✓ Write allowed
```

---

## Case 2: Alice Attempts Confused Deputy Attack (Blocked)

Alice tries to steal system logs via Bob.

```text
Alice → Gateway:
  OAuth token (user-scoped)

Gateway → Bob:
  PCA_0:
    p_0 = Alice
    ops_0 = {read:/user/*, write:/user/*}

Bob → Carol:
  process(PCA_0, "/sys/syslog.txt", "steal secrets")

Carol checks:
  {read:/sys/*} ⊆ {read:/user/*, write:/user/*} ❌

Read denied.

Fallback:
  write("/user/output_x.txt", "steal secrets")

Alice receives:
  ONLY her own content
```

**No system data leaks.**

---

## Why Token-Based Systems Fail Here

```text
OAuth-only / token-based flow:

Alice → Bob
Bob uses its OWN credentials
Bob reads /sys/*
Bob returns data to Alice

❌ Confused Deputy:
Alice exploits Bob’s authority
```

---

## Why PIC Works

```text
PIC flow:

Authority is bound to PCA
PCA origin = Alice

Bob’s /sys/* authority
does NOT exist in Alice’s transaction.

No service can "help" a user
do something they are not allowed to do.
```

---

## Summary

| Transaction Origin | read /user/* | read /sys/* | write /user/* |
|--------------------|--------------|-------------|---------------|
| Bob (service)      | ❌ No        | ✓ Yes       | ❌ No         |
| Alice (user)       | ✓ Yes        | ❌ No       | ✓ Yes         |

---

## Relationship to the PIC Spec

This repository contains **experimental examples** of the
**Provenance Identity Continuity (PIC) Model**.

The **PIC Model**, its invariants, and compliance rules are defined
**exclusively** by the **PIC Specification**:

[github.com/pic-protocol/pic-spec](https://github.com/pic-protocol/pic-spec)

The PIC Model was originally created by **Nicola Gallo**.
This repository is **non-normative**.

In case of conflict, the PIC Spec always takes precedence.
