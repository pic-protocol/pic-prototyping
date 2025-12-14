# PIC Prototyping

**Status: Experimental / Prototyping**

This repository hosts **experimental prototyping and reference implementations**
for the **Provenance Identity Continuity (PIC) framework**.

Its purpose is to explore:

- potential **PIC Protocol** encodings,
- execution flows and causal authority transitions,
- implementation strategies and developer experiments.

⚠️ **This repository is NOT the PIC Spec and is NOT a normative reference.**

---

## PIC Example: Confused Deputy Attack Prevention

### Setup

```text
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│     Alice       │       │      Bob        │       │     Carol       │
│    (Client)     │──────▶│   (Service)     │──────▶│   (Storage)     │
│                 │       │                 │       │                 │
│ Authority:      │       │ Authority:      │       │ Executes        │
│ {read: /user/*, │       │ {read: /user/*, │       │ operations      │
│  write: /user/*}│       │  write: /user/*,│       │                 │
│                 │       │  read: /sys/*}  │       │                 │
└─────────────────┘       └─────────────────┘       └─────────────────┘
```

- **Alice** can: `{read: /user/*, write: /user/*}`
- **Bob** can: `{read: /user/*, write: /user/*, read: /sys/*}` ← Bob can read system files!
- **Carol** executes whatever is authorized

---

### Bob's Service Logic

```python
def process(input_file, content):
    if carol.exists(input_file) and can_read(input_file):
        data = carol.read(input_file)
        result = data + "\n" + content
    else:
        result = content
    
    output_file = "/user/output_" + random_id() + ".txt"
    carol.write(output_file, result)
    return output_file  # Alice gets this file
```

Bob reads input file, appends content, writes to new output file, returns result to client.

---

### Case 1: Bob's Transaction — Read /sys/ Works

```text
Bob starts his own transaction:
  PCA_0: p_0 = Bob, ops_0 = {read: /user/*, write: /user/*, read: /sys/*}
         │
         ▼
Bob calls: process("/sys/syslog.txt", "my note")
         │
         ▼
Bob requests: read /sys/syslog.txt
CAT validates: {read: /sys/*} ⊆ ops_0? ✓ YES
         │
         ▼
Carol returns: "[2025-12-14] System started\n[2025-12-14] Secret key loaded..."
         │
         ▼
Bob writes: /user/output_abc123.txt
  content: "[2025-12-14] System started\n[2025-12-14] Secret key loaded...\nmy note"
         │
         ▼
✓ SUCCESS — Bob can read /sys/ and create output
```

---

### Case 2: Alice's Transaction — Alice Tries to Steal /sys/syslog.txt

Alice discovers Bob can read `/sys/syslog.txt`. Alice wants that data.

Alice calls Bob with: `input_file = "/sys/syslog.txt"`

```text
Alice starts transaction:
  PCA_0: p_0 = Alice, ops_0 = {read: /user/*, write: /user/*}
         │
         ▼
Bob receives PCA_1:
  p_0 = Alice (immutable)
  ops_1 ⊆ {read: /user/*, write: /user/*}
         │
         ▼
Alice sends: process("/sys/syslog.txt", "give me the secrets")
         │
         ▼
Bob's logic: file exists? Yes. Try to read it.
         │
         ▼
Bob requests: read /sys/syslog.txt
         │
         ▼
CAT validates:
  p_0 = Alice
  {read: /sys/syslog.txt} ⊆ {read: /user/*, write: /user/*}?
  ❌ NO — /sys/* not in Alice's authority
         │
         ▼
❌ REJECTED — Read blocked
         │
         ▼
Bob's logic falls back: cannot read, create new file
         │
         ▼
Bob requests: write /user/output_xyz789.txt
CAT validates: {write: /user/*} ⊆ ops_1? ✓ YES
         │
         ▼
Carol writes: /user/output_xyz789.txt
  content: "give me the secrets"  ← Only Alice's input, NO syslog data!

Alice receives: /user/output_xyz789.txt
Alice reads it: just her own input, no secrets.
```

**Result:** Alice tried to steal /sys/syslog.txt through Bob. PIC blocked the read. Alice only got her own content back.

---

### The Attack Explained

```text
TOKEN-BASED (Vulnerable):

Alice sends: process("/sys/syslog.txt", "steal this")
Bob checks own token: can I read /sys/*? Yes.
Bob reads /sys/syslog.txt ← SYSTEM SECRETS
Bob appends Alice's content
Bob writes to /user/output.txt
Bob returns file to Alice
Alice reads output: SYSTEM SECRETS + "steal this"

❌ CONFUSED DEPUTY
Alice exploited Bob's {read: /sys/*} to steal system logs.


PIC (Immune):

Alice sends: process("/sys/syslog.txt", "steal this")
Bob operates in Alice's transaction
Alice's ops_0 = {read: /user/*, write: /user/*}
Bob attempts: read /sys/syslog.txt
CAT: {read: /sys/*} ⊆ {read: /user/*, write: /user/*}? NO.
❌ REJECTED

Bob falls back: creates file with only Alice's input.
Alice gets nothing she couldn't already access.
```

---

### Summary

| Transaction | Origin | Can read /user/* | Can read /sys/* | Can write /user/* |
|-------------|--------|------------------|-----------------|-------------------|
| Bob's | Bob | ✓ Yes | ✓ Yes | ✓ Yes |
| Alice's | Alice | ✓ Yes | ❌ No | ✓ Yes |

---

### The Key Insight

Alice knows:

1. Bob has `{read: /sys/*}`
2. Bob's logic reads input file and includes it in output
3. If Alice sends `/sys/syslog.txt`, Bob will read it and return the content

**Token-Based:** Bob reads with own credentials → Alice gets system secrets

**PIC:** Bob operates in Alice's transaction → `/sys/*` not authorized → read blocked

```text
Bob's credentials: {read: /user/*, write: /user/*, read: /sys/*}
Alice's transaction: {read: /user/*, write: /user/*}

In Alice's transaction, Bob's {read: /sys/*} does not exist.
Alice cannot exploit Bob's elevated privileges.
```

**PIC guarantee:** Malicious input cannot trigger unauthorized operations, regardless of service's elevated privileges.

---

## Relationship to the PIC Spec

The **normative definition** of the PIC Model, its invariants, and what it means
to be **PIC-compliant** is defined **exclusively** by the **PIC Spec**.

- Official PIC Spec: https://github.com/pic-protocol/pic-spec  
- PIC Model author: **Nicola Gallo**  
- PIC Spec editors and maintainers: **PIC Spec Contributors**

> “This work is based on the Provenance Identity Continuity (PIC) Model created by  
> Nicola Gallo. The model and its initial specification originate from this work.  
> Maintenance of the PIC Spec and related PIC Protocol documents is performed over  
> time by the PIC Spec Contributors, with authorship of the model remaining with  
> Nicola Gallo.”

This repository:

- **implements and experiments with** the PIC Model as defined in the PIC Spec,
- **does not redefine, replace, or amend** the PIC Model or its invariants,
- **must not be treated as canonical or normative**.

In case of conflict, the PIC Spec always takes precedence.

---

## Scope

`pic-prototyping` may include:

- draft protocol message formats,
- wire-level experiments,
- reference or partial implementations,
- test vectors and simulations,
- examples intended for exploration and discussion.

All contents are **experimental**, may be incomplete, and are subject to change
without notice.

---

## Authorship and Attribution

- **Authorship of the PIC Model** remains exclusively with **Nicola Gallo**.
- This repository does **not** claim authorship of the PIC Model, its execution
  semantics, or its formal invariants.
- Contributors to this repository claim authorship **only** of the code or text
  they contribute here.

Any use of the PIC Model, the PIC Spec, or terms such as *“PIC”* or
*“PIC-compliant”* in derivative works **must comply with the attribution and
usage requirements defined in the PIC Spec (Appendix B)**.

---

## License

- The **PIC Spec** and related specification documents are licensed under  
  **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
- **All code in this repository** is licensed under the  
  **Apache License, Version 2.0**, unless stated otherwise.

See `LICENSE` for full terms.

---

## Governance and Contributions

This repository is experimental and evolves alongside the PIC Spec.

Contribution guidelines (if applicable) are defined in `CONTRIBUTING.md`.

In any conflict, the normative text of the **PIC Spec**, including its attribution
and authorship requirements, **always takes precedence** over this README.
