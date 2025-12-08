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
