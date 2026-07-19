// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! The reference authority profile (Prover/Verifier spec §4): operations as a set
//! with subset inclusion, an execution-contract order, a conformance function,
//! and the executed-vs-signed / PDP authorization check.

use crate::types::{ContractAttributes, ExecutionContract, Invariants, Request};
use crate::PicResult;

/// Reports the error, if any, that makes `current` an invalid (expansive)
/// continuation of `predecessor`. `Ok(())` means current ≤ predecessor under the
/// reference attenuation order (non-expansion, §2.4 / §3.3 check 6).
pub fn attenuates(current: &Invariants, predecessor: &Invariants) -> PicResult<()> {
    for op in &current.operations {
        if !predecessor.operations.contains(op) {
            return Err(format!(
                "non-expansion: operation {op:?} not present in predecessor"
            ));
        }
    }
    attenuates_contract(&current.execution_contract, &predecessor.execution_contract)
}

/// Checks that every predecessor contract constraint is preserved or strengthened
/// by `current` (§2.4).
fn attenuates_contract(
    current: &ExecutionContract,
    predecessor: &ExecutionContract,
) -> PicResult<()> {
    if !predecessor.role.is_empty() && current.role != predecessor.role {
        return Err(format!(
            "non-expansion: role {:?} relaxes predecessor role {:?}",
            current.role, predecessor.role
        ));
    }
    for c in &predecessor.compliance {
        if !current.compliance.contains(c) {
            return Err(format!("non-expansion: compliance {c:?} dropped"));
        }
    }
    if model_rank(&current.execution_model) > model_rank(&predecessor.execution_model) {
        return Err(format!(
            "non-expansion: executionModel {:?} relaxes predecessor {:?}",
            current.execution_model, predecessor.execution_model
        ));
    }
    Ok(())
}

/// Reports the error, if any, that makes an executor's attested attributes fail
/// the execution contract (§3.3 check 5). `Ok(())` means conforming.
pub fn conforms(att: &ContractAttributes, contract: &ExecutionContract) -> PicResult<()> {
    if !contract.role.is_empty() && att.role != contract.role {
        return Err(format!(
            "conformance: executor role {:?} does not satisfy required role {:?}",
            att.role, contract.role
        ));
    }
    for c in &contract.compliance {
        if !att.compliance.contains(c) {
            return Err(format!(
                "conformance: executor lacks required compliance {c:?}"
            ));
        }
    }
    if model_rank(&att.execution_model) > model_rank(&contract.execution_model) {
        return Err(format!(
            "conformance: executionModel {:?} not permitted by contract {:?}",
            att.execution_model, contract.execution_model
        ));
    }
    Ok(())
}

/// The PDP / reference-monitor decision (§4.3): is the concrete request permitted
/// by the authority carried in these invariants?
pub fn authorize(inv: &Invariants, req: &Request) -> PicResult<()> {
    let want = format!("{}:{}", req.operation, req.target);
    for granted in &inv.operations {
        if match_op(granted, &want) {
            return Ok(());
        }
    }
    Err(format!(
        "not authorized: {:?} not covered by {}",
        want,
        go_slice(&inv.operations)
    ))
}

/// Reports whether a granted operation pattern covers a concrete op. A pattern
/// ending in `*` matches by prefix; otherwise it must match exactly.
fn match_op(pattern: &str, concrete: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        concrete.starts_with(prefix)
    } else {
        pattern == concrete
    }
}

/// Orders execution models by restrictiveness: lower is more restrictive. An
/// unset/unknown model is the least restrictive (unconstrained).
fn model_rank(m: &str) -> i32 {
    match m {
        "deterministic" => 0,
        "agentic" => 1,
        _ => 2,
    }
}

/// Formats a slice the way Go's `%v` does: `[a b c]`, space-separated, unquoted.
/// Used so demo "reason:" lines read like the Go prototype's.
pub fn go_slice(v: &[String]) -> String {
    format!("[{}]", v.join(" "))
}
