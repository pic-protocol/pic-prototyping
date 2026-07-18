// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package pic

import (
	"fmt"
	"strings"
)

// This file implements the reference authority profile (Prover/Verifier spec §4):
// operations as a set with subset inclusion, an execution-contract order, a
// conformance function, and the executed-vs-signed / PDP authorization check.

// Attenuates reports the error, if any, that makes `current` an invalid
// (expansive) continuation of `predecessor`. nil means current ≤ predecessor
// under the reference attenuation order (non-expansion, §2.4 / §3.3 check 6).
func Attenuates(current, predecessor Invariants) error {
	// operations: every current operation MUST be present in the predecessor set.
	for _, op := range current.Operations {
		if !contains(predecessor.Operations, op) {
			return fmt.Errorf("non-expansion: operation %q not present in predecessor", op)
		}
	}
	return attenuatesContract(current.ExecutionContract, predecessor.ExecutionContract)
}

// attenuatesContract checks that every predecessor contract constraint is
// preserved or strengthened by current (§2.4).
func attenuatesContract(current, predecessor ExecutionContract) error {
	// role: a required role cannot be relaxed.
	if predecessor.Role != "" && current.Role != predecessor.Role {
		return fmt.Errorf("non-expansion: role %q relaxes predecessor role %q", current.Role, predecessor.Role)
	}
	// compliance: the required set may only grow (current ⊇ predecessor).
	for _, c := range predecessor.Compliance {
		if !contains(current.Compliance, c) {
			return fmt.Errorf("non-expansion: compliance %q dropped", c)
		}
	}
	// executionModel: the constraint may only tighten (current at least as restrictive).
	if modelRank(current.ExecutionModel) > modelRank(predecessor.ExecutionModel) {
		return fmt.Errorf("non-expansion: executionModel %q relaxes predecessor %q",
			current.ExecutionModel, predecessor.ExecutionModel)
	}
	return nil
}

// Conforms reports the error, if any, that makes an executor's attested
// attributes fail the execution contract (§3.3 check 5). nil means conforming.
func Conforms(att ContractAttributes, contract ExecutionContract) error {
	if contract.Role != "" && att.Role != contract.Role {
		return fmt.Errorf("conformance: executor role %q does not satisfy required role %q", att.Role, contract.Role)
	}
	for _, c := range contract.Compliance {
		if !contains(att.Compliance, c) {
			return fmt.Errorf("conformance: executor lacks required compliance %q", c)
		}
	}
	// A deterministic contract rejects an agentic executor: the executor's model
	// must be at least as restrictive as the contract allows.
	if modelRank(att.ExecutionModel) > modelRank(contract.ExecutionModel) {
		return fmt.Errorf("conformance: executionModel %q not permitted by contract %q",
			att.ExecutionModel, contract.ExecutionModel)
	}
	return nil
}

// Authorize is the PDP / reference-monitor decision (§4.3): is the concrete
// request permitted by the authority carried in these invariants? An operation
// like {operation:"read", target:"/sys/syslog.txt"} is permitted iff some
// granted pattern (e.g. "read:/sys/*") matches. This is where the confused
// deputy is denied at enforcement time when non-expansion already bounded it.
func Authorize(inv Invariants, req Request) error {
	want := req.Operation + ":" + req.Target
	for _, granted := range inv.Operations {
		if matchOp(granted, want) {
			return nil
		}
	}
	return fmt.Errorf("not authorized: %q not covered by %v", want, inv.Operations)
}

// matchOp reports whether a granted operation pattern covers a concrete op.
// A pattern ending in "*" matches by prefix; otherwise it must match exactly.
func matchOp(pattern, concrete string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(concrete, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == concrete
}

// modelRank orders execution models by restrictiveness: lower is more
// restrictive. An unset/unknown model is the least restrictive (unconstrained).
func modelRank(m string) int {
	switch m {
	case "deterministic":
		return 0
	case "agentic":
		return 1
	default:
		return 2
	}
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
