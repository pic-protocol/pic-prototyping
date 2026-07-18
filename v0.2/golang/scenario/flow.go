// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package scenario

import (
	"time"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/pic"
)

// This file builds one end-to-end execution flow: an origin PCA0 whose authority
// narrows hop by hop as real fixture executors continue it, plus a final rogue
// attempt that PIC rejects. It backs the `picdemo flow` visualization.

// FlowHop is one step of the execution flow: who acted, what they did, the
// authority they carry, what they dropped versus their predecessor, and the real
// signed PCA they produced.
type FlowHop struct {
	Index          int      `json:"hop"`
	Actor          string   `json:"actor"`
	Action         string   `json:"action"`
	Authority      []string `json:"authority"`
	Dropped        []string `json:"dropped,omitempty"`
	LineageCounter uint64   `json:"lineageCounter"`
	PreviousHash   string   `json:"previousPcaHash,omitempty"`
	Generates      *pic.PCA `json:"generates"`
}

// RogueAttempt is a compromised executor trying to re-expand authority; PIC
// rejects it (non-expansion), which is the point.
type RogueAttempt struct {
	Actor    string   `json:"actor"`
	Tried    []string `json:"tried"`
	Rejected bool     `json:"rejected"`
	Reason   string   `json:"reason"`
}

// FlowResult is the whole flow: the hops, the verification outcome, and the
// rejected rogue attempt.
type FlowResult struct {
	Description  string        `json:"description"`
	Hops         []FlowHop     `json:"hops"`
	VerifyOK     bool          `json:"verifyOk"`
	TipAuthority []string      `json:"tipAuthority"`
	Rogue        *RogueAttempt `json:"rogue"`
}

// Flow runs the execution flow on the real fixtures and returns it. Every PCA is
// really minted, signed, and verified on this call.
func (w *World) Flow(now time.Time) (*FlowResult, error) {
	contract := pic.ExecutionContract{} // permissive, so every fixture executor conforms
	ops0 := []string{"read-all", "backup", "share-files"}

	pca0, err := pic.MintPCA0(w.id("alice"), pic.Invariants{Operations: ops0, ExecutionContract: contract}, "", now)
	if err != nil {
		return nil, err
	}
	chain := []*pic.PCA{pca0}

	res := &FlowResult{
		Description: "Authority created once at the origin (alice) and propagated, only narrowing, through a causal chain of real fixture executors. Each hop produces a signed PCA; the final rogue expansion is rejected.",
		Hops: []FlowHop{{
			Index: 0, Actor: "alice", Action: "mint origin PCA0",
			Authority: ops0, LineageCounter: 0, Generates: pca0,
		}},
	}

	steps := []struct {
		actor, action, op string
		ops               []string
	}{
		{"gateway", "continue: forward (no attenuation)", "read-all", []string{"read-all", "backup", "share-files"}},
		{"backup-service", "continue: attenuate (drop share-files)", "backup", []string{"read-all", "backup"}},
		{"archive-service", "continue: attenuate (drop backup)", "read-all", []string{"read-all"}},
		{"storage-service", "execute: read under {read-all}", "read-all", []string{"read-all"}},
	}
	for i, s := range steps {
		pred := chain[len(chain)-1]
		req := pic.Request{Operation: s.op, Target: "eu-1/tenant-42/resource", SecurityDomain: "tenant-42"}
		next, err := pic.NewProver(w.id(s.actor), w.att(s.actor)).Continue(pred, pic.Invariants{Operations: s.ops, ExecutionContract: contract}, req, now)
		if err != nil {
			return nil, err
		}
		chain = append(chain, next)
		ph, _ := pred.Digest()
		res.Hops = append(res.Hops, FlowHop{
			Index: i + 1, Actor: s.actor, Action: s.action,
			Authority: s.ops, Dropped: diffOps(pred.Invariants.Operations, s.ops),
			LineageCounter: next.LineageCounter, PreviousHash: ph, Generates: next,
		})
	}

	inv, verr := w.verifier().VerifyFullChain(chain, now)
	res.VerifyOK = verr == nil
	res.TipAuthority = inv.Operations

	// Rogue: a compromised executor tries to re-add 'backup' the lineage dropped.
	tip := chain[len(chain)-1]
	tried := []string{"read-all", "backup"}
	rogue, err := pic.NewProver(w.id("archive-service"), w.att("archive-service")).
		ContinueMalicious(tip, pic.Invariants{Operations: tried, ExecutionContract: contract},
			pic.Request{Operation: "backup", Target: "eu-1/tenant-42/resource", SecurityDomain: "tenant-42"}, now)
	if err != nil {
		return nil, err
	}
	rerr := w.verifier().VerifyHop(rogue, tip, now, false)
	res.Rogue = &RogueAttempt{Actor: "archive-service", Tried: tried, Rejected: rerr != nil, Reason: errStr(rerr)}
	return res, nil
}

// diffOps returns the operations present in a but not in b.
func diffOps(a, b []string) []string {
	var out []string
	for _, x := range a {
		found := false
		for _, y := range b {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			out = append(out, x)
		}
	}
	return out
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
