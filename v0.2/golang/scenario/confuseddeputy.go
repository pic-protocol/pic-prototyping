// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

// Package scenario runs the PIC "Why PIC" examples on top of the pic package,
// using the real v0.2 fixtures (DID identities and signed attestations) loaded
// once into memory. It provides:
//
//   - the Authority-Mixing / cross-lineage composition example (authoritymixing.go),
//     matching the PIC site "Why PIC" page and Prover/Verifier spec §1.4;
//   - the cross-service confused-deputy example (this file);
//   - the multi-hop chains used by the snapshot and revocation demos.
//
// It is non-normative demonstration code. The PIC Specification is authoritative.
package scenario

import (
	"fmt"
	"time"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/fixtureset"
	"github.com/pic-protocol/pic-prototyping/v0.2/golang/pic"
)

const sysFile = "/sys/syslog.txt"

// World is the loaded fixture cast plus the verifier registry.
type World struct {
	Set *fixtureset.Set
}

// NewWorld loads the cached v0.2 fixtures (real DID identities and signed
// attestations). The first call reads disk; later calls reuse the cache.
func NewWorld() (*World, error) {
	set, err := fixtureset.Load()
	if err != nil {
		return nil, err
	}
	return &World{Set: set}, nil
}

// id and att are shorthand for the loaded fixture identities and attestations.
func (w *World) id(name string) *pic.Identity    { return w.Set.Identity(name) }
func (w *World) att(name string) pic.Attestation { return w.Set.Attestation(name) }
func (w *World) verifier() *pic.Verifier         { return pic.NewVerifier(w.Set.Registry, nil) }

// userInvariants is the authority Alice grants: user-scoped read/write only.
func userInvariants() pic.Invariants {
	return pic.Invariants{
		Operations: []string{"read:/user/*", "write:/user/*"},
		ExecutionContract: pic.ExecutionContract{
			Compliance:     []string{"GDPR"},
			ExecutionModel: "deterministic",
		},
	}
}

// sysInvariants is a service's own authority: system-scoped read/write.
func sysInvariants() pic.Invariants {
	return pic.Invariants{
		Operations: []string{"read:/sys/*", "write:/sys/*"},
		ExecutionContract: pic.ExecutionContract{
			Compliance:     []string{"GDPR"},
			ExecutionModel: "deterministic",
		},
	}
}

// ProcessResult is the outcome of the storage service processing a request.
type ProcessResult struct {
	Verified   bool
	VerifyErr  error
	Authorized bool
	AuthErr    error
}

// Blocked reports whether the request produced no system-data access.
func (r ProcessResult) Blocked() bool { return !r.Verified || !r.Authorized }

// process is the storage service (Carol) logic: verify the received chain,
// enforce executed-vs-signed on the tip request binding, and authorize the
// concrete request against the tip authority (spec §3.3 check 8, §4.3).
func (w *World) process(chain []*pic.PCA, executed pic.Request, now time.Time) ProcessResult {
	inv, err := w.verifier().VerifyFullChain(chain, now)
	if err != nil {
		return ProcessResult{Verified: false, VerifyErr: err}
	}
	res := ProcessResult{Verified: true}
	if tip := chain[len(chain)-1]; tip.ProofOfRelationship != nil {
		signed := tip.ProofOfRelationship.Request
		if signed.Operation != executed.Operation || signed.Target != executed.Target {
			res.AuthErr = fmt.Errorf("executed-vs-signed mismatch: signed %s:%s, executed %s:%s",
				signed.Operation, signed.Target, executed.Operation, executed.Target)
			return res
		}
	}
	if err := pic.Authorize(inv, executed); err != nil {
		res.AuthErr = err
		return res
	}
	res.Authorized = true
	return res
}

// Case1Legit is the archive service's own transaction: it originates a
// system-scoped lineage and reads a system file. It is authorized.
func (w *World) Case1Legit(now time.Time) (chain []*pic.PCA, req pic.Request, res ProcessResult, err error) {
	pca0, err := pic.MintPCA0(w.id("archive-service"), sysInvariants(), "", now)
	if err != nil {
		return nil, req, res, err
	}
	chain = []*pic.PCA{pca0}
	req = pic.Request{Operation: "read", Target: sysFile, SecurityDomain: "sys"}
	return chain, req, w.process(chain, req, now), nil
}

// Case2Honest is Alice's request forwarded honestly by the archive service: it
// adds no authority, so the lineage stays user-scoped and the storage service
// denies the out-of-scope system read. No system data leaks.
func (w *World) Case2Honest(now time.Time) (chain []*pic.PCA, req pic.Request, res ProcessResult, err error) {
	pca0, err := pic.MintPCA0(w.id("alice"), userInvariants(), "", now)
	if err != nil {
		return nil, req, res, err
	}
	req = pic.Request{Operation: "read", Target: sysFile, SecurityDomain: "sys"}
	archive := pic.NewProver(w.id("archive-service"), w.att("archive-service"))
	pca1, err := archive.Continue(pca0, userInvariants(), req, now)
	if err != nil {
		return nil, req, res, err
	}
	chain = []*pic.PCA{pca0, pca1}
	return chain, req, w.process(chain, req, now), nil
}

// Case2Malicious is a compromised archive service that tries to inject system
// authority into Alice's lineage. The successor PCA fails non-expansion at the
// Verifier: it cannot be validated as a conforming continuation.
func (w *World) Case2Malicious(now time.Time) (chain []*pic.PCA, req pic.Request, res ProcessResult, err error) {
	pca0, err := pic.MintPCA0(w.id("alice"), userInvariants(), "", now)
	if err != nil {
		return nil, req, res, err
	}
	req = pic.Request{Operation: "read", Target: sysFile, SecurityDomain: "sys"}
	expanded := pic.Invariants{
		Operations:        []string{"read:/user/*", "write:/user/*", "read:/sys/*"},
		ExecutionContract: userInvariants().ExecutionContract,
	}
	archive := pic.NewProver(w.id("archive-service"), w.att("archive-service"))
	pca1, err := archive.ContinueMalicious(pca0, expanded, req, now)
	if err != nil {
		return nil, req, res, err
	}
	chain = []*pic.PCA{pca0, pca1}
	return chain, req, w.process(chain, req, now), nil
}

// chainExecutors are the deterministic fixture executors cycled to build long
// chains for the snapshot and revocation demos (all real fixture identities).
var chainExecutors = []string{"gateway", "backup-service", "archive-service", "storage-service"}

// BuildChain creates a lineage of `hops` non-origin PCAs after PCA0 (hops+1 PCAs
// total), each produced by a real fixture executor cycled from chainExecutors.
func (w *World) BuildChain(hops int, now time.Time) ([]*pic.PCA, error) {
	// A permissive origin contract so every cycled executor conforms.
	inv := pic.Invariants{Operations: []string{"read:/user/*"}}
	pca0, err := pic.MintPCA0(w.id("alice"), inv, "", now)
	if err != nil {
		return nil, err
	}
	chain := []*pic.PCA{pca0}
	req := pic.Request{Operation: "read", Target: "/user/file", SecurityDomain: "tenant-42"}
	for i := 0; i < hops; i++ {
		name := chainExecutors[i%len(chainExecutors)]
		next, err := pic.NewProver(w.id(name), w.att(name)).Continue(chain[len(chain)-1], inv, req, now)
		if err != nil {
			return nil, err
		}
		chain = append(chain, next)
	}
	return chain, nil
}
