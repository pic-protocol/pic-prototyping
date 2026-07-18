// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

// Package scenario builds the classic Cross-Service Confused Deputy setup
// (Alice → Bob/Archive → Carol/Storage) on top of the pic package and provides
// the multi-hop chains used by the snapshot and revocation demos.
//
// It is non-normative demonstration code. The PIC Specification is authoritative.
package scenario

import (
	"fmt"
	"time"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/pic"
)

// Operation targets used across the scenario.
const (
	userScope = "/user/"
	sysFile   = "/sys/syslog.txt"
)

// World holds the identities, key registry, and signed attestations of the
// scenario. Carol (Storage) is the terminal executor: she verifies the PCA she
// receives and authorizes the concrete request; she never checks caller identity
// directly and enforces only what the PCA allows.
type World struct {
	Registry *pic.Registry

	Alice          *pic.Identity // human user / origin principal
	Bob            *pic.Identity // Archive service (intermediate executor)
	Carol          *pic.Identity // Storage service (terminal executor / enforcer)
	OrgAuthority   *pic.Identity // attestation issuer
	SnapshotIssuer *pic.Identity // trusted snapshot validator (§5.2)

	BobArchiveAtt pic.Attestation // Bob's conformance evidence
}

// NewWorld creates and registers the scenario identities and signs the
// attestations they present, with validity windows anchored at `now`.
func NewWorld(now time.Time) (*World, error) {
	w := &World{Registry: pic.NewRegistry()}
	var err error
	for _, spec := range []struct {
		id  string
		dst **pic.Identity
	}{
		{"did:example:users:alice", &w.Alice},
		{"did:example:workloads:archive", &w.Bob},
		{"did:example:workloads:storage", &w.Carol},
		{"did:example:org-authority", &w.OrgAuthority},
		{"did:example:snapshot-issuer", &w.SnapshotIssuer},
	} {
		if *spec.dst, err = pic.NewIdentity(spec.id); err != nil {
			return nil, err
		}
		w.Registry.Add(*spec.dst)
	}

	// Bob's attestation: a deterministic archive service under GDPR.
	w.BobArchiveAtt, err = pic.SignAttestation(pic.Attestation{
		Subject: w.Bob.ID,
		Attributes: pic.ContractAttributes{
			Role:           "archive-service",
			Compliance:     []string{"GDPR"},
			ExecutionModel: "deterministic",
			Environment:    "production",
			Region:         "eu-1",
		},
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(30 * 24 * time.Hour),
	}, w.OrgAuthority)
	if err != nil {
		return nil, err
	}
	return w, nil
}

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

// sysInvariants is Bob's own authority: system-scoped read/write.
func sysInvariants() pic.Invariants {
	return pic.Invariants{
		Operations: []string{"read:/sys/*", "write:/sys/*"},
		ExecutionContract: pic.ExecutionContract{
			Compliance:     []string{"GDPR"},
			ExecutionModel: "deterministic",
		},
	}
}

// ProcessResult is the outcome of Carol processing a request against a chain.
type ProcessResult struct {
	Verified   bool
	VerifyErr  error
	Authorized bool
	AuthErr    error
}

// Blocked reports whether the request produced no system-data access: either the
// chain failed verification, or authorization was denied.
func (r ProcessResult) Blocked() bool { return !r.Verified || !r.Authorized }

// process is Carol's storage logic: verify the received chain, enforce
// executed-vs-signed on the tip request binding, and authorize the concrete
// request against the tip authority (Prover/Verifier spec §3.3 check 8, §4.3).
func (w *World) process(chain []*pic.PCA, executed pic.Request, now time.Time) ProcessResult {
	v := pic.NewVerifier(w.Registry, nil)
	inv, err := v.VerifyFullChain(chain, now)
	if err != nil {
		return ProcessResult{Verified: false, VerifyErr: err}
	}
	res := ProcessResult{Verified: true}
	// executed-vs-signed: when the tip carries a request binding, what is executed
	// must match what was signed.
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

// Case1Legit is Bob's own transaction: Bob originates a system-scoped lineage
// and reads a system file through Carol. It is authorized.
func (w *World) Case1Legit(now time.Time) (chain []*pic.PCA, req pic.Request, res ProcessResult, err error) {
	pca0, err := pic.MintPCA0(w.Bob, sysInvariants(), "", now)
	if err != nil {
		return nil, req, res, err
	}
	chain = []*pic.PCA{pca0}
	req = pic.Request{Operation: "read", Target: sysFile, SecurityDomain: "sys"}
	return chain, req, w.process(chain, req, now), nil
}

// Case2Honest is Alice's request forwarded honestly by Bob: Bob adds no
// authority, so the lineage stays user-scoped and Carol denies the out-of-scope
// system read. No system data leaks.
func (w *World) Case2Honest(now time.Time) (chain []*pic.PCA, req pic.Request, res ProcessResult, err error) {
	pca0, err := pic.MintPCA0(w.Alice, userInvariants(), "", now)
	if err != nil {
		return nil, req, res, err
	}
	// The confused-deputy request: read a system file (Alice's lineage cannot).
	req = pic.Request{Operation: "read", Target: sysFile, SecurityDomain: "sys"}
	bob := pic.NewProver(w.Bob, w.BobArchiveAtt)
	// Bob forwards Alice's authority unchanged (honest: no expansion).
	pca1, err := bob.Continue(pca0, userInvariants(), req, now)
	if err != nil {
		return nil, req, res, err
	}
	chain = []*pic.PCA{pca0, pca1}
	return chain, req, w.process(chain, req, now), nil
}

// Case2Malicious is a compromised Bob that tries to inject system authority into
// Alice's lineage. The successor PCA fails the Verifier's non-expansion check: it
// cannot be validated as a conforming continuation. The confused deputy is
// structurally impossible, not merely denied at enforcement.
func (w *World) Case2Malicious(now time.Time) (chain []*pic.PCA, req pic.Request, res ProcessResult, err error) {
	pca0, err := pic.MintPCA0(w.Alice, userInvariants(), "", now)
	if err != nil {
		return nil, req, res, err
	}
	req = pic.Request{Operation: "read", Target: sysFile, SecurityDomain: "sys"}
	// Bob injects read:/sys/* — an authority absent from Alice's origin.
	expanded := pic.Invariants{
		Operations: []string{"read:/user/*", "write:/user/*", "read:/sys/*"},
		ExecutionContract: pic.ExecutionContract{
			Compliance:     []string{"GDPR"},
			ExecutionModel: "deterministic",
		},
	}
	bob := pic.NewProver(w.Bob, w.BobArchiveAtt)
	pca1, err := bob.ContinueMalicious(pca0, expanded, req, now)
	if err != nil {
		return nil, req, res, err
	}
	chain = []*pic.PCA{pca0, pca1}
	return chain, req, w.process(chain, req, now), nil
}

// BuildChain creates a user-scoped lineage of `hops` non-origin PCAs after PCA0
// (so the chain has hops+1 PCAs), each produced by a fresh conforming executor
// and registered in the world. Used by the snapshot and revocation demos.
func (w *World) BuildChain(hops int, now time.Time) ([]*pic.PCA, error) {
	pca0, err := pic.MintPCA0(w.Alice, userInvariants(), "", now)
	if err != nil {
		return nil, err
	}
	chain := []*pic.PCA{pca0}
	for i := 0; i < hops; i++ {
		exec, err := pic.NewIdentity(fmt.Sprintf("did:example:workloads:hop-%d", i+1))
		if err != nil {
			return nil, err
		}
		w.Registry.Add(exec)
		att, err := pic.SignAttestation(pic.Attestation{
			Subject: exec.ID,
			Attributes: pic.ContractAttributes{
				Compliance:     []string{"GDPR"},
				ExecutionModel: "deterministic",
			},
			IssuedAt:  now.Add(-time.Hour),
			ExpiresAt: now.Add(30 * 24 * time.Hour),
		}, w.OrgAuthority)
		if err != nil {
			return nil, err
		}
		req := pic.Request{Operation: "read", Target: userScope + "file", SecurityDomain: "tenant-42"}
		next, err := pic.NewProver(exec, att).Continue(chain[len(chain)-1], userInvariants(), req, now)
		if err != nil {
			return nil, err
		}
		chain = append(chain, next)
	}
	return chain, nil
}
