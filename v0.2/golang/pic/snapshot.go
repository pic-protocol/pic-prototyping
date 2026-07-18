// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package pic

import (
	"fmt"
	"time"
)

// This file implements the Snapshot Hash Chain profile (Prover/Verifier spec
// §5.2), the profile v0.2 orients on. A trusted issuer validates the chain up to
// some PCA[k] and signs a snapshot committing to its content id; a downstream
// Verifier then validates only the hops after the snapshot — cost
// O(hops since the last snapshot) instead of O(n).

// IssueSnapshot has a trusted snapshot issuer validate chain[0..throughIndex]
// (full-chain) and, only if valid, sign a snapshot committing to PCA[throughIndex]
// as the valid tip. It refuses to attest an invalid chain.
func IssueSnapshot(issuer *Identity, reg *Registry, chain []*PCA, throughIndex int, now time.Time) (*Snapshot, error) {
	if throughIndex < 0 || throughIndex >= len(chain) {
		return nil, fmt.Errorf("snapshot: throughIndex %d out of range", throughIndex)
	}
	// The issuer re-validates the whole prefix it vouches for.
	if _, err := NewVerifier(reg, nil).VerifyFullChain(chain[:throughIndex+1], now); err != nil {
		return nil, fmt.Errorf("snapshot: refusing to attest an invalid chain: %w", err)
	}
	tip := chain[throughIndex]
	dig, err := tip.Digest()
	if err != nil {
		return nil, err
	}
	s := &Snapshot{
		LineageID:      tip.LineageID,
		ThroughCounter: tip.LineageCounter,
		ThroughPcaHash: dig,
		Issuer:         issuer.ID,
		IssuedAt:       now,
		ExpiresAt:      now.Add(DefaultLineageTTL),
	}
	msg, err := s.signingBytes()
	if err != nil {
		return nil, err
	}
	s.Proof = &Proof{
		Type:               SignatureType,
		VerificationMethod: issuer.VerificationMethod,
		Signature:          issuer.sign(msg),
	}
	return s, nil
}

// VerifyFromSnapshot validates a lineage starting from a trusted snapshot
// (§5.2). `tail` is [PCA[k], PCA[k+1], …, PCA[n]] where tail[0] is the snapshotted
// tip. The Verifier checks the snapshot signature and that it commits to tail[0],
// trusts tail[0] as a valid tip without walking back to PCA0, and validates the
// hops after it. Cost is O(len(tail)-1). Returns the invariants at the tip.
//
// The snapshot issuer is an added trust anchor (§5.2): its key must be registered
// and trusted by this Verifier.
func (v *Verifier) VerifyFromSnapshot(snap *Snapshot, tail []*PCA, now time.Time) (Invariants, error) {
	if len(tail) == 0 {
		return Invariants{}, fmt.Errorf("snapshot verify: empty tail")
	}
	if snap.Proof == nil {
		return Invariants{}, fmt.Errorf("snapshot verify: missing signature")
	}
	msg, err := snap.signingBytes()
	if err != nil {
		return Invariants{}, err
	}
	if err := v.Registry.verify(snap.Issuer, msg, snap.Proof.Signature); err != nil {
		return Invariants{}, fmt.Errorf("snapshot verify: %w", err)
	}
	if err := withinValidity(snap.IssuedAt, snap.ExpiresAt, now); err != nil {
		return Invariants{}, fmt.Errorf("snapshot verify: %w", err)
	}

	tip := tail[0]
	dig, err := tip.Digest()
	if err != nil {
		return Invariants{}, err
	}
	if dig != snap.ThroughPcaHash {
		return Invariants{}, fmt.Errorf("snapshot verify: tip digest does not match snapshot commitment")
	}
	if tip.LineageID != snap.LineageID || tip.LineageCounter != snap.ThroughCounter {
		return Invariants{}, fmt.Errorf("snapshot verify: tip coordinates do not match snapshot")
	}
	// The tip is trusted as a valid chain tip via the snapshot; still honor a
	// revocation that strikes it or its future.
	if v.Revocations != nil {
		if err := v.Revocations.Check(tip); err != nil {
			return Invariants{}, fmt.Errorf("snapshot verify tip: %w", err)
		}
	}
	// Validate only the hops after the snapshot: O(hops since snapshot).
	for i := 1; i < len(tail); i++ {
		if err := v.VerifyHop(tail[i], tail[i-1], now, false); err != nil {
			return Invariants{}, fmt.Errorf("post-snapshot hop %d: %w", i, err)
		}
	}
	return tail[len(tail)-1].Invariants, nil
}
