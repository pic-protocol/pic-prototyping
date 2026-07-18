// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package pic

import (
	"fmt"
	"time"
)

// This file implements the parts of the PIC Revocation Specification the
// prototype uses: the origin-commitment derivation of lineageId and the root
// branchId, and the native causal cutoffs (LINEAGE-SUFFIX, BRANCH-SUFFIX, GRANT).

// originCore is the profile-defined canonical projection of a PCA0 that excludes
// lineageId and proof, used to derive lineageId (Revocation spec §2.1). It must
// include at least profile, issuer, originNonce, grantId presence/value, the
// origin authority context, issuedAt, and expiresAt.
type originCore struct {
	Profile     string     `json:"profile"`
	Issuer      string     `json:"issuer"`
	OriginNonce string     `json:"originNonce"`
	GrantID     string     `json:"grantId"`
	Invariants  Invariants `json:"invariants"`
	IssuedAt    time.Time  `json:"issuedAt"`
	ExpiresAt   time.Time  `json:"expiresAt"`
}

// deriveLineageID computes lineageId = H("PIC-Lineage-v0" || canonical(originCore))
// from a PCA0 (Revocation spec §2.1). It is non-self-referential: it excludes the
// lineageId and proof fields.
func deriveLineageID(p *PCA) (string, error) {
	core := originCore{
		Profile:     p.Profile,
		Issuer:      p.Issuer,
		OriginNonce: p.OriginNonce,
		GrantID:     p.GrantID,
		Invariants:  p.Invariants,
		IssuedAt:    p.IssuedAt,
		ExpiresAt:   p.ExpiresAt,
	}
	b, err := canonicalJSON(core)
	if err != nil {
		return "", err
	}
	return hashParts([]byte(lineageDomainSep), []byte{0}, b), nil
}

// rootBranchID = H("PIC-Root-Branch-v0" || lineageId) (Revocation spec §2.4).
// Non-circular (lineageId already excludes the identifier and proof), always
// present, and directly targetable by BRANCH-SUFFIX.
func rootBranchID(lineageID string) string {
	return hashParts([]byte(branchRootDomain), []byte{0}, []byte(lineageID))
}

// Strategy names of the native causal revocations (Revocation spec §3.1).
const (
	StrategyLineageSuffix = "LINEAGE-SUFFIX"
	StrategyBranchSuffix  = "BRANCH-SUFFIX"
	StrategyGrant         = "GRANT"
)

// Revocation is one native causal cutoff. Only the fields relevant to its
// strategy are set. A real deployment authenticates and authorizes each of
// these (§5.1); this prototype focuses on the matching predicates (§3.1).
type Revocation struct {
	Strategy    string `json:"strategy"`
	LineageID   string `json:"lineageId,omitempty"`
	BranchID    string `json:"branchId,omitempty"`
	GrantID     string `json:"grantId,omitempty"`
	FromCounter uint64 `json:"fromCounter,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
}

// matches reports whether this revocation strikes the given PCA (§3.1).
func (r Revocation) matches(p *PCA) bool {
	switch r.Strategy {
	case StrategyLineageSuffix:
		// Every branch of the lineage from a counter onward (crosses branches).
		return p.LineageID == r.LineageID && p.LineageCounter >= r.FromCounter
	case StrategyBranchSuffix:
		// Only the matching branch domain from a counter onward.
		return p.LineageID == r.LineageID && p.BranchID == r.BranchID && p.LineageCounter >= r.FromCounter
	case StrategyGrant:
		// Every lineage and branch derived from that grant.
		return r.GrantID != "" && p.GrantID == r.GrantID
	default:
		return false
	}
}

// RevocationStore is an append-only, monotonic set of active revocations
// (Revocation spec §5.3, §5.4). In this prototype it is an in-memory list; a
// deployment authenticates the view and constrains freshness.
type RevocationStore struct {
	entries []Revocation
}

// NewRevocationStore returns an empty store.
func NewRevocationStore() *RevocationStore { return &RevocationStore{} }

// Add appends a revocation (append-only: revocations only accumulate).
func (s *RevocationStore) Add(r Revocation) { s.entries = append(s.entries, r) }

// LineageSuffix appends a LINEAGE-SUFFIX(lineageId, fromCounter) cutoff.
func (s *RevocationStore) LineageSuffix(lineageID string, fromCounter uint64, issuer string) {
	s.Add(Revocation{Strategy: StrategyLineageSuffix, LineageID: lineageID, FromCounter: fromCounter, Issuer: issuer})
}

// Check returns an error if any active revocation strikes the PCA; nil otherwise.
// The lookup is O(1) in lineage length (independent of chain length).
func (s *RevocationStore) Check(p *PCA) error {
	if s == nil {
		return nil
	}
	for _, r := range s.entries {
		if r.matches(p) {
			return fmt.Errorf("revoked by %s(lineage=%s, branch=%s, grant=%s, fromCounter=%d) at counter %d",
				r.Strategy, short(r.LineageID), short(r.BranchID), r.GrantID, r.FromCounter, p.LineageCounter)
		}
	}
	return nil
}

// short truncates a digest for readable messages.
func short(s string) string {
	if len(s) <= 14 {
		return s
	}
	return s[:14] + "…"
}
