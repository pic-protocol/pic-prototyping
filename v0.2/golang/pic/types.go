// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package pic

import "time"

// Profile identifiers used by this prototype.
const (
	RevocableProfile = "PIC-Revocable-v0"
	PoRType          = "PIC-PoR-v0"
	RevocationType   = "PIC-Revocation-v0"
)

// ExecutionContract is the reference-profile execution contract: the constraints
// a successor executor must satisfy (Prover/Verifier spec §1.8, §4.2).
type ExecutionContract struct {
	Role           string   `json:"role,omitempty"`
	Compliance     []string `json:"compliance,omitempty"`
	ExecutionModel string   `json:"executionModel,omitempty"` // "deterministic" | "agentic"
}

// Invariants are the signed, non-expansive state of a lineage: the authority
// that may continue (operations) and the contract executors must satisfy.
type Invariants struct {
	Operations        []string          `json:"operations"`
	ExecutionContract ExecutionContract `json:"executionContract"`
}

// Continuation is the freshness challenge a PCA emits for its next hop (§6.1).
type Continuation struct {
	Challenge string    `json:"challenge"`
	Mode      string    `json:"mode"`              // "single-use"
	MaxUses   int       `json:"maxUses,omitempty"` // per-Verifier local bound
	ExpiresAt time.Time `json:"expiresAt"`
}

// Attestation is a signed attribute attestation: the conformance evidence an
// executor presents to prove it satisfies the predecessor execution contract
// (§1.6). Its Proof is the issuer's signature.
type Attestation struct {
	Subject    string             `json:"subject"`
	Attributes ContractAttributes `json:"attributes"`
	IssuedAt   time.Time          `json:"issuedAt"`
	ExpiresAt  time.Time          `json:"expiresAt"`
	Issuer     string             `json:"issuer"`
	Proof      *Proof             `json:"proof,omitempty"`
}

// attestationSigningBytes returns the canonical bytes the issuer signature
// covers: the attestation without its own proof.
func attestationSigningBytes(a Attestation) ([]byte, error) {
	a.Proof = nil
	return canonicalJSON(a)
}

// ContractAttributes are the attested attributes checked against an execution
// contract by the conformance function (§3.3 check 5, §4.2).
type ContractAttributes struct {
	Role           string   `json:"role,omitempty"`
	Compliance     []string `json:"compliance,omitempty"`
	ExecutionModel string   `json:"executionModel,omitempty"`
	Environment    string   `json:"environment,omitempty"`
	Region         string   `json:"region,omitempty"`
}

// Request is the request binding: it pins authority to the concrete action, so
// enforcement can check executed-vs-signed (§2.3, §3.3 check 8).
type Request struct {
	Operation      string `json:"operation"`
	Target         string `json:"target"`
	SecurityDomain string `json:"securityDomain"`
	RequestDigest  string `json:"requestDigest,omitempty"`
	PayloadDigest  string `json:"payloadDigest,omitempty"`
}

// ContinuationResponse answers the predecessor's challenge with a fresh local
// nonce (§2.3). It proves the executor observed and holds the predecessor PCA.
type ContinuationResponse struct {
	PredecessorChallenge string `json:"predecessorChallenge"`
	ExecutorNonce        string `json:"executorNonce"`
}

// PoR (Proof of Relationship) binds the current execution to exactly one
// predecessor (§2.3). It is carried in the clear and covered by the PCA signature.
type PoR struct {
	Type                 string               `json:"type"`
	PreviousPcaHash      string               `json:"previousPcaHash"`
	ContinuationResponse ContinuationResponse `json:"continuationResponse"`
	Executor             string               `json:"executor"`
	Request              Request              `json:"request"`
	ExecutorAttestation  Attestation          `json:"executorAttestation"`
}

// Proof is a single detached signature covering a document as a whole.
type Proof struct {
	Type               string `json:"type"`
	VerificationMethod string `json:"verificationMethod"`
	Signature          string `json:"signature"`
}

// PCA is a PIC Context of Authority: the signed document carrying a lineage's
// invariants at one hop. PCA0 (the origin) carries no PoR and no previous hash.
//
// The revocation coordinates (profile, lineageId, lineageCounter, branchId,
// grantId, originIssuer) are the Revocation-spec fields propagated along the
// lineage; originNonce and issuer appear on PCA0 only.
type PCA struct {
	// Revocation coordinates (Revocation spec §2).
	Profile        string `json:"profile,omitempty"`
	LineageID      string `json:"lineageId,omitempty"`
	LineageCounter uint64 `json:"lineageCounter"`
	BranchID       string `json:"branchId,omitempty"`
	GrantID        string `json:"grantId,omitempty"`
	OriginIssuer   string `json:"originIssuer,omitempty"`

	// Origin (PCA0) only.
	Issuer      string `json:"issuer,omitempty"`
	OriginNonce string `json:"originNonce,omitempty"`

	// Non-origin only.
	ProofOfRelationship *PoR `json:"proofOfRelationship,omitempty"`

	Invariants   Invariants   `json:"invariants"`
	Continuation Continuation `json:"continuation"`

	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`

	// Outer single signature over the whole PCA (§2.5).
	Proof *Proof `json:"proof,omitempty"`
}

// IsOrigin reports whether this PCA is a PCA0 (no Proof of Relationship).
func (p *PCA) IsOrigin() bool { return p.ProofOfRelationship == nil }

// Digest returns the content-addressed id of the complete, signed PCA
// ("sha256:<hex>" over its canonical bytes, proof included). This is the value a
// successor places in previousPcaHash (§2.5).
func (p *PCA) Digest() (string, error) { return digestOf(p) }

// signingBytes returns the canonical bytes a signature covers: the whole PCA
// except the outer proof (a document cannot sign its own signature).
func (p *PCA) signingBytes() ([]byte, error) {
	saved := p.Proof
	p.Proof = nil
	b, err := canonicalJSON(p)
	p.Proof = saved
	return b, err
}

// Envelope is the signed handoff wrapper carrying the predecessor and current
// PCAs together (§2.5). Envelopes are never nested.
type Envelope struct {
	Envelope EnvelopeBody `json:"envelope"`
	Proof    *Proof       `json:"proof,omitempty"`
}

// EnvelopeBody carries the two self-contained PCAs and their convenience digests.
type EnvelopeBody struct {
	ForwardedBy       string `json:"forwardedBy"`
	Predecessor       *PCA   `json:"predecessor"`
	PredecessorDigest string `json:"predecessorDigest"`
	Current           *PCA   `json:"current"`
	CurrentDigest     string `json:"currentDigest"`
}

func (e *Envelope) signingBytes() ([]byte, error) {
	saved := e.Proof
	e.Proof = nil
	b, err := canonicalJSON(e)
	e.Proof = saved
	return b, err
}

// Snapshot is a signed attestation from a trusted issuer that the chain of a
// lineage is valid up to PCA[throughCounter], whose content id is throughPcaHash
// (Prover/Verifier spec §5.2). A downstream Verifier trusts it as the chain tip
// and validates only the hops after it.
type Snapshot struct {
	LineageID      string    `json:"lineageId"`
	ThroughCounter uint64    `json:"throughCounter"`
	ThroughPcaHash string    `json:"throughPcaHash"`
	Issuer         string    `json:"issuer"`
	IssuedAt       time.Time `json:"issuedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	Proof          *Proof    `json:"proof,omitempty"`
}

func (s *Snapshot) signingBytes() ([]byte, error) {
	saved := s.Proof
	s.Proof = nil
	b, err := canonicalJSON(s)
	s.Proof = saved
	return b, err
}
