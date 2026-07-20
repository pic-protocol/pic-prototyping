// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package pic

import (
	"fmt"
	"time"
)

// Durations used by the illustrative profile. A profile picks its own values.
const (
	DefaultLineageTTL   = 24 * time.Hour  // whole-lineage validity (§6.3)
	DefaultHopTTL       = 5 * time.Minute // tighter per-hop window (§6.3)
	DefaultChallengeTTL = 5 * time.Minute // continuation challenge lifetime (§6.1)
)

// signPCA computes the single outer signature over the PCA (proof excluded) and
// attaches it (§2.5).
func signPCA(p *PCA, signer *Identity) error {
	msg, err := p.signingBytes()
	if err != nil {
		return err
	}
	p.Proof = &Proof{
		Type:               SignatureType,
		VerificationMethod: signer.VerificationMethod,
		Signature:          signer.sign(msg),
	}
	return nil
}

// SignAttestation returns a copy of att signed by its issuer (the conformance
// evidence of §1.6). The issuer key must be registered so a Verifier can check it.
func SignAttestation(att Attestation, issuer *Identity) (Attestation, error) {
	att.Issuer = issuer.ID
	msg, err := attestationSigningBytes(att)
	if err != nil {
		return att, err
	}
	att.Proof = &Proof{
		Type:               SignatureType,
		VerificationMethod: issuer.VerificationMethod,
		Signature:          issuer.sign(msg),
	}
	return att, nil
}

// MintPCA0 creates and signs an origin PCA for `issuer` (Prover/Verifier spec
// §1.8), stamped with the revocation coordinates of the revocable profile:
// a fresh originNonce, the derived lineageId, lineageCounter 0, the root
// branchId, and originIssuer = issuer. `grantID` may be empty.
//
// Minting/deriving a PCA0 (e.g. from an OAuth token at a gateway) is the origin
// trust boundary and is out of PIC's continuity scope (§6.2); here the origin
// principal simply signs its own PCA0.
func MintPCA0(issuer *Identity, inv Invariants, grantID string, now time.Time) (*PCA, error) {
	nonce, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	challenge, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	p := &PCA{
		Profile:        RevocableProfile,
		LineageCounter: 0,
		GrantID:        grantID,
		OriginIssuer:   issuer.ID,
		Issuer:         issuer.ID,
		OriginNonce:    nonce,
		Invariants:     inv,
		Continuation: Continuation{
			Challenge: challenge,
			Mode:      "single-use",
			MaxUses:   1,
			ExpiresAt: now.Add(DefaultChallengeTTL),
		},
		IssuedAt:  now,
		ExpiresAt: now.Add(DefaultLineageTTL),
	}
	// Derive the lineage identity from the non-self-referential origin core, then
	// the root branch id (Revocation spec §2.1, §2.4).
	lineageID, err := deriveLineageID(p)
	if err != nil {
		return nil, err
	}
	p.LineageID = lineageID
	p.BranchID = rootBranchID(lineageID)

	if err := signPCA(p, issuer); err != nil {
		return nil, err
	}
	return p, nil
}

// Prover constructs successor PCAs for one executor identity and its attestation.
type Prover struct {
	Executor    *Identity
	Attestation Attestation
}

// NewProver returns a Prover for the given executor identity and conformance
// attestation.
func NewProver(executor *Identity, attestation Attestation) *Prover {
	return &Prover{Executor: executor, Attestation: attestation}
}

// Continue builds and signs a successor PCA that continues `pred` with the given
// (attenuated) invariants and request binding (§2.1–§2.5). It performs the
// Prover self-check of §2.3/§2.4: a Prover MUST NOT emit an expansive successor.
func (pr *Prover) Continue(pred *PCA, inv Invariants, req Request, now time.Time) (*PCA, error) {
	return pr.build(pred, inv, req, nil, now, true)
}

// ContinueEnforce builds the next ordinary outer PCA of a Sandboxed Execution
// (PIC Sandboxed Execution Specification §2.5): it continues `pred` on the outer
// ENFORCE lineage and carries `ml` in the signed `multiLineage` profile field.
// The request MUST already commit to `ml` through req.MultiLineageDigest; the
// single PCA signature then covers both, pinning the concrete ENFORCE operation
// to that exact inner execution under the executed-vs-signed rule.
func (pr *Prover) ContinueEnforce(pred *PCA, inv Invariants, req Request, ml *MultiLineage, now time.Time) (*PCA, error) {
	return pr.build(pred, inv, req, ml, now, true)
}

// ContinueMalicious builds a successor PCA *without* the Prover self-check,
// simulating a buggy or compromised executor (§1.1). PIC's guarantee is that
// such a PCA still fails at the next honest Verifier; this constructor exists so
// the demo can show that rejection.
func (pr *Prover) ContinueMalicious(pred *PCA, inv Invariants, req Request, now time.Time) (*PCA, error) {
	return pr.build(pred, inv, req, nil, now, false)
}

func (pr *Prover) build(pred *PCA, inv Invariants, req Request, ml *MultiLineage, now time.Time, enforce bool) (*PCA, error) {
	if enforce {
		if err := Attenuates(inv, pred.Invariants); err != nil {
			return nil, fmt.Errorf("prover self-check failed: %w", err)
		}
		if err := Conforms(pr.Attestation.Attributes, pred.Invariants.ExecutionContract); err != nil {
			return nil, fmt.Errorf("prover self-check failed: %w", err)
		}
	}
	predDigest, err := pred.Digest()
	if err != nil {
		return nil, err
	}
	nonce, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	challenge, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	// Per-hop expiry is the tighter of the hop window and the lineage bound (§6.3).
	expires := now.Add(DefaultHopTTL)
	if expires.After(pred.ExpiresAt) {
		expires = pred.ExpiresAt
	}
	challengeExpiry := now.Add(DefaultChallengeTTL)
	if challengeExpiry.After(pred.ExpiresAt) {
		challengeExpiry = pred.ExpiresAt
	}

	p := &PCA{
		// Revocation coordinates propagated unchanged, counter incremented (§2.2).
		Profile:        pred.Profile,
		LineageID:      pred.LineageID,
		LineageCounter: pred.LineageCounter + 1,
		BranchID:       pred.BranchID,
		GrantID:        pred.GrantID,
		OriginIssuer:   pred.OriginIssuer,

		ProofOfRelationship: &PoR{
			Type:            PoRType,
			PreviousPcaHash: predDigest,
			ContinuationResponse: ContinuationResponse{
				PredecessorChallenge: pred.Continuation.Challenge,
				ExecutorNonce:        nonce,
			},
			Executor:            pr.Executor.ID,
			Request:             req,
			ExecutorAttestation: pr.Attestation,
		},
		Invariants: inv,
		Continuation: Continuation{
			Challenge: challenge,
			Mode:      "single-use",
			MaxUses:   1,
			ExpiresAt: challengeExpiry,
		},
		MultiLineage: ml, // Sandboxed Execution profile field (nil on ordinary PCAs)
		IssuedAt:     now,
		ExpiresAt:    expires,
	}
	if err := signPCA(p, pr.Executor); err != nil {
		return nil, err
	}
	return p, nil
}

// WrapEnvelope produces the signed handoff envelope carrying `pred` and
// `current` together (§2.5). The forwarder signs the envelope; the two PCAs keep
// their own signatures.
func WrapEnvelope(forwarder *Identity, pred, current *PCA) (*Envelope, error) {
	predDigest, err := pred.Digest()
	if err != nil {
		return nil, err
	}
	curDigest, err := current.Digest()
	if err != nil {
		return nil, err
	}
	env := &Envelope{
		Envelope: EnvelopeBody{
			ForwardedBy:       forwarder.ID,
			Predecessor:       pred,
			PredecessorDigest: predDigest,
			Current:           current,
			CurrentDigest:     curDigest,
		},
	}
	msg, err := env.signingBytes()
	if err != nil {
		return nil, err
	}
	env.Proof = &Proof{
		Type:               SignatureType,
		VerificationMethod: forwarder.VerificationMethod,
		Signature:          forwarder.sign(msg),
	}
	return env, nil
}
