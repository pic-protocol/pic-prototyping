// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package pic

import (
	"fmt"
	"strings"
	"time"
)

// Verifier validates PCAs before any authority is exercised (Prover/Verifier
// spec §3). It resolves keys through a Registry, consults an optional
// RevocationStore, and keeps per-Verifier state for single-use challenges.
type Verifier struct {
	Registry    *Registry
	Revocations *RevocationStore // optional; nil means no revocation state consulted

	used map[string]bool // consumed single-use challenges (§6.1)
}

// NewVerifier returns a Verifier over the given key registry and (optional)
// revocation store.
func NewVerifier(reg *Registry, rev *RevocationStore) *Verifier {
	return &Verifier{Registry: reg, Revocations: rev, used: map[string]bool{}}
}

// VerifyOrigin validates a PCA0 (§3.2) and the revocation-coordinate derivation
// (Revocation spec §2.1, §2.4): signature under the issuer, validity window,
// profile present, and lineageId/branchId recomputed from the origin core.
func (v *Verifier) VerifyOrigin(p *PCA, now time.Time) error {
	if !p.IsOrigin() {
		return fmt.Errorf("origin validation: PCA carries a Proof of Relationship")
	}
	if p.Proof == nil {
		return fmt.Errorf("origin validation: missing signature")
	}
	msg, err := p.signingBytes()
	if err != nil {
		return err
	}
	if err := v.Registry.verify(p.Issuer, msg, p.Proof.Signature); err != nil {
		return fmt.Errorf("origin validation: %w", err)
	}
	if err := withinValidity(p.IssuedAt, p.ExpiresAt, now); err != nil {
		return fmt.Errorf("origin validation: %w", err)
	}
	if p.Profile != RevocableProfile {
		return fmt.Errorf("origin validation: unknown profile %q", p.Profile)
	}
	if p.LineageCounter != 0 {
		return fmt.Errorf("origin validation: lineageCounter must be 0, got %d", p.LineageCounter)
	}
	wantLineage, err := deriveLineageID(p)
	if err != nil {
		return err
	}
	if p.LineageID != wantLineage {
		return fmt.Errorf("origin validation: lineageId does not match origin commitment")
	}
	if p.BranchID != rootBranchID(p.LineageID) {
		return fmt.Errorf("origin validation: branchId is not the derived root branch id")
	}
	if v.Revocations != nil {
		if err := v.Revocations.Check(p); err != nil {
			return fmt.Errorf("origin validation: %w", err)
		}
	}
	return nil
}

// VerifyHop validates a non-origin PCA against its already-validated predecessor,
// performing the ordered checks of §3.3 plus the revocation-coordinate
// continuity of Revocation spec §2.3. If consume is true, single-use challenges
// are marked consumed (live acceptance); re-validation of history passes false.
func (v *Verifier) VerifyHop(cur, pred *PCA, now time.Time, consume bool) error {
	if cur.IsOrigin() {
		return fmt.Errorf("hop validation: PCA carries no Proof of Relationship")
	}
	por := cur.ProofOfRelationship

	// 1. integrity — single signature over the whole PCA.
	if cur.Proof == nil {
		return fmt.Errorf("hop: missing signature")
	}
	msg, err := cur.signingBytes()
	if err != nil {
		return err
	}
	if err := v.Registry.verify(cur.Proof.VerificationMethod, msg, cur.Proof.Signature); err != nil {
		return fmt.Errorf("hop integrity: %w", err)
	}

	// 2. predecessor binding — previousPcaHash equals the presented predecessor.
	predDigest, err := pred.Digest()
	if err != nil {
		return err
	}
	if por.PreviousPcaHash != predDigest {
		return fmt.Errorf("hop binding: previousPcaHash does not match the presented predecessor")
	}

	// Revocation-coordinate continuity (Revocation spec §2.3).
	if err := coordinateContinuity(cur, pred); err != nil {
		return fmt.Errorf("hop coordinates: %w", err)
	}

	// 3. continuation — response carries the predecessor challenge, unexpired,
	//    and (single-use) not already consumed.
	if por.ContinuationResponse.PredecessorChallenge != pred.Continuation.Challenge {
		return fmt.Errorf("hop continuation: response does not answer the predecessor challenge")
	}
	if !now.Before(pred.Continuation.ExpiresAt) {
		return fmt.Errorf("hop continuation: predecessor challenge expired")
	}
	if consume && pred.Continuation.Mode == "single-use" {
		if v.used[pred.Continuation.Challenge] {
			return fmt.Errorf("hop continuation: single-use challenge already consumed (replay)")
		}
	}

	// 4. attestation — embedded issuer signature valid, within validity, subject
	//    matches the executor, which matches the key that signed the PCA.
	if err := v.verifyAttestation(por, cur.Proof.VerificationMethod, now); err != nil {
		return fmt.Errorf("hop attestation: %w", err)
	}

	// 5. conformance — attested attributes satisfy the predecessor contract.
	if err := Conforms(por.ExecutorAttestation.Attributes, pred.Invariants.ExecutionContract); err != nil {
		return fmt.Errorf("hop conformance: %w", err)
	}

	// 6. non-expansion — invariants are equal to or more restrictive.
	if err := Attenuates(cur.Invariants, pred.Invariants); err != nil {
		return fmt.Errorf("hop non-expansion: %w", err)
	}

	// 7. temporal — hop window contained in the predecessor's (§6.3).
	if err := temporalCheck(cur, pred, now); err != nil {
		return fmt.Errorf("hop temporal: %w", err)
	}

	// (8. request match — executed-vs-signed — is enforced at execution time by
	//     the reference monitor against por.Request; see Authorize / scenario.)

	// revocation state — is this position cut off?
	if v.Revocations != nil {
		if err := v.Revocations.Check(cur); err != nil {
			return fmt.Errorf("hop revocation: %w", err)
		}
	}

	if consume && pred.Continuation.Mode == "single-use" {
		v.used[pred.Continuation.Challenge] = true
	}
	return nil
}

// coordinateContinuity enforces the hop-by-hop continuity of the revocation
// coordinates (Revocation spec §2.3).
func coordinateContinuity(cur, pred *PCA) error {
	if cur.Profile != pred.Profile {
		return fmt.Errorf("profile changed")
	}
	if cur.LineageID != pred.LineageID {
		return fmt.Errorf("lineageId changed")
	}
	if (cur.GrantID == "") != (pred.GrantID == "") || cur.GrantID != pred.GrantID {
		return fmt.Errorf("grantId presence/value changed")
	}
	if cur.OriginIssuer != pred.OriginIssuer {
		return fmt.Errorf("originIssuer changed")
	}
	if cur.BranchID != pred.BranchID {
		return fmt.Errorf("branchId changed without an authorized branch-creation transition")
	}
	// exact counter rule: current == predecessor + 1, no overflow/wrap.
	if cur.LineageCounter != pred.LineageCounter+1 {
		return fmt.Errorf("lineageCounter must be predecessor+1 (%d), got %d", pred.LineageCounter+1, cur.LineageCounter)
	}
	return nil
}

func (v *Verifier) verifyAttestation(por *PoR, pcaVM string, now time.Time) error {
	att := por.ExecutorAttestation
	if att.Proof == nil {
		return fmt.Errorf("attestation missing issuer signature")
	}
	msg, err := attestationSigningBytes(att)
	if err != nil {
		return err
	}
	if err := v.Registry.verify(att.Issuer, msg, att.Proof.Signature); err != nil {
		return fmt.Errorf("issuer signature: %w", err)
	}
	if err := withinValidity(att.IssuedAt, att.ExpiresAt, now); err != nil {
		return fmt.Errorf("attestation validity: %w", err)
	}
	if att.Subject != por.Executor {
		return fmt.Errorf("attestation subject %q does not match executor %q", att.Subject, por.Executor)
	}
	// the key that signed the PCA must belong to the executor.
	if !strings.HasPrefix(pcaVM, por.Executor) {
		return fmt.Errorf("PCA signing key %q does not belong to executor %q", pcaVM, por.Executor)
	}
	return nil
}

// VerifyFullChain validates a whole chain from PCA0 to the tip (Full Hash Chain
// profile, §5.1): cost O(n). It returns the invariants authorized at the tip.
// History re-validation does not consume single-use challenges.
func (v *Verifier) VerifyFullChain(chain []*PCA, now time.Time) (Invariants, error) {
	if len(chain) == 0 {
		return Invariants{}, fmt.Errorf("empty chain")
	}
	if err := v.VerifyOrigin(chain[0], now); err != nil {
		return Invariants{}, err
	}
	for i := 1; i < len(chain); i++ {
		if err := v.VerifyHop(chain[i], chain[i-1], now, false); err != nil {
			return Invariants{}, fmt.Errorf("hop %d: %w", i, err)
		}
	}
	return chain[len(chain)-1].Invariants, nil
}

// VerifyEnvelope validates one incremental transition carried in an envelope
// (§6.8): envelope signature and digests, then the single hop cur-against-pred,
// consuming the predecessor's single-use challenge. It trusts the predecessor
// inductively (validated by the hop that produced it) rather than walking back.
func (v *Verifier) VerifyEnvelope(env *Envelope, now time.Time) (Invariants, error) {
	body := env.Envelope
	if body.Current == nil || body.Predecessor == nil {
		return Invariants{}, fmt.Errorf("envelope: missing predecessor or current")
	}
	if env.Proof == nil {
		return Invariants{}, fmt.Errorf("envelope: missing signature")
	}
	msg, err := env.signingBytes()
	if err != nil {
		return Invariants{}, err
	}
	if err := v.Registry.verify(env.Proof.VerificationMethod, msg, env.Proof.Signature); err != nil {
		return Invariants{}, fmt.Errorf("envelope signature: %w", err)
	}
	// digests are convenience, not trusted input: recompute and cross-check.
	predDigest, err := body.Predecessor.Digest()
	if err != nil {
		return Invariants{}, err
	}
	curDigest, err := body.Current.Digest()
	if err != nil {
		return Invariants{}, err
	}
	if body.PredecessorDigest != predDigest || body.CurrentDigest != curDigest {
		return Invariants{}, fmt.Errorf("envelope: supplied digest does not match recomputed digest")
	}
	if body.Current.ProofOfRelationship.PreviousPcaHash != predDigest {
		return Invariants{}, fmt.Errorf("envelope: current.previousPcaHash does not equal predecessorDigest")
	}
	if v.Revocations != nil {
		if err := v.Revocations.Check(body.Predecessor); err != nil {
			return Invariants{}, fmt.Errorf("envelope predecessor: %w", err)
		}
	}
	if err := v.VerifyHop(body.Current, body.Predecessor, now, true); err != nil {
		return Invariants{}, err
	}
	return body.Current.Invariants, nil
}

func withinValidity(issuedAt, expiresAt, now time.Time) error {
	if now.Before(issuedAt) {
		return fmt.Errorf("not yet valid")
	}
	if !now.Before(expiresAt) {
		return fmt.Errorf("expired")
	}
	return nil
}

func temporalCheck(cur, pred *PCA, now time.Time) error {
	if cur.IssuedAt.Before(pred.IssuedAt) {
		return fmt.Errorf("issuedAt precedes predecessor")
	}
	if cur.ExpiresAt.After(pred.ExpiresAt) {
		return fmt.Errorf("expiresAt exceeds predecessor")
	}
	if err := withinValidity(cur.IssuedAt, cur.ExpiresAt, now); err != nil {
		return err
	}
	if cur.Continuation.ExpiresAt.After(pred.ExpiresAt) {
		return fmt.Errorf("emitted challenge outlives the lineage")
	}
	return nil
}
