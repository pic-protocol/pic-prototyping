// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

// Package pic is a minimal, standard-library-only reference prototype of the PIC
// Prover, Verifier, Snapshot Hash Chain profile, and native revocation cutoffs.
//
// It is non-normative and exists for exploration and benchmarking. The PIC
// Specification (github.com/pic-protocol/pic-spec) is authoritative.
package pic

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
)

// suite identifiers used by this illustrative profile (Prover/Verifier spec §6.4).
const (
	SignatureType    = "Ed25519Signature2020"
	digestPrefix     = "sha256:"
	lineageDomainSep = "PIC-Lineage-v0"
	branchRootDomain = "PIC-Root-Branch-v0"
)

// b64 is the URL-safe base64 encoding without padding used throughout the profile.
var b64 = base64.RawURLEncoding

// Identity is an executor, issuer, or principal: an Ed25519 key pair addressed by
// an identifier (a DID in the examples, but any string works) and a verification
// method. PIC does not depend on any identifier scheme; a bare key pair suffices.
type Identity struct {
	ID                 string
	VerificationMethod string
	Public             ed25519.PublicKey
	private            ed25519.PrivateKey
}

// NewIdentity generates a fresh Ed25519 identity. The verification method is the
// identifier with a "#key-1" fragment, matching the spec examples.
func NewIdentity(id string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{
		ID:                 id,
		VerificationMethod: id + "#key-1",
		Public:             pub,
		private:            priv,
	}, nil
}

// sign produces a detached signature over msg with this identity's private key.
func (id *Identity) sign(msg []byte) string {
	return b64.EncodeToString(ed25519.Sign(id.private, msg))
}

// Registry resolves a verification method (or bare issuer id) to a public key.
// It stands in for a DID resolver / key distribution mechanism, which is out of
// scope for PIC itself.
type Registry struct {
	keys map[string]ed25519.PublicKey
}

// NewRegistry returns an empty key registry.
func NewRegistry() *Registry { return &Registry{keys: map[string]ed25519.PublicKey{}} }

// Add registers an identity under both its verification method and its id, so a
// Verifier can resolve either form.
func (r *Registry) Add(id *Identity) {
	r.keys[id.VerificationMethod] = id.Public
	r.keys[id.ID] = id.Public
}

// verify checks sig (base64url) over msg for the key registered under ref.
func (r *Registry) verify(ref string, msg []byte, sig string) error {
	pub, ok := r.keys[ref]
	if !ok {
		return fmt.Errorf("unknown verification method %q", ref)
	}
	raw, err := b64.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("malformed signature: %w", err)
	}
	if !ed25519.Verify(pub, msg, raw) {
		return fmt.Errorf("signature does not verify under %q", ref)
	}
	return nil
}

// canonicalJSON returns a deterministic JSON encoding of v: object keys sorted
// lexicographically, no insignificant whitespace, numbers preserved. This is the
// reproducible byte representation a hash or signature covers (spec §6.4). It is
// an illustrative canonicalization, sufficient for this prototype.
func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, tree); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		enc, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(enc)
	}
	return nil
}

// hashHex returns "sha256:<hex>" over the canonical encoding of v.
func digestOf(v any) (string, error) {
	b, err := canonicalJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return digestPrefix + hexEncode(sum[:]), nil
}

// hashBytes returns "sha256:<hex>" over the domain-separated concatenation of
// the given parts. Used for lineageId and branchId derivation (Revocation spec).
func hashParts(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return digestPrefix + hexEncode(h.Sum(nil))
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

// randomB64 returns n random bytes encoded as base64url (challenges, nonces).
func randomB64(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b64.EncodeToString(buf), nil
}
