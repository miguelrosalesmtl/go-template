package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// tokenEntropyBytes is the size of the random part of a token. 32 bytes = 256
// bits, which is not brute-forceable and leaves no reason to economise.
const tokenEntropyBytes = 32

// Token prefixes. They make a leaked credential identifiable on sight -- in a
// log, a bug report, or a public repository -- and let secret scanners match on
// them. Change these to your product's name.
const (
	SessionTokenPrefix       = "mtt_sess_"
	InvitationTokenPrefix    = "mtt_inv_"
	PasswordResetTokenPrefix = "mtt_pwr_"
	EmailVerifyTokenPrefix   = "mtt_ver_"
)

// NewToken mints a cryptographically random bearer token and returns both the
// plaintext and its SHA-256 digest.
//
// The plaintext is shown to the user exactly once (in the login response, or in
// an invitation link) and is never stored. Only the digest goes to the database,
// so an attacker who reads the sessions table still cannot authenticate as
// anyone: they would have to invert SHA-256.
//
// Hashing a 256-bit random token with plain SHA-256 is correct and deliberate.
// The slow, salted hashing in this package's Hasher exists to defend low-entropy
// human-chosen passwords against offline guessing; a token has nothing to guess,
// so a fast digest costs nothing and keeps the per-request lookup cheap.
func NewToken(prefix string) (plaintext string, digest []byte, err error) {
	buf := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("auth: generate token: %w", err)
	}

	// URL-safe: the invitation token has to survive being pasted into a link.
	plaintext = prefix + base64.RawURLEncoding.EncodeToString(buf)
	return plaintext, HashToken(plaintext), nil
}

// HashToken returns the SHA-256 digest of a plaintext token. It is what turns a
// bearer token from an incoming request into the value to look up in the
// sessions or invitations table.
func HashToken(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:]
}
