// Package auth holds the two primitives every multi-tenant app needs and nobody
// should hand-roll twice: password hashing and opaque bearer tokens.
//
// It knows nothing about users, organizations, or HTTP -- it deals only in strings and
// bytes, which keeps it trivially testable and reusable.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrMismatch reports that a password does not match the hash it was checked
// against. Callers must not distinguish it from "user not found" when
// responding to a login attempt, or they hand an attacker an account oracle.
var ErrMismatch = errors.New("auth: password does not match")

// saltLength and keyLength are in bytes. 16 and 32 are the sizes recommended in
// the Argon2 RFC (RFC 9106) and by OWASP.
const (
	saltLength = 16
	keyLength  = 32
)

// Hasher produces and verifies argon2id password hashes.
//
// Argon2id is the current OWASP first choice: it is memory-hard, so an attacker
// with GPUs or ASICs gains far less advantage than against bcrypt or PBKDF2.
type Hasher struct {
	memoryKiB   uint32
	iterations  uint32
	parallelism uint8
}

// NewHasher returns a Hasher with the given argon2id cost parameters. They come
// from settings.Auth so that tests can turn the cost down without weakening the
// production defaults.
func NewHasher(memoryKiB, iterations uint32, parallelism uint8) *Hasher {
	return &Hasher{memoryKiB: memoryKiB, iterations: iterations, parallelism: parallelism}
}

// Hash returns an encoded argon2id hash of the password, in the standard PHC
// string format:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<base64 salt>$<base64 key>
//
// The cost parameters and the salt travel inside the string, which is what lets
// Verify check a password against a hash produced with older parameters. That in
// turn means you can raise the cost over time without invalidating anyone's
// existing password.
func (h *Hasher) Hash(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, h.iterations, h.memoryKiB, h.parallelism, keyLength)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.memoryKiB, h.iterations, h.parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify reports whether password matches encodedHash. It returns ErrMismatch if
// the password is simply wrong, and a different error if the stored hash is
// malformed -- the caller should treat both as a failed login but may want to
// alert on the second.
//
// The parameters used are the ones embedded in encodedHash, not the ones on h,
// so a hash written under an older cost still verifies.
func (h *Hasher) Verify(password, encodedHash string) error {
	memoryKiB, iterations, parallelism, salt, want, err := decodeHash(encodedHash)
	if err != nil {
		return err
	}

	got := argon2.IDKey([]byte(password), salt, iterations, memoryKiB, parallelism, uint32(len(want)))

	// Constant-time: a byte-by-byte compare that returns early would leak, via
	// timing, how many leading bytes of the derived key were correct.
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

// NeedsRehash reports whether encodedHash was produced with weaker parameters
// than h currently uses. Call it after a successful Verify: that is the only
// moment the plaintext password is in hand, so it is the only moment you can
// transparently upgrade the stored hash to the stronger cost.
func (h *Hasher) NeedsRehash(encodedHash string) bool {
	memoryKiB, iterations, parallelism, _, _, err := decodeHash(encodedHash)
	if err != nil {
		// Unparseable: rewriting it is strictly an improvement.
		return true
	}
	return memoryKiB < h.memoryKiB ||
		iterations < h.iterations ||
		parallelism < h.parallelism
}

// decodeHash pulls the cost parameters, salt, and derived key back out of a PHC
// string.
func decodeHash(encodedHash string) (memoryKiB, iterations uint32, parallelism uint8, salt, key []byte, err error) {
	parts := strings.Split(encodedHash, "$")
	// A leading "$" means parts[0] is empty: ["", "argon2id", "v=19", "m=..", salt, key]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, errors.New("auth: hash is not in argon2id PHC format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("auth: parse hash version: %w", err)
	}
	if version != argon2.Version {
		return 0, 0, 0, nil, nil, fmt.Errorf("auth: unsupported argon2 version %d", version)
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memoryKiB, &iterations, &parallelism); err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("auth: parse hash parameters: %w", err)
	}

	if salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[4]); err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("auth: decode salt: %w", err)
	}
	if key, err = base64.RawStdEncoding.Strict().DecodeString(parts[5]); err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("auth: decode key: %w", err)
	}
	if len(key) == 0 {
		return 0, 0, 0, nil, nil, errors.New("auth: hash contains an empty key")
	}
	return memoryKiB, iterations, parallelism, salt, key, nil
}
