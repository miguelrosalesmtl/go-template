package auth

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewTokenIsUniqueAndPrefixed(t *testing.T) {
	seen := make(map[string]bool, 100)

	for range 100 {
		plaintext, digest, err := NewToken(SessionTokenPrefix)
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}

		if !strings.HasPrefix(plaintext, SessionTokenPrefix) {
			t.Fatalf("token %q lacks the session prefix", plaintext)
		}
		if seen[plaintext] {
			t.Fatalf("NewToken returned a duplicate token: %q", plaintext)
		}
		seen[plaintext] = true

		// The digest must be reproducible from the plaintext -- that is the only
		// way an incoming bearer token can be matched against the stored row.
		if !bytes.Equal(digest, HashToken(plaintext)) {
			t.Fatal("the digest returned by NewToken does not match HashToken(plaintext)")
		}
	}
}

// The plaintext must not be recoverable from what we store. This is what makes a
// leak of the sessions table useless to an attacker.
func TestHashTokenIsNotReversible(t *testing.T) {
	plaintext, digest, err := NewToken(SessionTokenPrefix)
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	if bytes.Contains(digest, []byte(plaintext)) {
		t.Fatal("the digest contains the plaintext token")
	}
	if len(digest) != 32 { // SHA-256
		t.Fatalf("digest is %d bytes, want 32", len(digest))
	}
	if bytes.Equal(digest, HashToken(plaintext+"x")) {
		t.Fatal("a different token produced the same digest")
	}
}
