package auth

import (
	"errors"
	"strings"
	"testing"
)

// Test cost. Far below the production defaults on purpose: these tests hash
// dozens of times and we are exercising the logic, not the work factor. Never
// copy these numbers into a config.
const (
	testMemory      = 64
	testIterations  = 1
	testParallelism = 1
)

func testHasher() *Hasher { return NewHasher(testMemory, testIterations, testParallelism) }

func TestHashAndVerify(t *testing.T) {
	h := testHasher()

	hash, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if err := h.Verify("correct horse battery staple", hash); err != nil {
		t.Errorf("Verify with the right password: got %v, want nil", err)
	}

	if err := h.Verify("wrong password", hash); !errors.Is(err, ErrMismatch) {
		t.Errorf("Verify with the wrong password: got %v, want ErrMismatch", err)
	}
}

// The salt is what stops an attacker who steals the table from spotting that two
// users share a password, and from attacking every hash with one rainbow table.
func TestHashIsSaltedPerCall(t *testing.T) {
	h := testHasher()

	first, err := h.Hash("same password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	second, err := h.Hash("same password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if first == second {
		t.Fatal("hashing the same password twice produced identical output: the salt is not random")
	}
	// Both must still verify -- a salt that broke verification would be worse.
	if err := h.Verify("same password", first); err != nil {
		t.Errorf("first hash does not verify: %v", err)
	}
	if err := h.Verify("same password", second); err != nil {
		t.Errorf("second hash does not verify: %v", err)
	}
}

func TestHashFormat(t *testing.T) {
	hash, err := testHasher().Hash("password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	// The PHC string is what makes the cost parameters portable, so its shape is
	// part of the contract, not an implementation detail.
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Errorf("hash %q does not start with the argon2id PHC prefix", hash)
	}
	if got := strings.Count(hash, "$"); got != 5 {
		t.Errorf("hash %q has %d '$' separators, want 5", hash, got)
	}
}

// A hash stored under weaker parameters must still verify -- otherwise raising
// the cost would lock every existing user out of their account.
func TestVerifyUsesTheParametersInTheHash(t *testing.T) {
	weak := NewHasher(64, 1, 1)
	strong := NewHasher(256, 3, 1)

	hash, err := weak.Hash("password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if err := strong.Verify("password", hash); err != nil {
		t.Errorf("a hash made with weaker parameters must still verify: %v", err)
	}
	if !strong.NeedsRehash(hash) {
		t.Error("NeedsRehash should flag a hash written under weaker parameters")
	}
	if weak.NeedsRehash(hash) {
		t.Error("NeedsRehash should not flag a hash written under the current parameters")
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	h := testHasher()

	tests := map[string]string{
		"empty":             "",
		"not PHC":           "just-a-string",
		"bcrypt":            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
		"too few fields":    "$argon2id$v=19$m=64,t=1,p=1$c2FsdA",
		"bad base64 salt":   "$argon2id$v=19$m=64,t=1,p=1$!!!!$c2FsdA",
		"unknown version":   "$argon2id$v=99$m=64,t=1,p=1$c2FsdA$aGFzaA",
		"bad parameters":    "$argon2id$v=19$m=abc,t=1,p=1$c2FsdA$aGFzaA",
		"empty derived key": "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$",
	}

	for name, hash := range tests {
		t.Run(name, func(t *testing.T) {
			err := h.Verify("password", hash)
			if err == nil {
				t.Fatal("a malformed hash must never verify")
			}
			// A malformed hash is a corrupt record, not a wrong password. Keeping
			// them distinguishable lets the service log the former and stay silent
			// about the latter.
			if errors.Is(err, ErrMismatch) {
				t.Errorf("got ErrMismatch, want a parse error: %v", err)
			}
		})
	}
}
