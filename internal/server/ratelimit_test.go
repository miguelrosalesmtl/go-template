package server

import (
	"testing"
	"time"

	"github.com/miguelrosalesmtl/go-template/internal/settings"
)

// The limiter's HTTP behaviour (429 + Retry-After) is covered by TestRateLimiting.
// These cover the in-memory bookkeeping directly, above all reap -- the guard that
// stops the bucket map from being an unbounded, attacker-controlled allocation.

func TestLimiterAllowWindow(t *testing.T) {
	l := newLimiter(settings.RateLimit{Attempts: 2, Window: time.Hour})

	if ok, _ := l.allow("k"); !ok {
		t.Fatal("first attempt should be allowed")
	}
	if ok, _ := l.allow("k"); !ok {
		t.Fatal("second attempt (at the limit) should be allowed")
	}
	ok, retryAfter := l.allow("k")
	if ok {
		t.Fatal("third attempt should be refused")
	}
	if retryAfter <= 0 {
		t.Errorf("a refused attempt must report a positive Retry-After, got %v", retryAfter)
	}

	// A different key is independent.
	if ok, _ := l.allow("other"); !ok {
		t.Error("a different key must have its own budget")
	}
}

func TestLimiterReapDropsExpiredBuckets(t *testing.T) {
	l := newLimiter(settings.RateLimit{Attempts: 1, Window: time.Hour})

	l.allow("live")
	l.allow("stale")
	// Force one bucket to look expired, as it would be after its window elapsed.
	l.buckets["stale"].expiresAt = time.Now().Add(-time.Minute)

	l.reap()

	if _, ok := l.buckets["stale"]; ok {
		t.Error("reap must delete an expired bucket")
	}
	if _, ok := l.buckets["live"]; !ok {
		t.Error("reap must keep a live bucket")
	}
}

func TestLimiterExpiredKeyResets(t *testing.T) {
	l := newLimiter(settings.RateLimit{Attempts: 1, Window: time.Hour})

	l.allow("k") // count = 1, at the limit
	if ok, _ := l.allow("k"); ok {
		t.Fatal("second attempt should be refused before expiry")
	}

	// Once the window passes, the key is fresh again.
	l.buckets["k"].expiresAt = time.Now().Add(-time.Second)
	if ok, _ := l.allow("k"); !ok {
		t.Error("an expired key should start a new window and be allowed")
	}
}
