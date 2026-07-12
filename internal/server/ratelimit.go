package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miguelrosalesmtl/go-template/internal/identity"
	"github.com/miguelrosalesmtl/go-template/internal/settings"
)

// A token-bucket rate limiter for the unauthenticated endpoints.
//
// KNOW WHAT THIS IS AND IS NOT. It is in-memory, so it is PER-REPLICA: three
// replicas means three times the configured allowance, and a restart forgets
// everything. A shared counter would mean Redis, which this template deliberately
// does not have.
//
// So it is a speed bump, not a wall. It exists so that an unprotected deployment
// is not trivially brute-forceable, and so that the shape of the thing -- which
// endpoints, keyed on what, audited how -- is already correct when you replace it.
// A serious deployment puts the real limiter at the proxy or the WAF, where it
// sees every replica's traffic and can drop a request before it costs you a
// goroutine. The README says so too.
//
// Login is keyed by IP *and* by email. Keying only on IP lets one attacker spray a
// thousand accounts from one address at one attempt each and never trip; keying
// only on email lets a botnet hammer one account from a thousand addresses. Both
// keys must pass.

// limiter is a fixed-window counter, keyed by an arbitrary string.
//
// A fixed window rather than a leaky bucket because the failure mode -- up to 2x
// the limit across a window boundary -- does not matter for a speed bump, and the
// implementation fits on a screen and has no dependencies.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	attempts int
	window   time.Duration
}

type bucket struct {
	count     int
	expiresAt time.Time
}

func newLimiter(cfg settings.RateLimit) *limiter {
	l := &limiter{
		buckets:  make(map[string]*bucket),
		attempts: cfg.Attempts,
		window:   cfg.Window,
	}
	return l
}

// allow records an attempt against key and reports whether it is permitted. When
// it is not, it also returns how long the caller should wait.
func (l *limiter) allow(key string) (bool, time.Duration) {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok || now.After(b.expiresAt) {
		l.buckets[key] = &bucket{count: 1, expiresAt: now.Add(l.window)}
		return true, 0
	}

	if b.count >= l.attempts {
		return false, time.Until(b.expiresAt)
	}
	b.count++
	return true, 0
}

// reap discards expired buckets.
//
// Without it the map is an unbounded, attacker-controlled allocation: every new IP
// creates an entry, and nothing would ever remove it. That is a memory-exhaustion
// bug wearing a rate-limiter costume.
func (l *limiter) reap() {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	for key, b := range l.buckets {
		if now.After(b.expiresAt) {
			delete(l.buckets, key)
		}
	}
}

// runReaper prunes expired buckets until ctx is done. Started by the server.
func (l *limiter) runReaper(done <-chan struct{}) {
	ticker := time.NewTicker(l.window)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			l.reap()
		}
	}
}

// rateLimit guards a route. keyFn derives the bucket key from the request; return
// several keys to require that ALL of them pass -- which is how login is limited
// by IP and by email at once.
func (s *Server) rateLimit(keyFn func(*http.Request) []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.limiter == nil { // disabled
				next.ServeHTTP(w, r)
				return
			}

			for _, key := range keyFn(r) {
				if key == "" {
					continue
				}
				ok, retryAfter := s.limiter.allow(key)
				if ok {
					continue
				}

				// Retry-After is not politeness: it is what lets a legitimate client
				// back off correctly instead of hammering, and what stops your own
				// SDK from turning a limit into an outage.
				w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))

				// errorHandler audits it. A single 429 is noise; a stream of them
				// from one IP is an attack, and the audit log is where you would see
				// the difference.
				s.errors.handle(w, r, identity.ErrRateLimited)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------- keys

// byIP limits on the client address alone. Used where there is no better key.
func (s *Server) byIP(prefix string) func(*http.Request) []string {
	return func(r *http.Request) []string {
		return []string{prefix + "|ip|" + s.clientIP(r)}
	}
}

// byIPAndEmail limits on the client address AND the email in the body, requiring
// both to pass.
//
// Keying on only one of them leaves an obvious hole in each direction: IP alone
// lets an attacker spray a thousand accounts from one address, one attempt each,
// and never trip a counter; email alone lets a botnet hammer one account from a
// thousand addresses. Both.
//
// Reading the body here means buffering it so the handler can read it again --
// which is why this peeks at a bounded copy rather than consuming the stream.
func (s *Server) byIPAndEmail(prefix string) func(*http.Request) []string {
	return func(r *http.Request) []string {
		keys := []string{prefix + "|ip|" + s.clientIP(r)}
		if email := peekEmail(r); email != "" {
			keys = append(keys, prefix+"|email|"+email)
		}
		return keys
	}
}

// peekEmail reads the "email" field out of the request body WITHOUT consuming it,
// by buffering the body and putting it back for the handler.
//
// Middleware that reads the body is a classic way to produce a handler that then
// sees an empty one, so the restore is the entire point of this function. The read
// is bounded by maxBodyBytes for the same reason the decoder is: an unbounded read
// here would be a free denial of service.
//
// A malformed body is not an error to this function -- it returns "" and lets the
// handler produce the 400. The limiter's job is to count, not to validate.
func peekEmail(r *http.Request) string {
	if r.Body == nil {
		return ""
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return ""
	}
	// Put it back, or the handler decodes an empty body.
	r.Body = io.NopCloser(bytes.NewReader(raw))

	var body struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(body.Email))
}
