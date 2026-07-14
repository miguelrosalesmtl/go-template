package server

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// corsMaxAge is how long a browser may cache a preflight. A day: long enough that
// preflights are not a per-request cost, short enough that revoking an origin takes
// effect the same day.
const corsMaxAge = 24 * time.Hour

// CORS and the security headers.

// securityHeaders sets the headers a browser needs in order to protect a user from
// this API misbehaving -- or from somebody else's page trying to make it misbehave.
//
// They are cheap, they are static, and every one of them is here because its
// absence is a finding in any security review you will ever have.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// Do not let a browser guess that our JSON is really HTML and run it. This
		// is what turns a stored string into a stored XSS.
		h.Set("X-Content-Type-Options", "nosniff")

		// This API returns JSON and never a page. A CSP that forbids everything is
		// therefore free, and it means a response that somehow does get rendered can
		// load nothing and run nothing.
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		// Belt and braces for the same thing on older browsers.
		h.Set("X-Frame-Options", "DENY")

		// Do not leak our URLs -- which contain organization slugs, and in the reset flow a
		// TOKEN -- to whatever site the user clicks through to next.
		h.Set("Referrer-Policy", "no-referrer")

		// Tell browsers to refuse plaintext for a year. Only meaningful over HTTPS,
		// and harmless otherwise, so it is unconditional rather than a config knob
		// somebody forgets to turn on.
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		next.ServeHTTP(w, r)
	})
}

// cors answers cross-origin requests from the configured allowlist.
//
// EMPTY ALLOWLIST MEANS OFF, and that is the right default for an API with no
// browser client: no origin is echoed, so no browser will let another site call
// this API at all.
//
// The allowlist is EXACT, never a wildcard, and never a pattern. This API
// authenticates with a bearer token, and Access-Control-Allow-Origin: * together
// with credentials is the one combination the CORS specification refuses to honour
// -- because it would let every site on the internet make authenticated calls with
// your users' tokens. settings.validate refuses a "*" in production for the same
// reason.
func (s *Server) cors(next http.Handler) http.Handler {
	allowed := s.corsCfg.AllowedOrigins

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Not a cross-origin request, or CORS is switched off. Either way there is
		// nothing to say, and saying nothing is what blocks the browser.
		if origin == "" || len(allowed) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		if !slices.Contains(allowed, origin) {
			// Deliberately no headers and no error: the request is served normally
			// and the BROWSER refuses to hand the response to the page. Returning a
			// 403 here would be worse -- it tells a probing script which origins are
			// allowed, and it breaks non-browser clients, which send an Origin header
			// sometimes and are not subject to CORS at all.
			next.ServeHTTP(w, r)
			return
		}

		h := w.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")

		// The response varies by Origin, so a cache must not serve one origin's
		// response to another. Forgetting this turns a CDN into a CORS bypass.
		h.Add("Vary", "Origin")

		// The preflight.
		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			h.Set("Access-Control-Max-Age", strconv.Itoa(int(corsMaxAge.Seconds())))
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Retry-After is on 429s and the client cannot read it cross-origin unless we
		// say so. Same for the request id, which is what a user quotes in a bug report.
		h.Set("Access-Control-Expose-Headers", strings.Join([]string{
			"Retry-After", "X-Request-Id",
		}, ", "))

		next.ServeHTTP(w, r)
	})
}
