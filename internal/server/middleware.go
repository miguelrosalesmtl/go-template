package server

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/auth"
	"github.com/miguelrosalesmtl/go-template/internal/identity"
)

// withAuditMeta attaches the request id, client IP, and user agent to the context,
// so every audit entry written while serving this request carries them.
//
// It sits at the top of the chain, before authentication, precisely because the
// entries that most need it are the ones written when authentication FAILS.
func (s *Server) withAuditMeta(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := audit.RequestMeta{
			RequestID: middleware.GetReqID(r.Context()),
			IPAddress: s.clientIP(r),
			UserAgent: r.UserAgent(),
		}
		next.ServeHTTP(w, r.WithContext(audit.WithRequestMeta(r.Context(), meta)))
	})
}

// requireAuth authenticates the bearer token and puts the acting user on the
// request context. Everything behind it can call userFrom(ctx) unconditionally.
//
// It accepts two kinds of credential. A session token (mtt_sess_) belongs to a
// human and derives authority from their memberships. An API key (mtt_key_) belongs
// to an organization, carries its own frozen permission scope, and acts AS its
// creating user -- so userFrom still works, and the audit trail names a person,
// tagged with the key it came through. A key is bound to one organization, so it is
// only meaningful on organization-scoped routes; sessionOnly keeps it off the rest.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			s.errors.handle(w, r, identity.ErrUnauthenticated)
			return
		}

		if strings.HasPrefix(token, auth.APIKeyTokenPrefix) {
			key, org, actor, err := s.identity.AuthenticateAPIKey(r.Context(), token)
			if err != nil {
				s.errors.handle(w, r, err)
				return
			}
			// Act as the creating user (no session), and remember the key so
			// requireOrganization can bind the request to the key's organization.
			ctx := withUser(r.Context(), actor, identity.Session{})
			ctx = withAPIKey(ctx, apiKeyContext{key: key, org: org})
			// Re-stamp the audit metadata to tag every entry with the key id. The
			// earlier withAuditMeta could not: it runs before authentication.
			ctx = audit.WithRequestMeta(ctx, audit.RequestMeta{
				RequestID: middleware.GetReqID(ctx),
				IPAddress: s.clientIP(r),
				UserAgent: r.UserAgent(),
				APIKeyID:  &key.ID,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		user, session, err := s.identity.Authenticate(r.Context(), token)
		if err != nil {
			s.errors.handle(w, r, err)
			return
		}

		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user, session)))
	})
}

// sessionOnly rejects API-key credentials. It guards the routes that only make
// sense for a logged-in human -- account management and the staff surface -- so a
// key scoped to one organization can never change its owner's password, create
// organizations, or reach /admin. A key is for programmatic access to an
// organization's own resources, and nothing more.
func (s *Server) sessionOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := apiKeyFrom(r.Context()); ok {
			writeError(w, http.StatusForbidden,
				"API keys cannot be used on this endpoint; authenticate with a user session")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireOrganization resolves the {organization} slug in the path, verifies the caller may
// act in it, and puts the organization and their role on the context.
//
// This is the single choke point for organization authorization. Every route under
// /api/v1/organizations/{organization} passes through it, so no handler has to remember to
// check membership -- and no handler can forget to.
func (s *Server) requireOrganization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slug := chi.URLParam(r, "organization")

		// An API key is bound to exactly one organization. It may act only on that
		// organization's URL; anything else is 404, the same answer a stranger gets,
		// so a key cannot even confirm another organization exists. Its authority is
		// the key's frozen scope -- no membership lookup, no roles.
		if kc, ok := apiKeyFrom(r.Context()); ok {
			if slug != kc.org.Slug {
				s.errors.handle(w, r, identity.ErrNotFound)
				return
			}
			access := identity.OrganizationAccess{
				Organization: kc.org,
				Permissions:  kc.key.Permissions,
				ViaAPIKey:    true,
			}
			next.ServeHTTP(w, r.WithContext(withOrganization(r.Context(), access)))
			return
		}

		user := userFrom(r.Context())

		access, err := s.identity.ResolveOrganization(r.Context(), user, slug)
		if err != nil {
			// ResolveOrganization returns ErrNotFound both for an organization that does not
			// exist and for one the caller cannot see, so this 404s either way.
			s.errors.handle(w, r, err)
			return
		}

		// A superuser entering an organization they do not belong to. Record it BEFORE
		// serving, so an access is logged even if the handler then panics or the
		// client disconnects mid-response.
		//
		// A failure to write the audit entry fails the request. That is the whole
		// bargain: the bypass is allowed precisely because it cannot happen
		// unseen, so an unauditable access must not proceed.
		if access.ViaSuperuser {
			if err := s.identity.RecordSuperuserAccess(
				r.Context(), user, access.Organization, r.Method, r.URL.Path,
			); err != nil {
				s.log.Error("could not audit superuser organization access -- refusing the request",
					slog.String("user_id", user.ID.String()),
					slog.String("organization", access.Organization.Slug),
					slog.String("error", err.Error()),
				)
				s.errors.handle(w, r, err)
				return
			}
			s.log.Warn("superuser entered an organization they are not a member of",
				slog.String("user_id", user.ID.String()),
				slog.String("email", user.Email),
				slog.String("organization", access.Organization.Slug),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
			)
		}

		next.ServeHTTP(w, r.WithContext(withOrganization(r.Context(), access)))
	})
}

// requireSuperuser guards the staff surface at /api/v1/admin. It must sit inside
// requireAuth, which is what put the user on the context.
//
// A non-superuser gets 404, not 403. The staff surface should not advertise its
// own existence to an ordinary user who goes poking at /api/v1/admin.
func (s *Server) requireSuperuser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !userFrom(r.Context()).IsSuperuser {
			s.errors.handle(w, r, identity.ErrNotFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requirePermission rejects callers who lack permission p in the request's
// organization. It must sit inside requireOrganization, which is what resolved the caller's
// permission set and put it on the context.
//
// This is where RBAC is actually enforced. It replaced a requireRole(RoleAdmin)
// ladder, and the difference is not cosmetic: a ladder can only ask "are you at
// least an admin?", which cannot express "may manage billing but not members",
// because authority was one-dimensional. A permission set has no ordering, so
// every route states exactly the one thing it needs.
//
// The permission must exist in identity.Catalog. If you guard a route with a
// permission you forgot to add there, no role can ever be granted it -- the
// foreign key on role_permissions makes sure of that -- and the route becomes
// unreachable by anyone except a superuser. That is a loud failure by design.
func (s *Server) requirePermission(p identity.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !accessFrom(r.Context()).Can(p) {
				s.errors.handle(w, r, identity.ErrForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// bearerToken pulls the credential out of the Authorization header. The scheme
// match is case-insensitive because RFC 7235 says it is.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// clientIP returns the caller's IP for the session and audit records.
//
// X-Forwarded-For is honoured only when SERVER_TRUST_PROXY_HEADERS is on. The
// header is trivially forged by anyone talking to the server directly, so
// trusting it unconditionally would let a caller write whatever IP they liked
// into the audit log -- which is worse than having no IP at all. Turn it on only
// when a proxy you control is guaranteed to overwrite the header.
func (s *Server) clientIP(r *http.Request) string {
	if s.config.TrustProxyHeaders {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			// The left-most entry is the original client; the rest are the proxies
			// it passed through.
			first, _, _ := strings.Cut(fwd, ",")
			if ip := strings.TrimSpace(first); ip != "" {
				return ip
			}
		}
		if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
			return real
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // no port, e.g. a unix socket
	}
	return host
}

// requestMeta bundles what the service records about the caller of a request.
func (s *Server) requestMeta(r *http.Request) identity.RequestMeta {
	// Cap the User-Agent: it is attacker-controlled and goes straight into a text
	// column, and nobody needs 8KB of it.
	ua := r.UserAgent()
	if len(ua) > 512 {
		ua = ua[:512]
	}
	return identity.RequestMeta{UserAgent: ua, IPAddress: s.clientIP(r)}
}

// requestLogger logs one line per request. It deliberately never logs the
// Authorization header, the request body, or the query string -- all three
// routinely carry credentials.
func requestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			log.Info("request",
				slog.String("method", r.Method),
				// r.URL.Path, not RequestURI: the query string may hold a token.
				slog.String("path", r.URL.Path),
				slog.Int("status", rec.status),
				slog.Duration("duration", time.Since(start)),
				slog.String("request_id", middleware.GetReqID(r.Context())),
			)
		})
	}
}

// statusRecorder captures the status code so the logger can report it.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
