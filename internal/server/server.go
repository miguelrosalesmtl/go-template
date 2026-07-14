// Package server wires the HTTP API: routing, middleware, and lifecycle.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/miguelrosalesmtl/go-template/internal/identity"
	"github.com/miguelrosalesmtl/go-template/internal/settings"
)

// Server holds the HTTP server and its dependencies.
type Server struct {
	http     *http.Server
	identity *identity.Service
	pool     *pgxpool.Pool
	log      *slog.Logger
	errors   errorHandler
	config   settings.Server
	corsCfg  settings.CORS
	limiter  *limiter // nil when disabled
	done     chan struct{}
}

// New builds a Server with every route registered.
func New(
	cfg settings.Server,
	rateCfg settings.RateLimit,
	corsCfg settings.CORS,
	debug bool,
	identityService *identity.Service,
	pool *pgxpool.Pool,
	log *slog.Logger,
) *Server {
	s := &Server{
		identity: identityService,
		pool:     pool,
		log:      log,
		errors:   errorHandler{log: log, debug: debug, pool: pool},
		config:   cfg,
		corsCfg:  corsCfg,
		done:     make(chan struct{}),
	}

	if len(corsCfg.AllowedOrigins) > 0 {
		log.Info("CORS enabled", slog.Any("origins", corsCfg.AllowedOrigins))
	}

	if rateCfg.Enabled {
		s.limiter = newLimiter(rateCfg)
		// Prune expired buckets. Without this the map is an unbounded,
		// attacker-controlled allocation: every new IP adds an entry forever.
		go s.limiter.runReaper(s.done)
		log.Info("rate limiting enabled (in-memory, PER-REPLICA -- put the real limiter at your proxy)",
			slog.Int("attempts", rateCfg.Attempts),
			slog.Duration("window", rateCfg.Window),
		)
	} else {
		log.Warn("RATE LIMITING IS DISABLED: /auth/login and /auth/register are open to brute force")
	}

	s.http = &http.Server{
		Addr:         cfg.Addr(),
		Handler:      s.routes(),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}
	return s
}

// routes is the whole API surface on one screen. Read it top to bottom and you
// can see exactly which middleware guards which endpoint -- which is the point
// of keeping it in one function.
func (s *Server) routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)
	r.Use(s.cors)
	r.Use(requestLogger(s.log))

	// Put the request id, IP, and user agent on the context, so that EVERY audit
	// entry written during this request carries them without a single service
	// method having to know they exist. See audit.WithRequestMeta.
	r.Use(s.withAuditMeta)

	// Note: chi's middleware.RealIP is deliberately NOT used. It rewrites
	// RemoteAddr from X-Forwarded-For unconditionally, with no way to say whether
	// a trustworthy proxy set that header -- so with a directly-reachable server
	// any caller could forge the IP recorded against their own session and audit
	// entries. clientIP() in middleware.go does the same job, gated on
	// SERVER_TRUST_PROXY_HEADERS.

	// Probes. Unauthenticated by necessity: the load balancer has no credentials.
	r.Get("/healthz", s.handleHealth)
	r.Get("/readyz", s.handleReady)

	r.Route("/api/v1", func(r chi.Router) {
		// --- Public: no session required. -------------------------------------
		//
		// Every one of these is rate limited, and they are the only ones that need
		// to be: an attacker who already holds a session token has better things to
		// do than brute-force it. Login and reset are limited by IP AND by email --
		// IP alone lets one attacker spray a thousand accounts from one address at
		// one attempt each; email alone lets a botnet hammer one account from a
		// thousand addresses.
		r.With(s.rateLimit(s.byIPAndEmail("register"))).
			Post("/auth/register", s.handleRegister)
		r.With(s.rateLimit(s.byIPAndEmail("login"))).
			Post("/auth/login", s.handleLogin)

		// Password reset. Request always answers 204 -- even for an address with no
		// account -- because anything else is a free account-enumeration oracle on
		// an unauthenticated endpoint.
		r.With(s.rateLimit(s.byIPAndEmail("reset"))).
			Post("/auth/password/reset", s.handleRequestPasswordReset)
		r.With(s.rateLimit(s.byIP("reset-confirm"))).
			Post("/auth/password/reset/confirm", s.handleResetPassword)

		// Email verification. Public, because the user clicks the link from their
		// inbox and may not have a session in that browser.
		r.With(s.rateLimit(s.byIP("verify"))).
			Post("/auth/email/verify", s.handleVerifyEmail)

		// The permission catalog: every permission this build enforces, with its
		// description. A role editor renders its checkbox list from this, which is
		// what stops a UI from ever offering a permission that no code checks.
		//
		// It is public because it is not secret -- it is the same list that is in
		// the open-source code -- and a login screen may want it.
		r.Get("/permissions", s.handleListPermissions)

		// --- Authenticated: a valid session token, but no organization yet. ---------
		// These are the endpoints a user needs before they belong anywhere: see
		// who they are, list their organizations, make one, or accept an invitation.
		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)

			r.Post("/auth/logout", s.handleLogout)
			r.Get("/auth/me", s.handleMe)
			r.Post("/auth/password", s.handleChangePassword)

			// Listing your sessions and being unable to do anything about them was an
			// odd half-feature: it showed you the compromise and offered no way to
			// end it.
			r.Get("/auth/sessions", s.handleListSessions)
			r.Delete("/auth/sessions/{sessionID}", s.handleRevokeSession)

			r.With(s.rateLimit(s.byIP("verify-resend"))).
				Post("/auth/email/verify/resend", s.handleResendVerification)

			r.Get("/organizations", s.handleListOrganizations)
			r.Post("/organizations", s.handleCreateOrganization)

			// Accepting an invitation cannot sit under /organizations/{organization}: the
			// caller is not a member yet, so requireOrganization would 404 them.
			//
			// Rate limited even though it is authenticated: the token is a bearer
			// credential in a URL, and this is where somebody would guess at one.
			r.With(s.rateLimit(s.byIP("invitation-accept"))).
				Post("/invitations/accept", s.handleAcceptInvitation)
		})

		// --- Staff: superuser only. -------------------------------------------
		// The one part of the API that reads across organizations. A non-superuser gets
		// 404 here, not 403 -- the staff surface does not advertise itself.
		//
		// There is deliberately no route to GRANT superuser: see the CLI.
		r.Route("/admin", func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Use(s.requireSuperuser)

			r.Get("/organizations", s.handleAdminListOrganizations)
			r.Get("/users", s.handleAdminListUsers)
			r.Patch("/users/{userID}", s.handleAdminSetUserActive)

			// Restoring a soft-deleted organization HAS to live here rather than under
			// /organizations/{organization}: a deleted organization 404s for everyone, its own owners
			// included, so nobody inside it can ask for it back.
			r.Post("/organizations/{organizationID}/restore", s.handleAdminRestoreOrganization)
		})

		// --- Organization-scoped: authenticated AND able to act in {organization}. --------
		// Everything below requireOrganization can trust organizationFrom(ctx) and must scope
		// every query to it. This is where your own resources go.
		//
		// Each route names the ONE permission it needs. Read the block top to
		// bottom and you have the application's entire authorization policy --
		// which is the point of putting it here rather than scattering checks
		// through the handlers.
		r.Route("/organizations/{organization}", func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Use(s.requireOrganization)

			// The organization itself. PATCH changes the NAME; the slug is immutable and a
			// request that tries to change it is refused -- it lives in your
			// customers' bookmarks and webhook configs. DELETE is a SOFT delete:
			// invisible to everyone at once, nothing destroyed, restorable by a
			// superuser.
			r.With(s.requirePermission(identity.PermOrganizationRead)).
				Get("/", s.handleGetOrganization)
			r.With(s.requirePermission(identity.PermOrganizationUpdate)).
				Patch("/", s.handleUpdateOrganization)
			r.With(s.requirePermission(identity.PermOrganizationDelete)).
				Delete("/", s.handleDeleteOrganization)

			// Leaving is not a permission: any member may walk out, and requiring
			// members.delete to leave would trap a plain member in an organization forever.
			// The last-owner rule still applies, so the sole owner gets a 409 telling
			// them to appoint a successor first.
			r.Delete("/members/me", s.handleLeaveOrganization)

			// Members.
			r.With(s.requirePermission(identity.PermMembersRead)).
				Get("/members", s.handleListMembers)
			r.With(s.requirePermission(identity.PermMembersUpdate)).
				Put("/members/{userID}/roles", s.handleSetMemberRoles)
			r.With(s.requirePermission(identity.PermMembersDelete)).
				Delete("/members/{userID}", s.handleRemoveMember)

			// Invitations. Issuing one hands out a role, so the service ALSO applies
			// the escalation guard -- invitations.create lets you invite, it does not
			// let you invite somebody into a role more powerful than your own.
			r.With(s.requirePermission(identity.PermInvitationsRead)).
				Get("/invitations", s.handleListInvitations)
			r.With(s.requirePermission(identity.PermInvitationsCreate)).
				Post("/invitations", s.handleCreateInvitation)
			r.With(s.requirePermission(identity.PermInvitationsDelete)).
				Delete("/invitations/{invitationID}", s.handleRevokeInvitation)

			// Roles: the configurable part of RBAC. Split into create/update/delete,
			// so you can grant "may edit roles but not delete them".
			r.With(s.requirePermission(identity.PermRolesRead)).
				Get("/roles", s.handleListRoles)
			r.With(s.requirePermission(identity.PermRolesCreate)).
				Post("/roles", s.handleCreateRole)
			r.With(s.requirePermission(identity.PermRolesUpdate)).
				Put("/roles/{roleID}", s.handleUpdateRole)
			r.With(s.requirePermission(identity.PermRolesDelete)).
				Delete("/roles/{roleID}", s.handleDeleteRole)

			r.With(s.requirePermission(identity.PermAuditRead)).
				Get("/audit", s.handleListAuditLog)
		})
	})

	return r
}

// Start begins serving HTTP. It blocks until the server stops.
func (s *Server) Start() error {
	s.log.Info("http server listening", slog.String("addr", s.config.Addr()))
	if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown drains in-flight requests, up to the caller's deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	s.log.Info("http server shutting down")
	close(s.done) // stop the limiter's reaper
	return s.http.Shutdown(ctx)
}

// handleHealth is the liveness probe: the process is running. It must not touch
// the database -- if it did, a brief database blip would make Kubernetes kill
// every replica, turning a recoverable outage into a total one.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReady is the readiness probe: dependencies are reachable, so this
// replica can serve traffic. Unlike liveness, this one does check the database:
// a replica that cannot reach Postgres should be taken out of the load balancer,
// not restarted.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := s.pool.Ping(ctx); err != nil {
		s.log.Warn("readiness check failed", slog.String("error", err.Error()))
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
