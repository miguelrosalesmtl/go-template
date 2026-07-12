package server

import (
	"context"

	"github.com/miguelrosalesmtl/go-template/internal/identity"
)

// contextKey is unexported so no other package can write these keys. That is the
// whole security property of this file: the only way a request context can come
// to hold a user or a tenant is by passing through the middleware below, which
// means a handler that reads one is guaranteed it was authenticated and
// authorized rather than supplied by the caller.
type contextKey int

const (
	userKey contextKey = iota
	sessionKey
	accessKey
)

// withUser attaches the authenticated user. Called only by requireAuth.
func withUser(ctx context.Context, u identity.User, s identity.Session) context.Context {
	ctx = context.WithValue(ctx, userKey, u)
	return context.WithValue(ctx, sessionKey, s)
}

// withTenant attaches the caller's resolved authority in the request's tenant.
// Called only by requireTenant.
func withTenant(ctx context.Context, access identity.TenantAccess) context.Context {
	return context.WithValue(ctx, accessKey, access)
}

// accessFrom returns the caller's full authority in the request's tenant,
// including whether it came from a membership or the superuser bypass. Most
// handlers want tenantFrom or roleFrom instead.
func accessFrom(ctx context.Context) identity.TenantAccess {
	a, ok := ctx.Value(accessKey).(identity.TenantAccess)
	if !ok {
		panic("server: no tenant access in context -- this route is missing the requireTenant middleware")
	}
	return a
}

// userFrom returns the authenticated user.
//
// It panics if there is none, and that is deliberate: it can only happen if a
// route was registered outside the requireAuth middleware, which is a programming
// error that must surface loudly in development rather than turn into a nil-user
// request that quietly reads somebody else's data in production. chi's Recoverer
// turns the panic into a 500.
func userFrom(ctx context.Context) identity.User {
	u, ok := ctx.Value(userKey).(identity.User)
	if !ok {
		panic("server: no user in context -- this route is missing the requireAuth middleware")
	}
	return u
}

// sessionFrom returns the session the request authenticated with.
func sessionFrom(ctx context.Context) identity.Session {
	s, ok := ctx.Value(sessionKey).(identity.Session)
	if !ok {
		panic("server: no session in context -- this route is missing the requireAuth middleware")
	}
	return s
}

// tenantFrom returns the tenant this request is scoped to. Every repository call
// a handler makes must be filtered by this tenant's ID.
func tenantFrom(ctx context.Context) identity.Tenant {
	return accessFrom(ctx).Tenant
}

// The tryX accessors are the non-panicking variants, for code that runs on paths
// where the middleware may not have got as far as populating the context -- above
// all the error handler, which has to record a denial for a request that failed
// BEFORE authentication, at authentication, or after it. It cannot assume any of
// them, and it must never panic while trying to log a refusal.

// tryUserFrom returns the authenticated user, if there is one.
func tryUserFrom(ctx context.Context) (identity.User, bool) {
	u, ok := ctx.Value(userKey).(identity.User)
	return u, ok
}

// tryAccessFrom returns the caller's tenant authority, if a tenant was resolved.
func tryAccessFrom(ctx context.Context) (identity.TenantAccess, bool) {
	a, ok := ctx.Value(accessKey).(identity.TenantAccess)
	return a, ok
}
