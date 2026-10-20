package api

import (
	"net/http"

	"github.com/scott/dns/auth"
	"github.com/scott/dns/storage"
)

// Access rules shared by the API handlers. A nil session means auth is
// disabled (the non-storage mux); with storage, the auth middleware always
// sets one.

// tenantOf treats an empty tenant ID as the main tenant, matching how zones
// created before tenancy are stored.
func tenantOf(id string) string {
	if id == "" {
		return auth.MainTenantID
	}
	return id
}

// canAccessZone reports whether the session may read or change the zone.
func canAccessZone(session *auth.Session, zone *storage.Zone) bool {
	if session == nil || session.IsSuperAdmin {
		return true
	}
	return tenantOf(session.TenantID) == tenantOf(zone.TenantID)
}

// isServerAdmin reports whether the session may use server-wide endpoints
// (config, DNSSEC keys, certs, ports, blocklist and so on). The "admin" role
// comes from API keys with the admin permission.
func isServerAdmin(session *auth.Session) bool {
	return session == nil || session.IsSuperAdmin || session.Role == "admin"
}

func isReadMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// requireWrite rejects changes from read-only sessions.
func requireWrite(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.GetSession(r.Context())
		if session != nil && session.Role == auth.RoleReadonly && !isReadMethod(r.Method) {
			http.Error(w, "Read-only access", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// RequireServerAdmin limits an endpoint to server admins. It must run after
// the auth middleware, which puts the session in the request context.
func RequireServerAdmin(next http.HandlerFunc) http.HandlerFunc {
	return requireServerAdmin(next)
}

// requireServerAdmin limits an endpoint to server admins.
func requireServerAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isServerAdmin(auth.GetSession(r.Context())) {
			http.Error(w, "Server admin access required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
