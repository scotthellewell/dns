package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/scott/dns/api"
	"github.com/scott/dns/auth"
	"github.com/scott/dns/sync"
	bolt "go.etcd.io/bbolt"
)

// The sync API hands out the cluster's shared secret, so with auth on every
// /api/sync/* route must refuse anonymous and non-admin callers. Before this
// test it was registered with no auth at all.
func TestSyncAPIRequiresServerAdmin(t *testing.T) {
	db, err := bolt.Open(filepath.Join(t.TempDir(), "sync.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mgr, err := sync.NewManager(db, &sync.Config{ServerName: "test", SharedSecret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}

	// Stand-in for the auth manager: no header is unauthenticated (401), and
	// the X-Test-Role header picks the session.
	authMW := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var s *auth.Session
			switch r.Header.Get("X-Test-Role") {
			case "super_admin":
				s = &auth.Session{Role: auth.RoleSuperAdmin, IsSuperAdmin: true, TenantID: auth.MainTenantID}
			case "admin":
				s = &auth.Session{Role: "admin", TenantID: auth.MainTenantID}
			case "user":
				s = &auth.Session{Role: auth.RoleUser, TenantID: auth.MainTenantID}
			default:
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r.WithContext(auth.ContextWithSession(r.Context(), s)))
		}
	}
	mux := http.NewServeMux()
	registerSyncRoutes(mux, mgr, api.CORSMiddleware, authMW)

	paths := []string{"/api/sync/status", "/api/sync/config", "/api/sync/peers", "/api/sync/join-secret", "/api/sync/oplog"}
	for _, role := range []string{"", "user"} {
		for _, p := range paths {
			req := httptest.NewRequest("GET", p, nil)
			if role != "" {
				req.Header.Set("X-Test-Role", role)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
				t.Errorf("role %q GET %s: got %d, want 401/403 (%s)", role, p, w.Code, w.Body.String())
			}
		}
	}
	for _, role := range []string{"super_admin", "admin"} {
		req := httptest.NewRequest("GET", "/api/sync/status", nil)
		req.Header.Set("X-Test-Role", role)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("role %q GET /api/sync/status: got %d, want 200", role, w.Code)
		}
	}
}
