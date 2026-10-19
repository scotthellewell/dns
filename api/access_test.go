package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/scott/dns/auth"
	"github.com/scott/dns/storage"
)

// fixedSessionAuth stands in for the auth manager and gives every request the
// same session.
type fixedSessionAuth struct{ session *auth.Session }

func (f fixedSessionAuth) MiddlewareFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(w, r.WithContext(auth.ContextWithSession(r.Context(), f.session)))
	}
}

func (f fixedSessionAuth) IsEnabled() bool { return true }

var (
	superAdmin   = &auth.Session{Username: "root", TenantID: auth.MainTenantID, Role: auth.RoleSuperAdmin, IsSuperAdmin: true}
	adminKey     = &auth.Session{Username: "API Key: admin", TenantID: auth.MainTenantID, Role: "admin"}
	mainUser     = &auth.Session{Username: "main-user", TenantID: auth.MainTenantID, Role: auth.RoleUser}
	mainReadonly = &auth.Session{Username: "viewer", TenantID: auth.MainTenantID, Role: auth.RoleReadonly}
	otherUser    = &auth.Session{Username: "other", TenantID: "other", Role: auth.RoleUser}
)

// newAccessTestStore returns a store with three zones: main.test (main
// tenant), legacy.test (no tenant, as stored before tenancy) and other.test
// (tenant "other"), each with an A record "www".
func newAccessTestStore(t *testing.T) (*storage.Store, map[string]string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "dns-access-test-*")
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(storage.Options{DataDir: dir})
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close(); os.RemoveAll(dir) })

	if err := store.CreateTenant(&storage.Tenant{ID: "other", Name: "Other"}); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for zone, tenant := range map[string]string{"main.test": auth.MainTenantID, "legacy.test": "", "other.test": "other"} {
		if err := store.CreateZone(&storage.Zone{Name: zone, Type: storage.ZoneTypeForward, TenantID: tenant, TTL: 3600}); err != nil {
			t.Fatal(err)
		}
		rec := &storage.Record{Zone: zone, Name: "www", Type: "A", TTL: 300, Enabled: true, Data: []byte(`{"ip":"192.0.2.1"}`)}
		if err := store.CreateRecord(rec); err != nil {
			t.Fatal(err)
		}
		ids[zone] = rec.ID
	}
	// CreateZone fills in the main tenant; store legacy.test with none, as
	// older or synced zones can be.
	legacy, err := store.GetZone("legacy.test")
	if err != nil {
		t.Fatal(err)
	}
	legacy.TenantID = ""
	if err := store.UpdateZone(legacy); err != nil {
		t.Fatal(err)
	}
	if z, _ := store.GetZone("legacy.test"); z.TenantID != "" {
		t.Fatalf("legacy.test tenant = %q, want empty", z.TenantID)
	}
	return store, ids
}

func newAccessTestMux(t *testing.T, store *storage.Store, session *auth.Session) *http.ServeMux {
	t.Helper()
	cfg, err := store.BuildParsedConfig()
	if err != nil {
		t.Fatal(err)
	}
	h := NewWithStorage(cfg, store, nil)
	mux := http.NewServeMux()
	a := fixedSessionAuth{session}
	h.RegisterRoutesWithAuth(mux, a)
	RegisterPortRoutesWithAuth(mux, h.corsMiddleware, a.MiddlewareFunc)
	RegisterCertRoutesWithAuth(mux, h.corsMiddleware, a.MiddlewareFunc)
	return mux
}

func do(mux *http.ServeMux, method, path string, body interface{}) *httptest.ResponseRecorder {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func recordExists(t *testing.T, store *storage.Store, zone, id string) bool {
	t.Helper()
	recs, err := store.GetAllZoneRecords(zone)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.ID == id {
			return true
		}
	}
	return false
}

func TestReadonlyCannotWrite(t *testing.T) {
	store, ids := newAccessTestStore(t)
	mux := newAccessTestMux(t, store, mainReadonly)

	if w := do(mux, "GET", "/api/records", nil); w.Code != http.StatusOK {
		t.Fatalf("GET records: got %d, want 200", w.Code)
	}
	if w := do(mux, "POST", "/api/records", RecordRequest{Zone: "main.test", Name: "new", Type: "A", TTL: 300, IP: "192.0.2.9"}); w.Code != http.StatusForbidden {
		t.Errorf("POST record: got %d, want 403", w.Code)
	}
	if w := do(mux, "DELETE", "/api/records/A/"+ids["main.test"], nil); w.Code != http.StatusForbidden {
		t.Errorf("DELETE record: got %d, want 403", w.Code)
	}
	if !recordExists(t, store, "main.test", ids["main.test"]) {
		t.Error("read-only session deleted a record")
	}
}

func TestServerWideEndpointsNeedServerAdmin(t *testing.T) {
	store, _ := newAccessTestStore(t)
	paths := []string{"/api/config", "/api/dnssec", "/api/settings", "/api/rrl", "/api/blocklist", "/api/delegations", "/api/ports", "/api/certs/list"}

	for _, s := range []*auth.Session{mainUser, mainReadonly, otherUser} {
		mux := newAccessTestMux(t, store, s)
		for _, p := range paths {
			if w := do(mux, "GET", p, nil); w.Code != http.StatusForbidden {
				t.Errorf("%s GET %s: got %d, want 403", s.Username, p, w.Code)
			}
		}
	}
	for _, s := range []*auth.Session{superAdmin, adminKey} {
		mux := newAccessTestMux(t, store, s)
		for _, p := range paths {
			if w := do(mux, "GET", p, nil); w.Code == http.StatusForbidden {
				t.Errorf("%s GET %s: got 403, want access", s.Username, p)
			}
		}
	}
}

func TestRecordByIDStaysInTenant(t *testing.T) {
	store, ids := newAccessTestStore(t)
	mux := newAccessTestMux(t, store, otherUser)

	// Another tenant's record, by ID: not found, and untouched.
	for _, zone := range []string{"main.test", "legacy.test"} {
		if w := do(mux, "PUT", "/api/records/A/"+ids[zone], RecordRequest{TTL: 60, IP: "203.0.113.66"}); w.Code != http.StatusNotFound {
			t.Errorf("PUT %s record: got %d, want 404", zone, w.Code)
		}
		if w := do(mux, "DELETE", "/api/records/A/"+ids[zone], nil); w.Code != http.StatusNotFound {
			t.Errorf("DELETE %s record: got %d, want 404", zone, w.Code)
		}
		if !recordExists(t, store, zone, ids[zone]) {
			t.Errorf("other tenant deleted a record in %s", zone)
		}
	}

	// By bare name: no longer matches anything.
	if w := do(mux, "DELETE", "/api/records/A/www", nil); w.Code != http.StatusNotFound {
		t.Errorf("DELETE by name: got %d, want 404", w.Code)
	}
	if !recordExists(t, store, "other.test", ids["other.test"]) {
		t.Error("DELETE by name removed a record")
	}

	// Wrong type for the ID: not found.
	if w := do(mux, "DELETE", "/api/records/TXT/"+ids["other.test"], nil); w.Code != http.StatusNotFound {
		t.Errorf("DELETE with wrong type: got %d, want 404", w.Code)
	}

	// Its own record: allowed.
	if w := do(mux, "DELETE", "/api/records/A/"+ids["other.test"], nil); w.Code != http.StatusOK {
		t.Errorf("DELETE own record: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
}

func TestMainUserCanEditLegacyZones(t *testing.T) {
	store, ids := newAccessTestStore(t)
	mux := newAccessTestMux(t, store, mainUser)

	if w := do(mux, "PUT", "/api/records/A/"+ids["legacy.test"], RecordRequest{TTL: 60, IP: "192.0.2.2"}); w.Code != http.StatusOK {
		t.Errorf("PUT legacy record: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if w := do(mux, "POST", "/api/records", RecordRequest{Zone: "legacy.test", Name: "new", Type: "A", TTL: 300, IP: "192.0.2.3"}); w.Code != http.StatusOK {
		t.Errorf("POST legacy record: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if w := do(mux, "DELETE", "/api/records/A/"+ids["other.test"], nil); w.Code != http.StatusNotFound {
		t.Errorf("DELETE other tenant's record: got %d, want 404", w.Code)
	}
}

func TestCreateRecordStaysInTenant(t *testing.T) {
	store, _ := newAccessTestStore(t)
	mux := newAccessTestMux(t, store, otherUser)

	for _, zone := range []string{"main.test", "legacy.test"} {
		if w := do(mux, "POST", "/api/records", RecordRequest{Zone: zone, Name: "evil", Type: "A", TTL: 300, IP: "203.0.113.66"}); w.Code != http.StatusForbidden {
			t.Errorf("POST into %s: got %d, want 403", zone, w.Code)
		}
	}
	if w := do(mux, "POST", "/api/records", RecordRequest{Zone: "other.test", Name: "ok", Type: "A", TTL: 300, IP: "192.0.2.4"}); w.Code != http.StatusOK {
		t.Errorf("POST into own zone: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
}

func TestZoneExportStaysInTenant(t *testing.T) {
	store, _ := newAccessTestStore(t)
	mux := newAccessTestMux(t, store, otherUser)

	for _, zone := range []string{"main.test", "legacy.test"} {
		if w := do(mux, "GET", "/api/zones/export/"+zone, nil); w.Code != http.StatusForbidden {
			t.Errorf("export %s: got %d, want 403", zone, w.Code)
		}
	}
	if w := do(mux, "GET", "/api/zones/export/other.test", nil); w.Code != http.StatusOK {
		t.Errorf("export own zone: got %d, want 200", w.Code)
	}
}
