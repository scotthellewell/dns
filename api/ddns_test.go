package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/scott/dns/storage"
)

func ddnsUpdate(mux *http.ServeMux, token, remote string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/ddns/update", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.RemoteAddr = remote
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// createDDNSHost creates a host as a super admin and returns its token.
func createDDNSHost(t *testing.T, store *storage.Store, zone, name string) string {
	t.Helper()
	w := do(newAccessTestMux(t, store, superAdmin), "POST", "/api/ddns/hosts", map[string]interface{}{"zone": zone, "name": name})
	if w.Code != http.StatusOK {
		t.Fatalf("create DDNS host: got %d (%s)", w.Code, w.Body.String())
	}
	var v ddnsHostView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v.Token, ddnsTokenPrefix) {
		t.Fatalf("create DDNS host: no token in %s", w.Body.String())
	}
	return v.Token
}

func aRecords(t *testing.T, store *storage.Store, zone, name string) []string {
	t.Helper()
	recs, err := store.GetRecords(zone, name, "A")
	if err != nil && err != storage.ErrNotFound {
		t.Fatal(err)
	}
	var ips []string
	for _, r := range recs {
		var d struct {
			IP string `json:"ip"`
		}
		_ = json.Unmarshal(r.Data, &d)
		ips = append(ips, d.IP)
	}
	return ips
}

func TestDDNSUpdate(t *testing.T) {
	store, _ := newAccessTestStore(t)
	token := createDDNSHost(t, store, "main.test", "home.dyn")
	mux := newAccessTestMux(t, store, nil)
	src := "198.51.100.10:40000"

	w := ddnsUpdate(mux, token, src, url.Values{"ip": {"203.0.113.5"}})
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "good 203.0.113.5" {
		t.Fatalf("first update: got %d %q", w.Code, w.Body.String())
	}
	if got := aRecords(t, store, "main.test", "home.dyn"); len(got) != 1 || got[0] != "203.0.113.5" {
		t.Fatalf("record after first update = %v", got)
	}

	w = ddnsUpdate(mux, token, src, url.Values{"ip": {"203.0.113.5"}})
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "nochg 203.0.113.5" {
		t.Errorf("repeat update: got %d %q", w.Code, w.Body.String())
	}

	w = ddnsUpdate(mux, token, src, url.Values{"ip": {"203.0.113.77"}})
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "good 203.0.113.77" {
		t.Errorf("changed update: got %d %q", w.Code, w.Body.String())
	}
	if got := aRecords(t, store, "main.test", "home.dyn"); len(got) != 1 || got[0] != "203.0.113.77" {
		t.Errorf("record after change = %v, want exactly [203.0.113.77]", got)
	}

	// The zone's other records are untouched.
	if got := aRecords(t, store, "main.test", "www"); len(got) != 1 || got[0] != "192.0.2.1" {
		t.Errorf("www record = %v, want untouched", got)
	}

	// The host remembers the last address; the admin view never shows the hash.
	host, _ := store.GetDDNSHost("home.dyn.main.test")
	if host == nil || host.LastIP != "203.0.113.77" {
		t.Errorf("host last IP = %+v", host)
	}
	list := do(newAccessTestMux(t, store, superAdmin), "GET", "/api/ddns/hosts", nil)
	if strings.Contains(list.Body.String(), host.TokenHash) || strings.Contains(list.Body.String(), "token") {
		t.Errorf("host list leaks token material: %s", list.Body.String())
	}
}

func TestDDNSUpdateUsesSourceAddress(t *testing.T) {
	store, _ := newAccessTestStore(t)
	token := createDDNSHost(t, store, "main.test", "src.dyn")
	mux := newAccessTestMux(t, store, nil)

	if w := ddnsUpdate(mux, token, "198.51.100.20:5000", nil); w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "good 198.51.100.20" {
		t.Errorf("update from public source: got %d %q", w.Code, w.Body.String())
	}
	// Behind a proxy the source is private: refuse instead of recording it.
	if w := ddnsUpdate(mux, token, "10.10.10.1:5000", nil); w.Code != http.StatusBadRequest {
		t.Errorf("update from private source: got %d %q, want 400", w.Code, w.Body.String())
	}
	if got := aRecords(t, store, "main.test", "src.dyn"); len(got) != 1 || got[0] != "198.51.100.20" {
		t.Errorf("record = %v, want [198.51.100.20]", got)
	}
}

func TestDDNSUpdateRejectsNonPublicAddresses(t *testing.T) {
	store, _ := newAccessTestStore(t)
	token := createDDNSHost(t, store, "main.test", "bad.dyn")
	mux := newAccessTestMux(t, store, nil)

	for _, ip := range []string{"10.0.0.1", "172.30.0.1", "192.168.1.1", "100.64.1.1", "127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.5", "fe80::1", "fd00::1", "nonsense"} {
		if w := ddnsUpdate(mux, token, "198.51.100.30:1", url.Values{"ip": {ip}}); w.Code != http.StatusBadRequest {
			t.Errorf("ip=%s: got %d %q, want 400", ip, w.Code, w.Body.String())
		}
	}
	if got := aRecords(t, store, "main.test", "bad.dyn"); len(got) != 0 {
		t.Errorf("record created from bad address: %v", got)
	}
}

func TestDDNSUpdateAuth(t *testing.T) {
	store, _ := newAccessTestStore(t)
	token := createDDNSHost(t, store, "main.test", "auth.dyn")
	mux := newAccessTestMux(t, store, nil)
	src := "198.51.100.40:1"
	form := url.Values{"ip": {"203.0.113.9"}}

	for name, tok := range map[string]string{"missing": "", "wrong": ddnsTokenPrefix + "AAAA", "no prefix": strings.TrimPrefix(token, ddnsTokenPrefix)} {
		if w := ddnsUpdate(mux, tok, src, form); w.Code != http.StatusUnauthorized {
			t.Errorf("%s token: got %d, want 401", name, w.Code)
		}
	}

	// The token in the URL is not accepted.
	req := httptest.NewRequest("POST", "/api/ddns/update?token="+url.QueryEscape(token)+"&ip=203.0.113.9", nil)
	req.RemoteAddr = src
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("token in URL: got %d, want 401", w.Code)
	}

	// X-DDNS-Token works as well as Bearer.
	req = httptest.NewRequest("POST", "/api/ddns/update", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-DDNS-Token", token)
	req.RemoteAddr = src
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("X-DDNS-Token: got %d %q", w.Code, w.Body.String())
	}
}

func TestDDNSTokenRotationAndDelete(t *testing.T) {
	store, _ := newAccessTestStore(t)
	oldToken := createDDNSHost(t, store, "main.test", "rot.dyn")
	admin := newAccessTestMux(t, store, superAdmin)
	mux := newAccessTestMux(t, store, nil)
	src := "198.51.100.50:1"
	form := url.Values{"ip": {"203.0.113.10"}}

	w := do(admin, "POST", "/api/ddns/hosts/rot.dyn.main.test/token", nil)
	var v ddnsHostView
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if w.Code != http.StatusOK || v.Token == "" || v.Token == oldToken {
		t.Fatalf("rotate: got %d %s", w.Code, w.Body.String())
	}
	if w := ddnsUpdate(mux, oldToken, src, form); w.Code != http.StatusUnauthorized {
		t.Errorf("old token after rotate: got %d, want 401", w.Code)
	}
	if w := ddnsUpdate(mux, v.Token, src, form); w.Code != http.StatusOK {
		t.Errorf("new token: got %d %q", w.Code, w.Body.String())
	}

	if w := do(admin, "DELETE", "/api/ddns/hosts/rot.dyn.main.test", nil); w.Code != http.StatusOK {
		t.Fatalf("delete: got %d", w.Code)
	}
	if w := ddnsUpdate(mux, v.Token, src, form); w.Code != http.StatusUnauthorized {
		t.Errorf("token after delete: got %d, want 401", w.Code)
	}
}

func TestDDNSHostsNeedServerAdmin(t *testing.T) {
	store, _ := newAccessTestStore(t)
	createDDNSHost(t, store, "main.test", "adm.dyn")

	for _, mux := range []*http.ServeMux{newAccessTestMux(t, store, mainUser), newAccessTestMux(t, store, otherUser), newAccessTestMux(t, store, mainReadonly)} {
		if w := do(mux, "GET", "/api/ddns/hosts", nil); w.Code != http.StatusForbidden {
			t.Errorf("list: got %d, want 403", w.Code)
		}
		if w := do(mux, "POST", "/api/ddns/hosts", map[string]string{"zone": "other.test", "name": "x"}); w.Code != http.StatusForbidden {
			t.Errorf("create: got %d, want 403", w.Code)
		}
		if w := do(mux, "POST", "/api/ddns/hosts/adm.dyn.main.test/token", nil); w.Code != http.StatusForbidden {
			t.Errorf("rotate: got %d, want 403", w.Code)
		}
	}
	if w := do(newAccessTestMux(t, store, adminKey), "GET", "/api/ddns/hosts", nil); w.Code != http.StatusOK {
		t.Errorf("admin key list: got %d, want 200", w.Code)
	}
}

func TestDDNSFailedAttemptsAreThrottled(t *testing.T) {
	store, _ := newAccessTestStore(t)
	token := createDDNSHost(t, store, "main.test", "thr.dyn")
	mux := newAccessTestMux(t, store, nil)
	src := "198.51.100.60:1"
	form := url.Values{"ip": {"203.0.113.11"}}

	for i := 0; i < ddnsFailLimit; i++ {
		ddnsUpdate(mux, ddnsTokenPrefix+"guess", src, form)
	}
	if w := ddnsUpdate(mux, token, src, form); w.Code != http.StatusTooManyRequests {
		t.Errorf("after %d failures: got %d, want 429", ddnsFailLimit, w.Code)
	}
	// Another source is unaffected.
	if w := ddnsUpdate(mux, token, "198.51.100.61:1", form); w.Code != http.StatusOK {
		t.Errorf("other source: got %d %q", w.Code, w.Body.String())
	}
}
