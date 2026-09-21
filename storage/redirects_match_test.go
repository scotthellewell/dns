package storage

import "testing"

// The "*.google.*" SafeSearch preset used an unanchored substring test, so it
// matched any name merely containing or starting with a google label. That
// redirected google.com.example.com - a domain Google does not own - to the
// SafeSearch VIP, and pointed every Google *service* host (FCM push, Play
// Store, Android checkin) at a front-end that only answers on 443.
func TestMatchDomain_DoubleWildcard(t *testing.T) {
	const pattern = "*.google.*"
	cases := []struct {
		domain string
		want   bool
		why    string
	}{
		{"google.com", true, "bare google domain"},
		{"www.google.com", true, "search host"},
		{"google.co.uk", true, "two-label public suffix"},
		{"www.google.de", true, "country search host"},
		{"mtalk.google.com", true, "service host is still a google domain"},

		{"google.com.example.com", false, "third-party domain that merely starts with google."},
		{"notgoogle.com", false, "google is a substring, not a label"},
		{"google.com.evil.net", false, "google label too far from the end"},
		{"googleapis.com", false, "different label entirely"},
		{"storage.googleapis.com", false, "googleapis is not google"},
		{"example.com", false, "unrelated"},
	}
	for _, c := range cases {
		if got := matchDomain(pattern, c.domain); got != c.want {
			t.Errorf("matchDomain(%q, %q) = %v, want %v (%s)", pattern, c.domain, got, c.want, c.why)
		}
	}
}

func TestMatchDomain_TrailingWildcard(t *testing.T) {
	const pattern = "google.*"
	cases := []struct {
		domain string
		want   bool
	}{
		{"google.com", true},
		{"google.co.uk", true},
		{"www.google.com", false},         // pattern has no leading *.
		{"google.com.example.com", false}, // the original false positive
		{"example.com", false},
	}
	for _, c := range cases {
		if got := matchDomain(pattern, c.domain); got != c.want {
			t.Errorf("matchDomain(%q, %q) = %v, want %v", pattern, c.domain, got, c.want)
		}
	}
}

func TestMatchDomain_LeadingWildcardUnchanged(t *testing.T) {
	const pattern = "*.youtube.com"
	for d, want := range map[string]bool{
		"youtube.com":             true,
		"www.youtube.com":         true,
		"m.youtube.com":           true,
		"youtube.com.example.net": false,
		"notyoutube.com":          false,
	} {
		if got := matchDomain(pattern, d); got != want {
			t.Errorf("matchDomain(%q, %q) = %v, want %v", pattern, d, got, want)
		}
	}
}

// SafeSearch needs to reach the search hosts only - google.<tld> and
// www.google.<tld> - not every Google service host. The trailing-wildcard
// branch therefore has to cope with a multi-label prefix.
func TestMatchDomain_MultiLabelPrefix(t *testing.T) {
	const pattern = "www.google.*"
	for d, want := range map[string]bool{
		"www.google.com":          true,
		"www.google.co.uk":        true,
		"www.google.de":           true,
		"google.com":              false, // bare domain needs its own rule
		"mtalk.google.com":        false, // service host must NOT be redirected
		"play.google.com":         false,
		"www.google.com.evil.net": false,
	} {
		if got := matchDomain(pattern, d); got != want {
			t.Errorf("matchDomain(%q, %q) = %v, want %v", pattern, d, got, want)
		}
	}
}
