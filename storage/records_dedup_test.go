package storage

import (
	"encoding/json"
	"testing"
)

// The duplicate check used to compare Data byte-for-byte, so the same rdata
// encoded with different key ordering slipped through and produced a second
// record that served identically in DNS answers.
func TestCanonicalJSON_KeyOrderIndependent(t *testing.T) {
	a := json.RawMessage(`{"priority":0,"target":"mail.example.com."}`)
	b := json.RawMessage(`{"target":"mail.example.com.","priority":0}`)

	if string(a) == string(b) {
		t.Fatal("test is meaningless if the raw bytes already match")
	}
	if canonicalJSON(a) != canonicalJSON(b) {
		t.Errorf("same rdata with different key order must canonicalise equal:\n a=%s\n b=%s",
			canonicalJSON(a), canonicalJSON(b))
	}
}

func TestCanonicalJSON_DistinctValuesStayDistinct(t *testing.T) {
	a := json.RawMessage(`{"priority":0,"target":"mail1.example.com."}`)
	b := json.RawMessage(`{"priority":10,"target":"mail1.example.com."}`)
	if canonicalJSON(a) == canonicalJSON(b) {
		t.Error("different priorities must not canonicalise equal")
	}
}

// Malformed input must still match another copy of itself, so it is not
// treated as unique and appended repeatedly.
func TestCanonicalJSON_MalformedIsStable(t *testing.T) {
	a := json.RawMessage(`{not json`)
	b := json.RawMessage(`  {not json  `)
	if canonicalJSON(a) != canonicalJSON(b) {
		t.Errorf("malformed data should compare stably: %q vs %q", canonicalJSON(a), canonicalJSON(b))
	}
}

func TestCanonicalJSON_Empty(t *testing.T) {
	if canonicalJSON(nil) != "" {
		t.Error("nil data should canonicalise to empty string")
	}
}
