package api

import (
	"encoding/json"
	"testing"
)

func TestMXRecordParsing(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantPri int
		wantTgt string
	}{
		{
			name:    "new format priority/target",
			input:   `{"priority":0,"target":"mail.example.com"}`,
			wantPri: 0,
			wantTgt: "mail.example.com",
		},
		{
			name:    "old format preference/exchange",
			input:   `{"preference":10,"exchange":"mail.example.com"}`,
			wantPri: 10,
			wantTgt: "mail.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data map[string]interface{}
			if err := json.Unmarshal([]byte(tt.input), &data); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			var priority int
			var target string

			// This is the logic from handleRecordsStorage
			if v, ok := data["target"].(string); ok {
				target = v
			} else if v, ok := data["exchange"].(string); ok {
				target = v
			}
			if v, ok := data["priority"].(float64); ok {
				priority = int(v)
			} else if v, ok := data["preference"].(float64); ok {
				priority = int(v)
			}

			if priority != tt.wantPri {
				t.Errorf("priority = %d, want %d", priority, tt.wantPri)
			}
			if target != tt.wantTgt {
				t.Errorf("target = %s, want %s", target, tt.wantTgt)
			}
		})
	}
}

func TestFormatRecordDataMX(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "new format priority/target",
			data: `{"priority":0,"target":"quicktechresults-com.mail.protection.outlook.com"}`,
			want: "0 quicktechresults-com.mail.protection.outlook.com",
		},
		{
			name: "new format with non-zero priority",
			data: `{"priority":10,"target":"mail.example.com"}`,
			want: "10 mail.example.com",
		},
		{
			name: "old format preference/exchange",
			data: `{"preference":5,"exchange":"legacy-mail.example.com"}`,
			want: "5 legacy-mail.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatRecordData("MX", json.RawMessage(tt.data))
			if got != tt.want {
				t.Errorf("formatRecordData() = %q, want %q", got, tt.want)
			}
		})
	}
}
