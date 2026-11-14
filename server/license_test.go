package server

import (
	"net/http"
	"testing"
)

// The gate must let the operator log in, read status, and paste a key while
// unlicensed, block every state-changing call, and keep reads open — including
// the externally-mounted k1z workflow routes (/api/v1/*), whose POSTs are the
// bypass this gate closes.
func TestLicenseGateExempt(t *testing.T) {
	cases := []struct {
		path, method string
		exempt       bool
	}{
		{"/api/auth/login", http.MethodPost, true},    // login must work unlicensed
		{"/api/health", http.MethodGet, true},         // health probe
		{"/api/license", http.MethodGet, true},        // read status
		{"/api/license", http.MethodPost, true},       // activate a key
		{"/api/tasks", http.MethodGet, true},          // reads stay open so the UI renders
		{"/api/settings", http.MethodGet, true},       // read
		{"/api/tasks", http.MethodPost, false},        // create task — gated
		{"/api/settings", http.MethodPut, false},      // change settings — gated
		{"/api/tasks/1", http.MethodDelete, false},    // delete — gated
		{"/api/v1/runs", http.MethodPost, false},      // launch workflow via k1z — gated (the bypass)
		{"/api/v1/runs", http.MethodGet, true},        // list runs — read
		{"/api/v1/schedules", http.MethodPost, false}, // create schedule via k1z — gated
		{"/ws/logs", http.MethodGet, true},            // websocket stream — read
	}
	for _, c := range cases {
		if got := licenseGateExempt(c.path, c.method); got != c.exempt {
			t.Errorf("licenseGateExempt(%q,%q)=%v, want %v", c.path, c.method, got, c.exempt)
		}
	}
}
