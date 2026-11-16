package config

import "testing"

// GateTrips decides exit 1 for creep scan: a stronger status or a higher
// severity than the gate trips it, a weaker one never does, and statuses
// that are not findings (discarded, not evaluated) never trip any gate.
func TestGateTrips(t *testing.T) {
	tests := []struct {
		gate, status, severity string
		want, wantErr          bool
	}{
		{"probable:critical", "probable", "critical", true, false},
		{"probable:critical", "verified", "critical", true, false},
		{"probable:critical", "probable", "high", false, false},
		{"probable:high", "probable", "critical", true, false},
		{"probable:high", "probable", "medium", false, false},
		{"verified:high", "probable", "critical", false, false},
		{"verified:high", "verified", "high", true, false},
		{"probable:info", "discarded", "critical", false, false},
		{"probable:info", "not_evaluated", "critical", false, false},
		{"none", "verified", "critical", false, false},
		{"probable:bogus", "probable", "critical", false, true},
		{"probable:critical", "probable", "bogus", false, true},
		{"none", "probable", "", false, true},
	}
	for _, tt := range tests {
		got, err := GateTrips(tt.gate, tt.status, tt.severity)
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("GateTrips(%q, %q, %q) = %v, %v; want %v, error %v", tt.gate, tt.status, tt.severity, got, err, tt.want, tt.wantErr)
		}
	}
}
