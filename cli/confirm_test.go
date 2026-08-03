package cli

import "testing"

func TestConfirmWrite(t *testing.T) {
	tests := []struct {
		name    string
		count   int
		options SafetyOptions
		want    bool
	}{
		{name: "dry run never proceeds", count: 1, options: SafetyOptions{DryRun: true}, want: false},
		{name: "dry run beats assume-yes", count: 5, options: SafetyOptions{DryRun: true, AssumeYes: true}, want: false},
		{name: "single object needs no prompt", count: 1, options: SafetyOptions{}, want: true},
		{name: "zero objects proceeds without prompt", count: 0, options: SafetyOptions{}, want: true},
		{name: "assume-yes proceeds for many", count: 42, options: SafetyOptions{AssumeYes: true}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConfirmWrite("do things to", tt.count, tt.options); got != tt.want {
				t.Errorf("ConfirmWrite(count=%d, %+v) = %v, want %v", tt.count, tt.options, got, tt.want)
			}
		})
	}
}
