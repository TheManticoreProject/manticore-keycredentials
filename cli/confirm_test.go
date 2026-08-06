package cli

import "testing"

// goopts ignores an unknown argument instead of refusing it, so a caller still
// passing the removed --dry-run would otherwise perform the write it meant to
// preview. The write modes have to refuse it.
func TestCheckRemovedSafetyFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{name: "no removed flag", args: []string{"mkc", "enroll", "-D", "CN=x", "--export-pfx"}, wantErr: false},
		{name: "bare --dry-run", args: []string{"mkc", "enroll", "-D", "CN=x", "--dry-run"}, wantErr: true},
		{name: "--dry-run=true form", args: []string{"mkc", "remove", "--dry-run=true"}, wantErr: true},
		{name: "--dry-run as the mode selector is not an argument", args: []string{"mkc", "--dry-run"}, wantErr: false},
		{name: "no arguments at all", args: []string{"mkc"}, wantErr: false},
		{name: "empty argument list", args: []string{}, wantErr: false},
		{name: "a value that merely looks like it", args: []string{"mkc", "attach", "-D", "CN=--dry-run"}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckRemovedSafetyFlags(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckRemovedSafetyFlags(%q) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
		})
	}
}

func TestConfirmWrite(t *testing.T) {
	tests := []struct {
		name    string
		count   int
		options SafetyOptions
		want    bool
	}{
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
