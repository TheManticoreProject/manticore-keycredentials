package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetFilterSingleSelectorForms(t *testing.T) {
	t.Run("distinguished name", func(t *testing.T) {
		got, err := targetFilter(TargetOptions{DistinguishedName: "CN=a,DC=b,DC=c"})
		if err != nil {
			t.Fatalf("targetFilter() error = %v", err)
		}
		if want := "(distinguishedName=CN=a,DC=b,DC=c)"; got != want {
			t.Errorf("filter = %q, want %q", got, want)
		}
	})

	t.Run("filter is passed through unchanged", func(t *testing.T) {
		got, err := targetFilter(TargetOptions{Filter: "(objectClass=computer)"})
		if err != nil {
			t.Fatalf("targetFilter() error = %v", err)
		}
		if want := "(objectClass=computer)"; got != want {
			t.Errorf("filter = %q, want %q", got, want)
		}
	})
}

func TestTargetFilterTargetsFileIsOred(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dns.txt")
	content := "# a comment\nCN=a,DC=x\n\n  CN=b,DC=x  \n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	got, err := targetFilter(TargetOptions{TargetsFile: path})
	if err != nil {
		t.Fatalf("targetFilter() error = %v", err)
	}
	want := "(|(distinguishedName=CN=a,DC=x)(distinguishedName=CN=b,DC=x))"
	if got != want {
		t.Errorf("filter = %q, want %q", got, want)
	}
}

func TestTargetFilterRequiresExactlyOneSelector(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		if _, err := targetFilter(TargetOptions{}); err == nil {
			t.Error("error = nil, want an error for no selector")
		}
	})

	t.Run("more than one", func(t *testing.T) {
		if _, err := targetFilter(TargetOptions{DistinguishedName: "CN=a", Filter: "(x=y)"}); err == nil {
			t.Error("error = nil, want an error for two selectors")
		}
	})
}

func TestTargetFilterEmptyTargetsFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte("# only a comment\n\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	if _, err := targetFilter(TargetOptions{TargetsFile: path}); err == nil {
		t.Error("error = nil, want an error for a targets file with no DN")
	}
}

func TestTargetOptionsEmpty(t *testing.T) {
	if !(TargetOptions{}).Empty() {
		t.Error("Empty() = false for zero options")
	}
	if (TargetOptions{Filter: "(x=y)"}).Empty() {
		t.Error("Empty() = true when a filter is set")
	}
}

func TestTargetFilterErrorNamesTheFlags(t *testing.T) {
	_, err := targetFilter(TargetOptions{})
	if err == nil || !strings.Contains(err.Error(), "--filter") {
		t.Errorf("error = %v, want it to name the selectors", err)
	}
}
