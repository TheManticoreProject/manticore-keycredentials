package certificate

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestReserveOutputDirCreatesTheDirectory(t *testing.T) {
	base := t.TempDir()

	dir, err := ReserveOutputDir(filepath.Join(base, "keys"), "2026-08-06_08-54-44")
	if err != nil {
		t.Fatalf("ReserveOutputDir() error = %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("os.Stat(%s) error = %v", dir, err)
	}
	if !info.IsDir() {
		t.Errorf("%s is not a directory", dir)
	}
	if want := filepath.Join(base, "keys", "2026-08-06_08-54-44"); dir != want {
		t.Errorf("dir = %s, want %s", dir, want)
	}
}

// Two runs starting in the same second ask for the same name. They must not be handed
// the same directory, or the second overwrites the first one's private key.
func TestReserveOutputDirDoesNotReuseADirectory(t *testing.T) {
	base := t.TempDir()
	const name = "2026-08-06_08-54-44"

	first, err := ReserveOutputDir(base, name)
	if err != nil {
		t.Fatalf("ReserveOutputDir() error = %v", err)
	}
	second, err := ReserveOutputDir(base, name)
	if err != nil {
		t.Fatalf("ReserveOutputDir() error = %v", err)
	}
	third, err := ReserveOutputDir(base, name)
	if err != nil {
		t.Fatalf("ReserveOutputDir() error = %v", err)
	}

	if first == second || second == third || first == third {
		t.Fatalf("reserved the same directory twice: %s, %s, %s", first, second, third)
	}
	if want := filepath.Join(base, name); first != want {
		t.Errorf("first = %s, want %s", first, want)
	}
	if want := filepath.Join(base, name+"_2"); second != want {
		t.Errorf("second = %s, want %s", second, want)
	}
	if want := filepath.Join(base, name+"_3"); third != want {
		t.Errorf("third = %s, want %s", third, want)
	}
}

// A pre-existing directory that the tool did not create is stepped over rather than
// written into.
func TestReserveOutputDirSkipsAnExistingDirectory(t *testing.T) {
	base := t.TempDir()
	const name = "2026-08-06_08-54-44"

	if err := os.MkdirAll(filepath.Join(base, name), OutputDirPerms); err != nil {
		t.Fatalf("os.MkdirAll() error = %v", err)
	}

	dir, err := ReserveOutputDir(base, name)
	if err != nil {
		t.Fatalf("ReserveOutputDir() error = %v", err)
	}
	if want := filepath.Join(base, name+"_2"); dir != want {
		t.Errorf("dir = %s, want %s", dir, want)
	}
}

// The reservation has to hold against concurrency too, since the collision this guards
// against is exactly two runs racing inside one second.
func TestReserveOutputDirIsSafeUnderConcurrency(t *testing.T) {
	base := t.TempDir()
	const name = "2026-08-06_08-54-44"
	const goroutines = 16

	var wg sync.WaitGroup
	var mu sync.Mutex
	dirs := map[string]bool{}
	errs := []error{}

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dir, err := ReserveOutputDir(base, name)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			dirs[dir] = true
		}()
	}
	wg.Wait()

	for _, err := range errs {
		t.Errorf("ReserveOutputDir() error = %v", err)
	}
	if len(dirs) != goroutines {
		t.Errorf("got %d distinct directories for %d concurrent reservations, want %d", len(dirs), goroutines, goroutines)
	}
}
