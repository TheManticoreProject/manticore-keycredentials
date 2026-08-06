package certificate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// maxOutputDirAttempts bounds the search for a free output directory name. It only
// has to cover runs colliding on the same one-second timestamp, so a small number is
// plenty and keeps a pathological loop from spinning.
const maxOutputDirAttempts = 1000

// OutputDirPerms is the mode of a directory holding exported key material.
const OutputDirPerms = 0o700

// ReserveOutputDir creates a directory for one run's exported files and returns its
// path.
//
// Callers name the directory after a timestamp with one-second resolution, and derive
// the filenames inside it from the subject or account name. Two runs starting in the
// same second would therefore write the same paths, and the second would overwrite the
// first run's private key — silently, and for enroll after the matching credential has
// already been written to the directory.
//
// The directory is reserved with os.Mkdir rather than os.MkdirAll: it fails when the
// directory already exists, and does so atomically, so a losing racer is told rather
// than quietly sharing the winner's directory. On a collision the name gains a
// "_2", "_3", ... suffix until a free one is found, which makes the reservation safe
// against a concurrent process as well as a sequential re-run.
//
// Parameters:
//
//	baseDir (string): The directory the run's output directory is created in.
//	name (string): The preferred name of the output directory.
//
// Returns:
//
//	The path of the created directory, or an error if none could be reserved.
func ReserveOutputDir(baseDir, name string) (string, error) {
	if err := os.MkdirAll(baseDir, OutputDirPerms); err != nil {
		return "", fmt.Errorf("error creating output directory '%s': %s", baseDir, err)
	}

	for attempt := 1; attempt <= maxOutputDirAttempts; attempt++ {
		candidate := filepath.Join(baseDir, name)
		if attempt > 1 {
			candidate = filepath.Join(baseDir, fmt.Sprintf("%s_%d", name, attempt))
		}

		err := os.Mkdir(candidate, OutputDirPerms)
		if err == nil {
			return candidate, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("error creating output directory '%s': %s", candidate, err)
		}
	}

	return "", fmt.Errorf("no free output directory under '%s' for '%s' after %d attempts", baseDir, name, maxOutputDirAttempts)
}
