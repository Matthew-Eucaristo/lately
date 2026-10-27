//go:build !darwin

package darwin

import (
	"os"
	"time"
)

// fileTimes has no birth time outside macOS; callers fall back to mtime.
func fileTimes(fi os.FileInfo) (birth, mod time.Time) { return time.Time{}, fi.ModTime() }
