package darwin

import (
	"os"
	"syscall"
	"time"
)

// fileTimes returns a file's birth (creation) and modification times.
func fileTimes(fi os.FileInfo) (birth, mod time.Time) {
	mod = fi.ModTime()
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		birth = time.Unix(st.Birthtimespec.Sec, st.Birthtimespec.Nsec)
	}
	return birth, mod
}
