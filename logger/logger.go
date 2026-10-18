package logger

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Options tunes rotation behavior (A1-7). The zero value keeps the
// classic behavior: plain-text rotated files, no per-write fsync.
type Options struct {
	// Compress gzips rotated files after CompressDelaySec. The delay
	// gives log tailers (fuzz-sec-intel) a window to drain the rotated
	// file while it is still plain text.
	Compress bool
	// CompressDelaySec delays gzip compression of rotated files.
	CompressDelaySec int
	// FsyncWrites fsyncs the log file after every event write. Durable
	// against power loss, but slow — leave off unless required.
	FsyncWrites bool
}

// Logger handles writing captured events to disk with size-based rotation
// and a cap on total disk usage (old logs are pruned).
type Logger struct {
	mu       sync.Mutex
	file     *os.File
	logPath  string
	logDir   string
	rotSize  int64 // rotate after this many bytes per file
	maxFiles int   // keep at most this many rotated files
	written  int64
	opts     Options
}

// New creates a Logger, creating the log directory if needed.
// rotSizeMB: rotate individual log file after this many MB.
// maxFiles: keep at most this many rotated log files (0 = unlimited).
func New(dir, filename string, rotSizeMB int, maxFiles ...int) (*Logger, error) {
	mf := 10
	if len(maxFiles) > 0 {
		mf = maxFiles[0]
	}
	return NewWithOptions(dir, filename, rotSizeMB, mf, Options{})
}

// NewWithOptions creates a Logger with rotation tuning (see Options).
func NewWithOptions(dir, filename string, rotSizeMB int, maxFiles int, opts Options) (*Logger, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create log dir %s: %w", dir, err)
	}

	path := filepath.Join(dir, filename)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open log file %s: %w", path, err)
	}

	info, _ := f.Stat()

	return &Logger{
		file:     f,
		logPath:  path,
		logDir:   dir,
		rotSize:  int64(rotSizeMB) * 1024 * 1024,
		maxFiles: maxFiles,
		written:  info.Size(),
		opts:     opts,
	}, nil
}

// WriteEvent appends a JSON-line event to the log file.
func (l *Logger) WriteEvent(event map[string]interface{}) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.rotSize > 0 && l.written >= l.rotSize {
		if err := l.rotate(); err != nil {
			return err
		}
	}

	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	n, err := l.file.Write(line)
	l.written += int64(n)
	if err == nil && l.opts.FsyncWrites {
		err = l.file.Sync()
	}
	return err
}

// WriteEventTyped appends a JSON-line event to the log file using a typed struct.
// This is preferred over WriteEvent as json.Marshal on structs guarantees proper
// escaping of all special characters, preventing JSON log injection.
func (l *Logger) WriteEventTyped(event interface{}) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.rotSize > 0 && l.written >= l.rotSize {
		if err := l.rotate(); err != nil {
			return err
		}
	}

	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	line = append(line, '\n')

	n, err := l.file.Write(line)
	l.written += int64(n)
	if err == nil && l.opts.FsyncWrites {
		err = l.file.Sync()
	}
	return err
}

// WriteRaw writes a raw string line to the log.
func (l *Logger) WriteRaw(line string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.rotSize > 0 && l.written >= l.rotSize {
		if err := l.rotate(); err != nil {
			return err
		}
	}

	n, err := l.file.WriteString(line + "\n")
	l.written += int64(n)
	if err == nil && l.opts.FsyncWrites {
		err = l.file.Sync()
	}
	return err
}

// uniqueRotatedPath returns logPath.<timestamp> that does not collide with
// an existing file. Two rotations inside the same second append -1, -2, ...
// so the earlier backup is never overwritten (A1-7).
func uniqueRotatedPath(logPath string) string {
	ts := time.Now().Format("20060102-150405")
	candidate := fmt.Sprintf("%s.%s", logPath, ts)
	for i := 1; ; i++ {
		if _, err := os.Lstat(candidate); os.IsNotExist(err) {
			return candidate
		}
		candidate = fmt.Sprintf("%s.%s-%d", logPath, ts, i)
	}
}

// rotate moves the current log aside and opens a fresh one.
//
// Rotation is rename-based (A1-7): os.Rename is atomic and O(1), so the
// write mutex is held only briefly, and the rotated file keeps its inode —
// downstream tailers (fuzz-sec-intel's parser) locate it among the
// log_path.* siblings and drain it to EOF without data loss. The
// copy-then-truncate fallback is only used when rename fails (e.g. across
// filesystems); it is slow and holds the mutex for the whole copy.
func (l *Logger) rotate() error {
	oldPath := uniqueRotatedPath(l.logPath)

	l.file.Close()

	if err := os.Rename(l.logPath, oldPath); err != nil {
		// Cross-device safe fallback: copy then truncate
		if cerr := copyThenTruncate(l.logPath, oldPath); cerr != nil {
			// Could not move the data aside; reopen and keep writing to
			// the original file rather than losing the log entirely.
			os.Rename(oldPath, l.logPath) // roll back a partial copy
			if f, rerr := os.OpenFile(l.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640); rerr == nil {
				l.file = f
			}
			return fmt.Errorf("rotate: %w (copy fallback: %v)", err, cerr)
		}
	}

	f, err := os.OpenFile(l.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("reopen log after rotate: %w", err)
	}
	l.file = f
	l.written = 0

	if l.opts.Compress {
		go l.compressRotated(oldPath)
	}

	// Prune old rotated files if we have a cap
	l.pruneOldLogs()
	return nil
}

// compressRotated gzips a rotated file after the configured delay and
// removes the plain-text original. The delay gives log tailers a window
// to drain the file while it is still plain text.
func (l *Logger) compressRotated(path string) {
	defer func() {
		// Compression must never panic the process; a failed compression
		// just leaves the plain rotated file in place (still pruned normally).
		_ = recover()
	}()
	if l.opts.CompressDelaySec > 0 {
		time.Sleep(time.Duration(l.opts.CompressDelaySec) * time.Second)
	}
	src, err := os.Open(path)
	if err != nil {
		return
	}
	defer src.Close()

	dst, err := os.Create(path + ".gz")
	if err != nil {
		return
	}
	zw := gzip.NewWriter(dst)
	if _, err := io.Copy(zw, src); err != nil {
		zw.Close()
		dst.Close()
		os.Remove(path + ".gz")
		return
	}
	if err := zw.Close(); err != nil {
		dst.Close()
		os.Remove(path + ".gz")
		return
	}
	if err := dst.Close(); err != nil {
		os.Remove(path + ".gz")
		return
	}
	// Close the source before removing it — Windows refuses to delete
	// files that are still open (the deferred Close would be too late).
	src.Close()
	os.Remove(path)
}

// copyThenTruncate copies src to dst then truncates src to zero length.
// This is atomic across filesystems unlike os.Rename.
func copyThenTruncate(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	// Truncate original instead of removing
	return os.Truncate(src, 0)
}

// rotatedNameRe matches rotated file names: log.TIMESTAMP[-N][.gz],
// where TIMESTAMP is YYYYMMDD-HHMMSS (the optional -N suffix comes from
// same-second collision avoidance).
var rotatedNameRe = regexp.MustCompile(`\.\d{8}-\d{6}(-\d+)?(\.gz)?$`)

// pruneOldLogs removes the oldest rotated log files when maxFiles is exceeded.
// Only matches files with the expected rotation timestamp suffix format.
// A maxFiles of 0 or less means unlimited retention — never prune.
func (l *Logger) pruneOldLogs() {
	if l.maxFiles <= 0 {
		return
	}
	pattern := l.logPath + ".*"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	// Only keep files that match the expected rotation timestamp format
	var validMatches []string
	for _, m := range matches {
		if rotatedNameRe.MatchString(m) {
			validMatches = append(validMatches, m)
		}
	}

	if len(validMatches) <= l.maxFiles {
		return
	}

	// Sort by modification time (oldest first)
	sort.Slice(validMatches, func(i, j int) bool {
		fi, _ := os.Stat(validMatches[i])
		fj, _ := os.Stat(validMatches[j])
		if fi == nil || fj == nil {
			return false
		}
		return fi.ModTime().Before(fj.ModTime())
	})

	// Remove oldest files to get back under the cap
	toRemove := len(validMatches) - l.maxFiles
	for i := 0; i < toRemove; i++ {
		os.Remove(validMatches[i])
	}
}

// Sync flushes the log file to stable storage.
//
// Close alone does not guarantee the last rotation window is durable, so a
// clean shutdown should Sync before Close. Safe on a logger that was never
// written to.
func (l *Logger) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	return l.file.Sync()
}

// Reopen closes the current descriptor and re-opens the log by path (G10).
//
// logrotate renames the payload file out from under the sensor; without a
// reopen, writes keep landing on the unlinked old inode where no tailer
// will ever find them. SIGHUP is the standard trigger. On failure the old
// descriptor (if still open) is kept so a later retry has a chance.
func (l *Logger) Reopen() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("reopen log %s: %w", l.logPath, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("stat reopened log %s: %w", l.logPath, err)
	}
	if l.file != nil {
		l.file.Close()
	}
	l.file = f
	l.written = info.Size()
	return nil
}

// Close flushes and closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// Path returns the current log file path.
func (l *Logger) Path() string {
	return l.logPath
}
