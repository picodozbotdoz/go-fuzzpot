package logger

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
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
	mu        sync.Mutex
	file      *os.File
	logPath   string
	logDir    string
	rotSize   int64 // rotate after this many bytes per file
	maxFiles  int   // keep at most this many rotated files
	written   int64
	rotations atomic.Int64
	opts      Options
}

// ErrLoggerClosed is returned by write paths once a failed rotation (or an
// explicit close) has left the logger with no usable descriptor. Reporting
// this distinctly beats letting every write fail with "file already closed"
// from deep inside os.File (G8).
var ErrLoggerClosed = errors.New("logger closed after failed rotation")

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

	// G8: an ignored Stat error nil-derefs on the Size call below.
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat log file %s: %w", path, err)
	}

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

// writeLine appends one complete line, recovering from torn writes (G8, R2-G1).
//
// os.File.Write returns a non-nil error whenever n != len(line), so the
// realistic torn case is n > 0 with an error (ENOSPC/EIO mid-line). The
// pre-write offset is l.written (every write goes through here, in O_APPEND
// mode), so recovery truncates the partial tail back to a line boundary —
// otherwise the next append concatenates onto the half-line and corrupts
// two records.
func (l *Logger) writeLine(line []byte) error {
	if l.file == nil {
		return ErrLoggerClosed
	}
	n, err := l.file.Write(line)
	l.written += int64(n)
	if err == nil && n == len(line) {
		if l.opts.FsyncWrites {
			return l.file.Sync()
		}
		return nil
	}
	if n > 0 {
		if terr := l.file.Truncate(l.written - int64(n)); terr != nil {
			return fmt.Errorf("torn write recovery (wrote %d/%d): %w", n, len(line), terr)
		}
		l.written -= int64(n)
	}
	return err
}

// WriteEventTyped appends a JSON-line event to the log file using a typed struct.
// This is preferred over map-based writes as json.Marshal on structs guarantees
// proper escaping of all special characters, preventing JSON log injection.
func (l *Logger) WriteEventTyped(event interface{}) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// R2-G2: a failed rotation must not drop the event. If the rollback
	// kept a usable descriptor the write proceeds (over-size until the
	// next event retries rotation); if rotation left the logger closed,
	// writeLine reports ErrLoggerClosed.
	l.maybeRotate()

	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	line = append(line, '\n')

	return l.writeLine(line)
}

// WriteRaw writes a raw string line to the log.
func (l *Logger) WriteRaw(line string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.maybeRotate() // R2-G2: see WriteEventTyped

	return l.writeLine([]byte(line + "\n"))
}

// maybeRotate rotates when the size threshold is reached. Failures are
// swallowed on purpose: the write paths must still attempt their write —
// dropping the event because rotation failed is the one unrecoverable
// outcome (R2-G2). The closed-logger case surfaces via writeLine.
func (l *Logger) maybeRotate() {
	if l.rotSize > 0 && l.written >= l.rotSize {
		_ = l.rotate()
	}
}

// Rotations reports how many rotations this logger has performed (G12).
func (l *Logger) Rotations() int64 {
	return l.rotations.Load()
}

// BytesWritten reports bytes in the current log file (G12).
func (l *Logger) BytesWritten() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.written
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
				return fmt.Errorf("rotate: %w (copy fallback: %v)", err, cerr)
			}
			// R2-G2: both the rename and the rollback reopen failed while
			// the descriptor is already closed. Park in the closed state
			// (writes return ErrLoggerClosed) instead of keeping a dead
			// *os.File that fails with "file already closed" forever.
			l.file = nil
			return fmt.Errorf("rotate: %w (copy fallback: %v, rollback reopen failed)", err, cerr)
		}
	}

	f, err := os.OpenFile(l.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		// G8: the old descriptor is closed and the data has been renamed
		// aside — there is nothing left to write to. Park the logger in
		// the closed state (writes return ErrLoggerClosed) instead of
		// keeping a dead *os.File that fails with "file already closed"
		// on every event.
		l.file = nil
		return fmt.Errorf("reopen log after rotate: %w", err)
	}
	l.file = f
	l.written = 0
	l.rotations.Add(1)

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

	// Sort by modification time (oldest first). R2-G8: files can vanish
	// between Glob and Stat (async compression removes plain originals),
	// and a comparator returning false regardless of order violates the
	// sort contract — the "oldest" head could then contain a newer file
	// and retention data beyond policy is lost. Stat once up front and
	// drop the misses instead.
	type rotFile struct {
		path    string
		modTime time.Time
	}
	statted := make([]rotFile, 0, len(validMatches))
	for _, m := range validMatches {
		if fi, err := os.Stat(m); err == nil {
			statted = append(statted, rotFile{m, fi.ModTime()})
		}
	}
	sort.Slice(statted, func(i, j int) bool {
		return statted[i].modTime.Before(statted[j].modTime)
	})

	// Remove oldest files to get back under the cap
	if len(statted) <= l.maxFiles {
		return
	}
	for _, f := range statted[:len(statted)-l.maxFiles] {
		os.Remove(f.path)
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
	if l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil
	return f.Close()
}

// Path returns the current log file path.
func (l *Logger) Path() string {
	return l.logPath
}
