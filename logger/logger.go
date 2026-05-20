package logger

import (
        "encoding/json"
        "fmt"
        "io"
        "os"
        "path/filepath"
        "sort"
        "sync"
        "time"
)

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
}

// New creates a Logger, creating the log directory if needed.
// rotSizeMB: rotate individual log file after this many MB.
// maxFiles: keep at most this many rotated log files (0 = unlimited).
func New(dir, filename string, rotSizeMB int, maxFiles ...int) (*Logger, error) {
        if err := os.MkdirAll(dir, 0755); err != nil {
                return nil, fmt.Errorf("create log dir %s: %w", dir, err)
        }

        path := dir + "/" + filename
        f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
        if err != nil {
                return nil, fmt.Errorf("open log file %s: %w", path, err)
        }

        info, _ := f.Stat()

        mf := 10 // default: keep 10 rotated files (~500MB at 50MB each)
        if len(maxFiles) > 0 && maxFiles[0] > 0 {
                mf = maxFiles[0]
        }

        return &Logger{
                file:     f,
                logPath:  path,
                logDir:   dir,
                rotSize:  int64(rotSizeMB) * 1024 * 1024,
                maxFiles: mf,
                written:  info.Size(),
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
        return err
}

// rotate renames the current log and opens a fresh one.
// Uses copy-then-truncate for cross-device atomicity.
func (l *Logger) rotate() error {
        ts := time.Now().Format("20060102-150405")
        oldPath := fmt.Sprintf("%s.%s", l.logPath, ts)

        l.file.Close()

        // Cross-device safe rotation: copy then truncate
        if err := copyThenTruncate(l.logPath, oldPath); err != nil {
                // If copy fails, try simple rename as fallback
                os.Rename(l.logPath, oldPath)
        }

        f, err := os.OpenFile(l.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
        if err != nil {
                return fmt.Errorf("reopen log after rotate: %w", err)
        }
        l.file = f
        l.written = 0

        // Prune old rotated files if we have a cap
        if l.maxFiles > 0 {
                l.pruneOldLogs()
        }
        return nil
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

// pruneOldLogs removes the oldest rotated log files when maxFiles is exceeded.
func (l *Logger) pruneOldLogs() {
        pattern := l.logPath + ".*"
        matches, err := filepath.Glob(pattern)
        if err != nil {
                return
        }
        if len(matches) <= l.maxFiles {
                return
        }

        // Sort by modification time (oldest first)
        sort.Slice(matches, func(i, j int) bool {
                fi, _ := os.Stat(matches[i])
                fj, _ := os.Stat(matches[j])
                if fi == nil || fj == nil {
                        return false
                }
                return fi.ModTime().Before(fj.ModTime())
        })

        // Remove oldest files to get back under the cap
        toRemove := len(matches) - l.maxFiles
        for i := 0; i < toRemove; i++ {
                os.Remove(matches[i])
        }
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
