package main

import (
        "context"
        "flag"
        "fmt"
        "log/slog"
        "net"
        "os"
        "os/signal"
        "sort"
        "strconv"
        "strings"
        "sync"
        "sync/atomic"
        "syscall"
        "time"
        "unicode/utf8"

        "golang.org/x/sys/unix"

        "fuzzpot/capture"
        "fuzzpot/config"
        "fuzzpot/logger"
        "fuzzpot/portscan"
)

var (
        version    = "1.1.0"
        slogLogger *slog.Logger // structured logger for operational events
)

// LogEntry is a typed struct for JSON log serialization.
// Using json.Marshal on a struct ensures proper escaping of all special
// characters, preventing JSON log injection vulnerabilities.
type LogEntry struct {
        Timestamp     string `json:"ts"`
        SourceIP      string `json:"src_ip"`
        SourcePort    int    `json:"src_port"`
        DestPort      int    `json:"dst_port"`
        Proto         string `json:"proto"`
        Size          int    `json:"size"`
        Printable     string `json:"printable"`          // json.Marshal handles escaping
        Hex           string `json:"hex,omitempty"`
        PayloadSHA256 string `json:"payload_sha256,omitempty"` // SHA256 hash for threat intel
}

func main() {
        cfgPath := flag.String("config", "config/config.yaml", "path to config file")
        dryRun := flag.Bool("dry-run", false, "show target ports and exit without listening")
        flag.Parse()

        // Load config
        cfg, err := config.Load(*cfgPath)
        if err != nil {
                fmt.Fprintf(os.Stderr, "config error: %v\n", err)
                os.Exit(1)
        }
        if err := cfg.Validate(); err != nil {
                fmt.Fprintf(os.Stderr, "config validation: %v\n", err)
                os.Exit(1)
        }

        // Initialize structured logger for operational events
        slogLogger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
                Level:     slog.LevelInfo,
                AddSource: false,
        }))

        // Setup file logger (configurable: rotate_mb, keep_files)
        log, err := logger.New(cfg.Logging.Dir, cfg.Logging.File, cfg.Logging.RotateMB, cfg.Logging.KeepFiles)
        if err != nil {
                fmt.Fprintf(os.Stderr, "logger init: %v\n", err)
                os.Exit(1)
        }
        defer log.Close()

        // Setup security logger for incident response
        secLog, err := logger.NewSecurityLogger(cfg.Logging.Dir)
        if err != nil {
                fmt.Fprintf(os.Stderr, "security logger init: %v\n", err)
                os.Exit(1)
        }
        defer secLog.Close()

        // Log startup with structured fields
        slogLogger.Info("fuzzpot_starting",
                "version", version,
                "config_path", *cfgPath,
                "log_dir", cfg.Logging.Dir,
                "read_timeout_sec", cfg.Capture.ReadTimeoutSec,
                "refresh_interval_sec", cfg.Refresh.IntervalSec,
        )

        // Build port ranges from config
        var ranges [][2]int
        for _, r := range cfg.Ports.Ranges {
                ranges = append(ranges, [2]int{r.From, r.To})
        }

        pm := portscan.NewPortManager(cfg.Ports.Exclude)

        // Show banner
        fmt.Fprintln(os.Stderr,)
        fmt.Fprintf(os.Stderr,"  ██▀███   ██▀███   ▒█████   ███▄    █  ▒█████  \n")
        fmt.Fprintf(os.Stderr," ▓██ ▒ ██▒▓██ ▒ ██▒▒██▒  ██▒ ██ ▀█   █ ▒██▒  ██▒\n")
        fmt.Fprintf(os.Stderr," ▓██ ░▄█ ▒▓██ ░▄█ ▒▒██░  ██▒▓██  ▀█ ██▒▒██░  ██▒\n")
        fmt.Fprintf(os.Stderr," ▒██▀▀█▄  ▒██▀▀█▄  ▒██   ██ ░▓██▒  ▐▌██▒▒██   ██░\n")
        fmt.Fprintf(os.Stderr," ░██▓ ▒██▒░██▓ ▒██▒░ ████▓▒░░▒██░   ▓██░░ ████▓▒░\n")
        fmt.Fprintf(os.Stderr," ░ ▒▓ ░▒▓░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░ ▒░▒░▒░ \n")
        fmt.Fprintf(os.Stderr,"   ░▒ ░ ▒░  ░▒ ░ ▒░  ░ ▒ ▒░   ░ ░░ ░ ░ ▒   ░ ▒ ▒░ \n")
        fmt.Fprintf(os.Stderr,"   ░░   ░   ░░   ░ ░ ░ ░ ▒     ░░   ░  ░   ░ ░ ▒  \n")
        fmt.Fprintf(os.Stderr,"    ░        ░           ░ ░      ░          ░  ░  \n")
        fmt.Fprintf(os.Stderr,"                  Protocol Fuzzing Honeypot          \n")
        fmt.Fprintf(os.Stderr,"                         v%s                      \n\n", version)

        // Show conflict analysis
        showConflictAnalysis(pm, ranges, cfg)

        // Get target ports
        targets := pm.TargetPorts(ranges)
        sort.Ints(targets)

        fmt.Fprintf(os.Stderr,"  [*] Ports in scope:   %d ports\n", len(targets))
        if len(targets) > 0 {
                fmt.Fprintf(os.Stderr,"  [*] Range:            %d – %d\n", targets[0], targets[len(targets)-1])
        }
        fmt.Fprintf(os.Stderr,"  [*] Log file:         %s\n", cfg.LogPath())
        fmt.Fprintf(os.Stderr,"  [*] Read timeout:     %ds\n", cfg.Capture.ReadTimeoutSec)
        fmt.Fprintf(os.Stderr,"  [*] Refresh interval: %ds\n", cfg.Refresh.IntervalSec)

        if *dryRun {
                fmt.Fprintln(os.Stderr,)
                showPortSummary(targets)
                os.Exit(0)
        }

        fmt.Fprintln(os.Stderr,)
        fmt.Fprintln(os.Stderr,"  [*] Starting listeners...")

        // Context for graceful shutdown
        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        // Graceful shutdown on SIGINT/SIGTERM
        sigCh := make(chan os.Signal, 1)
        signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
        go func() {
                <-sigCh
                fmt.Fprintln(os.Stderr,"\n  [*] Shutting down...")
                cancel()
        }()

        // Connection limiter — prevent goroutine explosion under flood.
        // Dynamically set maxConcurrent based on system file descriptor limit
        // to prevent DoS from exhausting all available FDs.
        var maxConcurrent int
        var rlimit unix.Rlimit
        if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rlimit); err == nil && rlimit.Cur > 0 {
                maxConcurrent = int(rlimit.Cur / 2) // Use half of available FDs
                if maxConcurrent < 100 {
                        maxConcurrent = 100 // Minimum safe value
                }
                if maxConcurrent > 4096 {
                        maxConcurrent = 4096 // Cap at reasonable default
                }
        } else {
                maxConcurrent = 256 // Conservative default if we can't determine limit
        }
        connSem := make(chan struct{}, maxConcurrent)
        // Stats
        var stats struct {
                mu          sync.Mutex
                connections int64
                payloads    int64
                errors      int64
                throttled   int64 // connections rejected due to limit
        }
        statsWriter := time.NewTicker(10 * time.Second)
        go func() {
                for range statsWriter.C {
                        stats.mu.Lock()
                        conn := stats.connections
                        pay := stats.payloads
                        errs := stats.errors
                        throt := stats.throttled
                        listening := pm.ListeningCount()
                        stats.mu.Unlock()
                        fmt.Fprintf(os.Stderr,"  [stats] listening:%d  connections:%d  payloads:%d  errors:%d  throttled:%d\n",
                                listening, conn, pay, errs, throt)
                        slogLogger.Info("stats_tick",
                                "listening_ports", listening,
                                "connections_total", conn,
                                "payloads_captured", pay,
                                "errors_total", errs,
                                "connections_throttled", throt,
                        )
                }
        }()

        // Start listeners
        for _, port := range targets {
                p := port
                if ctx.Err() != nil {
                        break
                }
                go func() {
                        err := listenPort(ctx, p, cfg, pm, log, secLog, &stats, connSem)
                        if err != nil && ctx.Err() == nil {
                                stats.mu.Lock()
                                stats.errors++
                                stats.mu.Unlock()
                        }
                }()
                time.Sleep(time.Millisecond) // stagger goroutine starts
        }

        fmt.Fprintf(os.Stderr,"  [*] Ready. Listening on %d ports.\n\n", len(targets))

        // Periodic conflict re-check
        ticker := time.NewTicker(cfg.RefreshInterval())
        defer ticker.Stop()

        for {
                select {
                case <-ctx.Done():
                        statsWriter.Stop()
                        stats.mu.Lock()
                        fmt.Fprintf(os.Stderr,"  [*] Final: connections=%d payloads=%d errors=%d throttled=%d\n",
                                stats.connections, stats.payloads, stats.errors, stats.throttled)
                        slogLogger.Info("fuzzpot_shutdown",
                                "connections_total", stats.connections,
                                "payloads_captured", stats.payloads,
                                "errors_total", stats.errors,
                                "connections_throttled", stats.throttled,
                        )
                        stats.mu.Unlock()
                        fmt.Fprintln(os.Stderr,"  [*] Done.")
                        return
                case <-ticker.C:
                        conflicts := pm.DetectConflicts()
                        if len(conflicts) > 0 {
                                secLog.LogConflict(conflicts)
                                fmt.Fprintf(os.Stderr,"  [!] %d port conflicts detected (claimed by system): %v\n",
                                        len(conflicts), conflicts)
                                slogLogger.Warn("port_conflicts_detected",
                                        "conflict_count", len(conflicts),
                                        "conflict_ports", conflicts,
                                )
                                // Note: closed listeners auto-recover on next restart.
                                // For runtime recovery, we'd need a listener registry — 
                                // kept simple here since conflicts are rare.
                        }
                }
        }
}

func listenPort(
        ctx context.Context,
        port int,
        cfg *config.Config,
        pm *portscan.PortManager,
        log *logger.Logger,
        secLog *logger.SecurityLogger,
        stats *struct {
                mu          sync.Mutex
                connections int64
                payloads    int64
                errors      int64
                throttled   int64
        },
        connSem chan struct{},
) error {
        addr := ":" + strconv.Itoa(port)

        lc := net.ListenConfig{
                // Set backlog (queue length for pending connections) to handle SYN floods
                // Note: SO_BACKLOG is not available on Linux; backlog is handled by ListenBacklog
                Control: func(network, address string, c syscall.RawConn) error {
                        return c.Control(func(fd uintptr) {
                                // Increase receive buffer to handle SYN floods
                                unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 256*1024)
                        })
                },
        }
        listener, err := lc.Listen(ctx, "tcp", addr)
        if err != nil {
                slogLogger.Error("listener_failed",
                        "port", port,
                        "error", err.Error(),
                        "action", "skip_port",
                )
                return fmt.Errorf("port %d: %w", port, err)
        }
        defer listener.Close()

        pm.SetListening(port)
        defer pm.ClearListening(port)

        for {
                select {
                case <-ctx.Done():
                        return nil
                default:
                }

                conn, err := listener.Accept()
                if err != nil {
                        if ctx.Err() != nil {
                                return nil // shutdown
                        }
                        continue
                }

                atomic.AddInt64(&stats.connections, 1)

                // Try to acquire a slot in the semaphore (non-blocking).
                // If at capacity, close immediately to prevent goroutine explosion.
                select {
                case connSem <- struct{}{}:
                        go handleConnection(conn, port, cfg, log, stats, connSem)
                default:
                        // At capacity — close immediately, log throttle event
                        secLog.LogThrottled(conn.RemoteAddr().String(), port)
                        atomic.AddInt64(&stats.throttled, 1)
                        conn.Close()
                }
        }
}

func handleConnection(conn net.Conn, port int, cfg *config.Config, log *logger.Logger, stats *struct {
        mu          sync.Mutex
        connections int64
        payloads    int64
        errors      int64
        throttled   int64
}, connSem chan struct{}) {
        defer conn.Close()
        defer func() { <-connSem }() // release semaphore slot

        // Set deadline for the whole capture
        event := capture.Capture(conn, cfg.ReadTimeout(), cfg.Capture.MaxPayloadSize)

        if event.Size > 0 {
                stats.mu.Lock()
                stats.payloads++
                stats.mu.Unlock()

                // Write to log using typed struct for proper JSON escaping
                logEntry := LogEntry{
                        Timestamp:     event.Timestamp.UTC().Format(time.RFC3339),
                        SourceIP:      event.SourceIP,
                        SourcePort:    event.SourcePort,
                        DestPort:      port,
                        Proto:         event.Proto,
                        Size:          event.Size,
                        Printable:     event.Printable, // json.Marshal will escape correctly
                        PayloadSHA256: event.PayloadSHA256,
                }

                // Hex payload is large (~2x raw size); omit it when configured
                // to reduce log volume. SHA256 is sufficient for deduplication.
                if cfg.Capture.LogHexPayload {
                        logEntry.Hex = event.Hex
                }

                if err := log.WriteEventTyped(logEntry); err != nil {
                        fmt.Fprintf(os.Stderr, "  [!] log write error: %v\n", err)
                        slogLogger.Error("log_write_failed",
                                "error", err.Error(),
                                "src_ip", event.SourceIP,
                                "dst_port", port,
                        )
                        stats.mu.Lock()
                        stats.errors++
                        stats.mu.Unlock()
                }

                // Console output
                fmt.Fprintf(os.Stderr,"  [hit] %s:%d → :%d  %d bytes  %q\n",
                        event.SourceIP, event.SourcePort, port,
                        event.Size, truncate(event.Printable, 80))
        }
}

func showConflictAnalysis(pm *portscan.PortManager, ranges [][2]int, cfg *config.Config) {
        used := portscan.GetUsedPorts()
        ephLo, ephHi, _ := portscan.EphemeralRange()

        var excludedBySystem, excludedByConfig, excludedByEphemeral, available []int

        for _, r := range ranges {
                for p := r[0]; p <= r[1]; p++ {
                        switch {
                        case used[p]:
                                excludedBySystem = append(excludedBySystem, p)
                        case contains(cfg.Ports.Exclude, p):
                                excludedByConfig = append(excludedByConfig, p)
                        case portscan.IsEphemeral(p, ephLo, ephHi):
                                excludedByEphemeral = append(excludedByEphemeral, p)
                        default:
                                available = append(available, p)
                        }
                }
        }

        fmt.Fprintln(os.Stderr,"  ── Port Conflict Analysis ──────────────────────────────")
        fmt.Fprintf(os.Stderr,"  [!] System-in-use:    %d ports  %s\n", len(excludedBySystem), truncatePortList(excludedBySystem, 8))
        fmt.Fprintf(os.Stderr,"  [!] Config-excluded:  %d ports  %s\n", len(excludedByConfig), truncatePortList(excludedByConfig, 8))
        fmt.Fprintf(os.Stderr,"  [!] Ephemeral range:  %d ports  (%d-%d)\n", len(excludedByEphemeral), ephLo, ephHi)
        fmt.Fprintf(os.Stderr,"  [✓] Available:        %d ports\n", len(available))
        fmt.Fprintln(os.Stderr,"  ─────────────────────────────────────────────────────────")
}

func showPortSummary(ports []int) {
        fmt.Fprintln(os.Stderr,"  ── Target Ports ─────────────────────────────────────────")

        // Group into ranges for readable output
        if len(ports) == 0 {
                fmt.Fprintln(os.Stderr,"  (none)")
                return
        }

        // Show first/last 10
        show := ports
        if len(show) > 20 {
                fmt.Fprintf(os.Stderr,"  First 10: %s\n", formatPortList(show[:10]))
                fmt.Fprintf(os.Stderr,"  ...       (%d more)\n", len(show)-20)
                fmt.Fprintf(os.Stderr,"  Last 10:  %s\n", formatPortList(show[len(show)-10:]))
        } else {
                fmt.Fprintf(os.Stderr,"  %s\n", formatPortList(show))
        }
        fmt.Fprintln(os.Stderr,"  ─────────────────────────────────────────────────────────")
}

func contains(slice []int, val int) bool {
        for _, v := range slice {
                if v == val {
                        return true
                }
        }
        return false
}

func truncate(s string, maxRunes int) string {
        if utf8.RuneCountInString(s) <= maxRunes {
                return s
        }
        runes := []rune(s)
        return string(runes[:maxRunes]) + "..."
}

func formatPortList(ports []int) string {
        strs := make([]string, len(ports))
        for i, p := range ports {
                strs[i] = strconv.Itoa(p)
        }
        return strings.Join(strs, ", ")
}

func truncatePortList(ports []int, max int) string {
        if len(ports) == 0 {
                return "(none)"
        }
        if len(ports) <= max {
                return "(" + formatPortList(ports) + ")"
        }
        return "(" + formatPortList(ports[:max]) + fmt.Sprintf(", +%d more)", len(ports)-max) + ")"
}
