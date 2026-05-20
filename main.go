package main

import (
        "context"
        "flag"
        "fmt"
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

var version = "1.1.0"

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
        Hex           string `json:"hex"`
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

        // Setup logger (50MB per file, keep 10 rotated files = max ~500MB on disk)
        log, err := logger.New(cfg.Logging.Dir, cfg.Logging.File, 50, 10)
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

        // Build port ranges from config
        var ranges [][2]int
        for _, r := range cfg.Ports.Ranges {
                ranges = append(ranges, [2]int{r.From, r.To})
        }

        pm := portscan.NewPortManager(cfg.Ports.Exclude)

        // Show banner
        fmt.Println()
        fmt.Printf("  ██▀███   ██▀███   ▒█████   ███▄    █  ▒█████  \n")
        fmt.Printf(" ▓██ ▒ ██▒▓██ ▒ ██▒▒██▒  ██▒ ██ ▀█   █ ▒██▒  ██▒\n")
        fmt.Printf(" ▓██ ░▄█ ▒▓██ ░▄█ ▒▒██░  ██▒▓██  ▀█ ██▒▒██░  ██▒\n")
        fmt.Printf(" ▒██▀▀█▄  ▒██▀▀█▄  ▒██   ██ ░▓██▒  ▐▌██▒▒██   ██░\n")
        fmt.Printf(" ░██▓ ▒██▒░██▓ ▒██▒░ ████▓▒░░▒██░   ▓██░░ ████▓▒░\n")
        fmt.Printf(" ░ ▒▓ ░▒▓░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░ ▒░▒░▒░ \n")
        fmt.Printf("   ░▒ ░ ▒░  ░▒ ░ ▒░  ░ ▒ ▒░   ░ ░░ ░ ░ ▒   ░ ▒ ▒░ \n")
        fmt.Printf("   ░░   ░   ░░   ░ ░ ░ ░ ▒     ░░   ░  ░   ░ ░ ▒  \n")
        fmt.Printf("    ░        ░           ░ ░      ░          ░  ░  \n")
        fmt.Printf("                  Protocol Fuzzing Honeypot          \n")
        fmt.Printf("                         v%s                      \n\n", version)

        // Show conflict analysis
        showConflictAnalysis(pm, ranges, cfg)

        // Get target ports
        targets := pm.TargetPorts(ranges)
        sort.Ints(targets)

        fmt.Printf("  [*] Ports in scope:   %d ports\n", len(targets))
        if len(targets) > 0 {
                fmt.Printf("  [*] Range:            %d – %d\n", targets[0], targets[len(targets)-1])
        }
        fmt.Printf("  [*] Log file:         %s\n", cfg.LogPath())
        fmt.Printf("  [*] Read timeout:     %ds\n", cfg.Capture.ReadTimeoutSec)
        fmt.Printf("  [*] Refresh interval: %ds\n", cfg.Refresh.IntervalSec)

        if *dryRun {
                fmt.Println()
                showPortSummary(targets)
                os.Exit(0)
        }

        fmt.Println()
        fmt.Println("  [*] Starting listeners...")

        // Context for graceful shutdown
        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        // Graceful shutdown on SIGINT/SIGTERM
        sigCh := make(chan os.Signal, 1)
        signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
        go func() {
                <-sigCh
                fmt.Println("\n  [*] Shutting down...")
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
                        fmt.Printf("  [stats] listening:%d  connections:%d  payloads:%d  errors:%d  throttled:%d\n",
                                listening, conn, pay, errs, throt)
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

        fmt.Printf("  [*] Ready. Listening on %d ports.\n\n", len(targets))

        // Periodic conflict re-check
        ticker := time.NewTicker(cfg.RefreshInterval())
        defer ticker.Stop()

        for {
                select {
                case <-ctx.Done():
                        statsWriter.Stop()
                        stats.mu.Lock()
                        fmt.Printf("  [*] Final: connections=%d payloads=%d errors=%d throttled=%d\n",
                                stats.connections, stats.payloads, stats.errors, stats.throttled)
                        stats.mu.Unlock()
                        fmt.Println("  [*] Done.")
                        return
                case <-ticker.C:
                        conflicts := pm.DetectConflicts()
                        if len(conflicts) > 0 {
                                secLog.LogConflict(conflicts)
                                fmt.Printf("  [!] %d port conflicts detected (claimed by system): %v\n",
                                        len(conflicts), conflicts)
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
        listener, err := net.Listen("tcp", addr)
        if err != nil {
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
                        Hex:           event.Hex,
                        PayloadSHA256: event.PayloadSHA256,
                }

                if err := log.WriteEventTyped(logEntry); err != nil {
                        fmt.Fprintf(os.Stderr, "  [!] log write error: %v\n", err)
                        stats.mu.Lock()
                        stats.errors++
                        stats.mu.Unlock()
                }

                // Console output
                fmt.Printf("  [hit] %s:%d → :%d  %d bytes  %q\n",
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

        fmt.Println("  ── Port Conflict Analysis ──────────────────────────────")
        fmt.Printf("  [!] System-in-use:    %d ports  %s\n", len(excludedBySystem), truncatePortList(excludedBySystem, 8))
        fmt.Printf("  [!] Config-excluded:  %d ports  %s\n", len(excludedByConfig), truncatePortList(excludedByConfig, 8))
        fmt.Printf("  [!] Ephemeral range:  %d ports  (%d-%d)\n", len(excludedByEphemeral), ephLo, ephHi)
        fmt.Printf("  [✓] Available:        %d ports\n", len(available))
        fmt.Println("  ─────────────────────────────────────────────────────────")
}

func showPortSummary(ports []int) {
        fmt.Println("  ── Target Ports ─────────────────────────────────────────")

        // Group into ranges for readable output
        if len(ports) == 0 {
                fmt.Println("  (none)")
                return
        }

        // Show first/last 10
        show := ports
        if len(show) > 20 {
                fmt.Printf("  First 10: %s\n", formatPortList(show[:10]))
                fmt.Printf("  ...       (%d more)\n", len(show)-20)
                fmt.Printf("  Last 10:  %s\n", formatPortList(show[len(show)-10:]))
        } else {
                fmt.Printf("  %s\n", formatPortList(show))
        }
        fmt.Println("  ─────────────────────────────────────────────────────────")
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
