package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"fuzzpot/capture"
	"fuzzpot/config"
	"fuzzpot/logger"
	"fuzzpot/portscan"
)

// Accept-failure handling constants: initial and capped backoff between
// retries, and how many consecutive permanent errors trigger a listener rebind.
const (
	acceptBackoffInitial  = 100 * time.Millisecond
	acceptBackoffMax      = 10 * time.Second
	acceptRebindThreshold = 5
)

var (
	version    = "1.1.0"
	slogLogger *slog.Logger // structured logger for operational events
)

// logSchemaVersion is the JSONL contract version emitted in every
// LogEntry's `v` field (B1-8). v1 = the original field set plus `v`
// itself; consumers treat a missing `v` as pre-versioning v1.
const logSchemaVersion = 1

// LogEntry is a typed struct for JSON log serialization.
// Using json.Marshal on a struct ensures proper escaping of all special
// characters, preventing JSON log injection vulnerabilities.
//
// Schema version (B1-8): `v` identifies the JSONL contract version. v1
// adds the field itself on top of the original schema; consumers must
// treat a missing `v` as the pre-versioning format (field-compatible
// with v1). The contract is validated in both fuzzpot and fuzz-sec-intel
// (contract/contract_test.go ↔ tests/test_contract.py).
type LogEntry struct {
	V             int    `json:"v"`
	Timestamp     string `json:"ts"`
	SourceIP      string `json:"src_ip"`
	SourcePort    int    `json:"src_port"`
	DestPort      int    `json:"dst_port"`
	Proto         string `json:"proto"`
	Size          int    `json:"size"`
	Printable     string `json:"printable"` // json.Marshal handles escaping
	Hex           string `json:"hex,omitempty"`
	PayloadSHA256 string `json:"payload_sha256,omitempty"` // SHA256 hash for threat intel
}

// statsCounters holds process-lifetime counters. All fields are atomic and
// must only be read via snapshot, so no mixed mutex/atomic access can race.
type statsCounters struct {
	connections atomic.Int64
	payloads    atomic.Int64
	errors      atomic.Int64
	throttled   atomic.Int64 // connections rejected due to concurrency limit
}

func (s *statsCounters) snapshot() (connections, payloads, errs, throttled int64) {
	return s.connections.Load(), s.payloads.Load(), s.errors.Load(), s.throttled.Load()
}

func main() {
	cfgPath := flag.String("config", "config/config.yaml", "path to config file")
	dryRun := flag.Bool("dry-run", false, "show target ports and exit without listening")
	strict := flag.Bool("strict", false, "fail instead of falling back to built-in defaults when the config file is missing")
	flag.Parse()

	// A missing config silently binding ~4000 default ports is a trap:
	// warn loudly, and let --strict make it fatal.
	if !config.Exists(*cfgPath) {
		if *strict {
			fmt.Fprintf(os.Stderr, "config error: %s not found (strict mode: refusing to fall back to defaults)\n", *cfgPath)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "  [!] WARNING: config file %s not found — falling back to built-in defaults\n", *cfgPath)
		fmt.Fprintf(os.Stderr, "  [!] WARNING: defaults bind ~4000 ports (ranges 2000-5000 and 8000-9000); use --strict to make a missing config fatal\n")
	}

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

	// Setup file logger (configurable: rotate_mb, keep_files, compression, fsync)
	log, err := logger.NewWithOptions(cfg.Logging.Dir, cfg.Logging.File,
		cfg.Logging.RotateMB, cfg.Logging.KeepFiles, logger.Options{
			Compress:         cfg.Logging.Compress,
			CompressDelaySec: cfg.Logging.CompressDelaySec,
			FsyncWrites:      cfg.Logging.FsyncWrites,
		})
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
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  ██▀███   ██▀███   ▒█████   ███▄    █  ▒█████  \n")
	fmt.Fprintf(os.Stderr, " ▓██ ▒ ██▒▓██ ▒ ██▒▒██▒  ██▒ ██ ▀█   █ ▒██▒  ██▒\n")
	fmt.Fprintf(os.Stderr, " ▓██ ░▄█ ▒▓██ ░▄█ ▒▒██░  ██▒▓██  ▀█ ██▒▒██░  ██▒\n")
	fmt.Fprintf(os.Stderr, " ▒██▀▀█▄  ▒██▀▀█▄  ▒██   ██ ░▓██▒  ▐▌██▒▒██   ██░\n")
	fmt.Fprintf(os.Stderr, " ░██▓ ▒██▒░██▓ ▒██▒░ ████▓▒░░▒██░   ▓██░░ ████▓▒░\n")
	fmt.Fprintf(os.Stderr, " ░ ▒▓ ░▒▓░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░ ▒░▒░▒░ \n")
	fmt.Fprintf(os.Stderr, "   ░▒ ░ ▒░  ░▒ ░ ▒░  ░ ▒ ▒░   ░ ░░ ░ ░ ▒   ░ ▒ ▒░ \n")
	fmt.Fprintf(os.Stderr, "   ░░   ░   ░░   ░ ░ ░ ░ ▒     ░░   ░  ░   ░ ░ ▒  \n")
	fmt.Fprintf(os.Stderr, "    ░        ░           ░ ░      ░          ░  ░  \n")
	fmt.Fprintf(os.Stderr, "                  Protocol Fuzzing Honeypot          \n")
	fmt.Fprintf(os.Stderr, "                         v%s                      \n\n", version)

	// Show conflict analysis
	showConflictAnalysis(pm, ranges, cfg)

	// Get target ports
	targets := pm.TargetPorts(ranges)
	sort.Ints(targets)

	fmt.Fprintf(os.Stderr, "  [*] Ports in scope:   %d ports\n", len(targets))
	if len(targets) > 0 {
		fmt.Fprintf(os.Stderr, "  [*] Range:            %d – %d\n", targets[0], targets[len(targets)-1])
	}
	fmt.Fprintf(os.Stderr, "  [*] Log file:         %s\n", cfg.LogPath())
	fmt.Fprintf(os.Stderr, "  [*] Read timeout:     %ds\n", cfg.Capture.ReadTimeoutSec)
	fmt.Fprintf(os.Stderr, "  [*] Refresh interval: %ds\n", cfg.Refresh.IntervalSec)

	if *dryRun {
		fmt.Fprintln(os.Stderr)
		showPortSummary(targets)
		os.Exit(0)
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  [*] Starting listeners...")

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connection limiter — prevent goroutine explosion under flood.
	// Dynamically set maxConcurrent based on system file descriptor limit
	// to prevent DoS from exhausting all available FDs.
	connSem := make(chan struct{}, maxConnections())
	// Stats
	var stats statsCounters
	statsWriter := time.NewTicker(10 * time.Second)
	go func() {
		for range statsWriter.C {
			conn, pay, errs, throt := stats.snapshot()
			listening := pm.ListeningCount()
			fmt.Fprintf(os.Stderr, "  [stats] listening:%d  connections:%d  payloads:%d  errors:%d  throttled:%d\n",
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

	// Graceful shutdown on SIGINT/SIGTERM, health-check on SIGUSR1
	// (Unix only — no user-defined signals on Windows)
	sigCh := make(chan os.Signal, 1)
	notifySignals := append([]os.Signal{syscall.SIGINT, syscall.SIGTERM}, healthSignals()...)
	signal.Notify(sigCh, notifySignals...)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				fmt.Fprintln(os.Stderr, "\n  [*] Shutting down...")
				cancel()
				return
			default:
				// health-check signal (the only other registered kind)
				conn, pay, errs, throt := stats.snapshot()
				fmt.Fprintf(os.Stderr, "  [health] listening=%d connections=%d payloads=%d errors=%d throttled=%d\n",
					pm.ListeningCount(), conn, pay, errs, throt)
			}
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
				stats.errors.Add(1)
			}
		}()
		time.Sleep(time.Millisecond) // stagger goroutine starts
	}

	fmt.Fprintf(os.Stderr, "  [*] Ready. Listening on %d ports.\n\n", len(targets))

	// Periodic conflict re-check
	ticker := time.NewTicker(cfg.RefreshInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			statsWriter.Stop()
			conn, pay, errs, throt := stats.snapshot()
			fmt.Fprintf(os.Stderr, "  [*] Final: connections=%d payloads=%d errors=%d throttled=%d\n",
				conn, pay, errs, throt)
			slogLogger.Info("fuzzpot_shutdown",
				"connections_total", conn,
				"payloads_captured", pay,
				"errors_total", errs,
				"connections_throttled", throt,
			)
			fmt.Fprintln(os.Stderr, "  [*] Done.")
			return
		case <-ticker.C:
			conflicts := pm.DetectConflicts()
			if len(conflicts) > 0 {
				secLog.LogConflict(conflicts)
				fmt.Fprintf(os.Stderr, "  [!] %d port conflicts detected (claimed by system): %v\n",
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

// isTemporaryAcceptError reports whether an Accept error is transient and
// worth retrying on the same listener: timeouts, fd exhaustion, aborted or
// interrupted connections. Everything else (including a closed listener)
// counts as permanent and enters the backoff-and-rebind path.
func isTemporaryAcceptError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EINTR)
}

func listenPort(
	ctx context.Context,
	port int,
	cfg *config.Config,
	pm *portscan.PortManager,
	log *logger.Logger,
	secLog *logger.SecurityLogger,
	stats *statsCounters,
	connSem chan struct{},
) error {
	addr := ":" + strconv.Itoa(port)

	lc := net.ListenConfig{
		// The pending-connection queue length is the listen(2) backlog
		// argument, configured via ListenConfig.Backlog — there is no
		// SO_BACKLOG socket option. Backlog 0 (the default) uses the
		// platform maximum (somaxconn on Linux). The Control hook only
		// enlarges the receive buffer for payload bursts (Unix-only).
		Control: listenControl,
	}
	// bindListener listens and arranges for a parked Accept to unblock
	// when the context is cancelled (each listener gets its own watcher,
	// so rebinds never race the watcher).
	bindListener := func() (net.Listener, error) {
		l, lerr := lc.Listen(ctx, "tcp", addr)
		if lerr != nil {
			return nil, lerr
		}
		go func() {
			<-ctx.Done()
			l.Close()
		}()
		return l, nil
	}

	listener, err := bindListener()
	if err != nil {
		slogLogger.Error("listener_failed",
			"port", port,
			"error", err.Error(),
			"action", "skip_port",
		)
		return fmt.Errorf("port %d: %w", port, err)
	}
	// Closure so a mid-loop listener rebind is what gets closed at exit.
	defer func() { listener.Close() }()

	pm.SetListening(port)
	defer pm.ClearListening(port)

	// Accept-failure handling: a bare continue hot-spins at 100% CPU on
	// permanent errors. Back off exponentially, and after enough
	// consecutive permanent errors try to rebind the listener.
	var acceptBackoff time.Duration
	consecutivePermanent := 0

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

			if acceptBackoff == 0 {
				acceptBackoff = acceptBackoffInitial
			}

			if isTemporaryAcceptError(err) {
				// Transient (timeout, fd exhaustion, aborted connection):
				// pause briefly and retry on the same listener.
				time.Sleep(acceptBackoff)
			} else {
				// Permanent: pause, and periodically rebind the listener
				// in case it ended up in a broken state.
				consecutivePermanent++
				time.Sleep(acceptBackoff)
				if consecutivePermanent >= acceptRebindThreshold {
					slogLogger.Warn("listener_rebind",
						"port", port,
						"last_error", err.Error(),
					)
					listener.Close()
					pm.ClearListening(port)
					newLn, lerr := bindListener()
					if lerr != nil {
						// Keep retrying: the loop's capped backoff bounds
						// the cost; the next Accept fails immediately on
						// the closed listener and re-enters this path.
						slogLogger.Error("listener_rebind_failed",
							"port", port,
							"error", lerr.Error(),
						)
					} else {
						listener = newLn
						pm.SetListening(port)
					}
					consecutivePermanent = 0
				}
			}

			acceptBackoff *= 2
			if acceptBackoff > acceptBackoffMax {
				acceptBackoff = acceptBackoffMax
			}
			continue
		}

		// A successful accept means the listener is healthy again.
		acceptBackoff = 0
		consecutivePermanent = 0

		stats.connections.Add(1)

		// Try to acquire a slot in the semaphore (non-blocking).
		// If at capacity, close immediately to prevent goroutine explosion.
		select {
		case connSem <- struct{}{}:
			go handleConnection(conn, port, cfg, log, stats, connSem)
		default:
			// At capacity — close immediately, log throttle event
			secLog.LogThrottled(conn.RemoteAddr().String(), port)
			stats.throttled.Add(1)
			conn.Close()
		}
	}
}

func handleConnection(conn net.Conn, port int, cfg *config.Config, log *logger.Logger, stats *statsCounters, connSem chan struct{}) {
	defer conn.Close()
	defer func() { <-connSem }() // release semaphore slot
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "  [!] panic in handleConnection: %v\n", r)
			slogLogger.Error("handle_connection_panic",
				"port", port,
				"recover", r,
			)
			stats.errors.Add(1)
		}
	}()

	// Set deadline for the whole capture
	event := capture.Capture(conn, cfg.ReadTimeout(), cfg.Capture.MaxPayloadSize)

	if event.Size > 0 {
		stats.payloads.Add(1)

		// Write to log using typed struct for proper JSON escaping
		logEntry := LogEntry{
			V:             logSchemaVersion,
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
			stats.errors.Add(1)
		}

		// Console output
		fmt.Fprintf(os.Stderr, "  [hit] %s:%d → :%d  %d bytes  %q\n",
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

	fmt.Fprintln(os.Stderr, "  ── Port Conflict Analysis ──────────────────────────────")
	fmt.Fprintf(os.Stderr, "  [!] System-in-use:    %d ports  %s\n", len(excludedBySystem), truncatePortList(excludedBySystem, 8))
	fmt.Fprintf(os.Stderr, "  [!] Config-excluded:  %d ports  %s\n", len(excludedByConfig), truncatePortList(excludedByConfig, 8))
	fmt.Fprintf(os.Stderr, "  [!] Ephemeral range:  %d ports  (%d-%d)\n", len(excludedByEphemeral), ephLo, ephHi)
	fmt.Fprintf(os.Stderr, "  [✓] Available:        %d ports\n", len(available))
	fmt.Fprintln(os.Stderr, "  ─────────────────────────────────────────────────────────")
}

func showPortSummary(ports []int) {
	fmt.Fprintln(os.Stderr, "  ── Target Ports ─────────────────────────────────────────")

	// Group into ranges for readable output
	if len(ports) == 0 {
		fmt.Fprintln(os.Stderr, "  (none)")
		return
	}

	// Show first/last 10
	show := ports
	if len(show) > 20 {
		fmt.Fprintf(os.Stderr, "  First 10: %s\n", formatPortList(show[:10]))
		fmt.Fprintf(os.Stderr, "  ...       (%d more)\n", len(show)-20)
		fmt.Fprintf(os.Stderr, "  Last 10:  %s\n", formatPortList(show[len(show)-10:]))
	} else {
		fmt.Fprintf(os.Stderr, "  %s\n", formatPortList(show))
	}
	fmt.Fprintln(os.Stderr, "  ─────────────────────────────────────────────────────────")
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
