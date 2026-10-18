package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
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

	// shutdownGracePeriod bounds how long shutdown waits for in-flight
	// handlers to finish writing before the log files are closed.
	shutdownGracePeriod = 10 * time.Second
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

// connectionTracker bounds the number of concurrent handlers and tracks their
// lifetime. Without the WaitGroup, shutdown returned while handlers were still
// writing to the log, so deferred Close calls raced in-flight writes and
// payloads were lost.
type connectionTracker struct {
	sem chan struct{}
	wg  sync.WaitGroup
}

func newConnectionTracker(maxConcurrent int) *connectionTracker {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &connectionTracker{sem: make(chan struct{}, maxConcurrent)}
}

// acquire reserves a handler slot without blocking. It reports false when the
// tracker is at capacity, in which case the caller must close the connection.
func (t *connectionTracker) acquire() bool {
	select {
	case t.sem <- struct{}{}:
		t.wg.Add(1)
		return true
	default:
		return false
	}
}

// release frees a slot reserved by acquire and marks the handler finished.
func (t *connectionTracker) release() {
	<-t.sem
	t.wg.Done()
}

// waitOrTimeout waits for wg to drain, reporting false if timeout expires
// first. Callers must decide what a false return means for them.
func waitOrTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// wait blocks until every in-flight handler has finished, or until timeout
// expires. It returns the number of handlers still running; a non-zero result
// means shutdown proceeded with work outstanding and should be logged.
func (t *connectionTracker) wait(timeout time.Duration) int {
	if waitOrTimeout(&t.wg, timeout) {
		return 0
	}
	return len(t.sem)
}

const (
	// hitConsoleBurst is how many "[hit]" lines may reach the console per
	// window. A human cannot read more than this, and an unbounded write per
	// payload serialises every handler on os.Stderr's lock — under a flood
	// that becomes the throughput ceiling, so an attacker could slow the
	// honeypot simply by sending more packets.
	hitConsoleBurst  = 20
	hitConsoleWindow = time.Second
)

// hitReporter rate-limits console hit output without dropping the signal
// entirely: suppressed events are counted and reported when the window rolls
// over, so an operator can still tell that traffic is arriving.
type hitReporter struct {
	mu         sync.Mutex
	out        io.Writer
	now        func() time.Time
	windowEnd  time.Time
	emitted    int
	suppressed int
}

func newHitReporter(out io.Writer) *hitReporter {
	return &hitReporter{out: out, now: time.Now}
}

// report writes one hit line if the budget allows, otherwise counts it as
// suppressed. The write happens outside the lock: the point is to bound the
// number of contended writes, not to serialise them more tightly.
func (r *hitReporter) report(srcIP string, srcPort, dstPort, size int, printable string) {
	now := r.now()

	r.mu.Lock()
	rolled := now.After(r.windowEnd)
	suppressed := 0
	if rolled {
		suppressed = r.suppressed
		r.windowEnd = now.Add(hitConsoleWindow)
		r.emitted = 0
		r.suppressed = 0
	}
	// The report that opens a window consumes budget like any other, so a
	// window emits exactly hitConsoleBurst lines, not one more.
	allow := r.emitted < hitConsoleBurst
	if allow {
		r.emitted++
	} else {
		r.suppressed++
	}
	r.mu.Unlock()

	if rolled && suppressed > 0 {
		fmt.Fprintf(r.out, "  [hit] ... %d more hit(s) suppressed in the previous %s\n",
			suppressed, hitConsoleWindow)
	}
	if !allow {
		return
	}

	fmt.Fprintf(r.out, "  [hit] %s:%d → :%d  %d bytes  %q\n",
		srcIP, srcPort, dstPort, size, truncate(printable, 80))
}

// main exists only so that realMain's deferred cleanup runs. os.Exit
// terminates the process immediately, so a defer registered after it would be
// silently skipped — which is what happened on --dry-run, where the log file
// was opened and never closed.
func main() {
	os.Exit(realMain())
}

// realMain parses flags, wires dependencies and runs the service. It returns a
// process exit code instead of calling os.Exit, so every deferred Close runs.
func realMain() int {
	cfgPath := flag.String("config", "config/config.yaml", "path to config file")
	dryRun := flag.Bool("dry-run", false, "show target ports and exit without listening")
	strict := flag.Bool("strict", false, "fail instead of falling back to built-in defaults when the config file is missing")
	flag.Parse()

	// A missing config silently binding ~4000 default ports is a trap:
	// warn loudly, and let --strict make it fatal.
	if !config.Exists(*cfgPath) {
		if *strict {
			fmt.Fprintf(os.Stderr, "config error: %s not found (strict mode: refusing to fall back to defaults)\n", *cfgPath)
			return 1
		}
		fmt.Fprintf(os.Stderr, "  [!] WARNING: config file %s not found — falling back to built-in defaults\n", *cfgPath)
		fmt.Fprintf(os.Stderr, "  [!] WARNING: defaults bind ~4000 ports (ranges 2000-5000 and 8000-9000); use --strict to make a missing config fatal\n")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config validation: %v\n", err)
		return 1
	}

	// Structured logger for operational events.
	slogLogger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: false,
	}))

	// File logger (configurable: rotate_mb, keep_files, compression, fsync).
	log, err := logger.NewWithOptions(cfg.Logging.Dir, cfg.Logging.File,
		cfg.Logging.RotateMB, cfg.Logging.KeepFiles, logger.Options{
			Compress:         cfg.Logging.Compress,
			CompressDelaySec: cfg.Logging.CompressDelaySec,
			FsyncWrites:      cfg.Logging.FsyncWrites,
		})
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger init: %v\n", err)
		return 1
	}
	defer log.Close()

	// Security logger for incident response.
	secLog, err := logger.NewSecurityLogger(cfg.Logging.Dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "security logger init: %v\n", err)
		return 1
	}
	defer secLog.Close()

	slogLogger.Info("fuzzpot_starting",
		"version", version,
		"config_path", *cfgPath,
		"log_dir", cfg.Logging.Dir,
		"read_timeout_sec", cfg.Capture.ReadTimeoutSec,
		"refresh_interval_sec", cfg.Refresh.IntervalSec,
	)

	ranges := portRanges(cfg)
	a, targets := newApp(cfg, log, secLog, ranges)

	printBanner()
	showConflictAnalysis(a.pm, ranges, cfg)

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
		return 0
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  [*] Starting listeners...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stopSignals := a.handleSignals(cancel)
	defer stopSignals()

	a.run(ctx)
	return 0
}

// app holds everything one run needs. Keeping it in a struct is what lets a
// test drive the supervision loop without parsing flags or owning process-wide
// signal state.
type app struct {
	cfg     *config.Config
	log     *logger.Logger
	secLog  *logger.SecurityLogger
	pm      *portscan.PortManager
	targets []int
	stats   statsCounters
	conns   *connectionTracker
	hits    *hitReporter
}

// newApp builds the run-time state and resolves the target port list.
func newApp(cfg *config.Config, log *logger.Logger, secLog *logger.SecurityLogger,
	ranges [][2]int) (*app, []int) {
	pm := portscan.NewPortManager(cfg.Ports.Exclude)
	targets := pm.TargetPorts(ranges)
	sort.Ints(targets)

	return &app{
		cfg:     cfg,
		log:     log,
		secLog:  secLog,
		pm:      pm,
		targets: targets,
		// Connection limiter — prevents goroutine explosion under flood.
		// Sized from the fd limit so a DoS cannot exhaust every descriptor.
		conns: newConnectionTracker(maxConnections()),
		hits:  newHitReporter(os.Stderr),
	}, targets
}

// portRanges flattens the configured port ranges into pairs.
func portRanges(cfg *config.Config) [][2]int {
	ranges := make([][2]int, 0, len(cfg.Ports.Ranges))
	for _, r := range cfg.Ports.Ranges {
		ranges = append(ranges, [2]int{r.From, r.To})
	}
	return ranges
}

// handleSignals wires SIGINT/SIGTERM to cancel and the platform health signal
// (SIGUSR1 on Unix, nothing on Windows) to an on-demand stats dump. The
// returned function detaches the watcher.
func (a *app) handleSignals(cancel context.CancelFunc) func() {
	sigCh := make(chan os.Signal, 1)
	notifySignals := append([]os.Signal{syscall.SIGINT, syscall.SIGTERM}, healthSignals()...)
	signal.Notify(sigCh, notifySignals...)

	a.watchSignals(sigCh, cancel)

	return func() {
		signal.Stop(sigCh)
		close(sigCh)
	}
}

// watchSignals translates received signals into actions until the channel is
// closed. Split out from handleSignals so the behaviour can be tested with a
// synthetic channel — process-wide signal delivery is not portable.
func (a *app) watchSignals(sigCh <-chan os.Signal, cancel context.CancelFunc) {
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				fmt.Fprintln(os.Stderr, "\n  [*] Shutting down...")
				cancel()
				return
			default:
				// health-check signal (the only other registered kind)
				conn, pay, errs, throt := a.stats.snapshot()
				fmt.Fprintf(os.Stderr, "  [health] listening=%d connections=%d payloads=%d errors=%d throttled=%d\n",
					a.pm.ListeningCount(), conn, pay, errs, throt)
			}
		}
	}()
}

// run starts the stats reporter and the listeners, then supervises them until
// ctx is cancelled, at which point it drains and returns.
func (a *app) run(ctx context.Context) {
	statsWriter := time.NewTicker(10 * time.Second)
	defer statsWriter.Stop()
	go a.reportStats(ctx, statsWriter)

	listeners := a.startListeners(ctx)

	fmt.Fprintf(os.Stderr, "  [*] Ready. Listening on %d ports.\n\n", len(a.targets))

	// Validate() already rejects interval_sec < 5 for loaded configs, but run()
	// is also reachable from tests and future embedders, and time.NewTicker
	// panics on a non-positive duration.
	refresh := a.cfg.RefreshInterval()
	if refresh <= 0 {
		refresh = 5 * time.Second
	}
	ticker := time.NewTicker(refresh)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.drain(listeners)
			return
		case <-ticker.C:
			a.checkConflicts()
		}
	}
}

// reportStats emits the periodic counters until ctx is cancelled. It selects
// on ctx because Ticker.Stop() does not close the channel, so ranging over it
// would block this goroutine forever.
func (a *app) reportStats(ctx context.Context, ticker *time.Ticker) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			conn, pay, errs, throt := a.stats.snapshot()
			listening := a.pm.ListeningCount()
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
	}
}

// startListeners launches one goroutine per target port and returns the group.
// Listeners are tracked separately from connections because a listener can
// still write a throttle event to the security log after the main loop has
// decided to shut down.
func (a *app) startListeners(ctx context.Context) *sync.WaitGroup {
	var listeners sync.WaitGroup
	for _, port := range a.targets {
		p := port
		if ctx.Err() != nil {
			break
		}
		listeners.Add(1)
		go func() {
			defer listeners.Done()
			err := listenPort(ctx, p, a.cfg, a.pm, a.log, a.secLog, &a.stats, a.conns, a.hits)
			if err != nil && ctx.Err() == nil {
				a.stats.errors.Add(1)
			}
		}()
		time.Sleep(time.Millisecond) // stagger goroutine starts
	}
	return &listeners
}

// drain waits for in-flight work before the caller closes the log files.
// Anything still running after the grace period is reported rather than waited
// on indefinitely: a hung handler must not block shutdown forever.
func (a *app) drain(listeners *sync.WaitGroup) {
	if n := a.conns.wait(shutdownGracePeriod); n > 0 {
		slogLogger.Warn("shutdown_timeout",
			"in_flight_handlers", n,
			"grace_period_sec", int(shutdownGracePeriod.Seconds()),
		)
		fmt.Fprintf(os.Stderr, "  [!] shutdown timed out with %d handler(s) still running\n", n)
	}
	if !waitOrTimeout(listeners, shutdownGracePeriod) {
		slogLogger.Warn("shutdown_timeout", "component", "listeners")
	}

	conn, pay, errs, throt := a.stats.snapshot()
	fmt.Fprintf(os.Stderr, "  [*] Final: connections=%d payloads=%d errors=%d throttled=%d\n",
		conn, pay, errs, throt)
	slogLogger.Info("fuzzpot_shutdown",
		"connections_total", conn,
		"payloads_captured", pay,
		"errors_total", errs,
		"connections_throttled", throt,
	)
	fmt.Fprintln(os.Stderr, "  [*] Done.")
}

// checkConflicts re-scans for ports claimed by the system since startup.
func (a *app) checkConflicts() {
	conflicts := a.pm.DetectConflicts()
	if len(conflicts) == 0 {
		return
	}
	a.secLog.LogConflict(conflicts)
	fmt.Fprintf(os.Stderr, "  [!] %d port conflicts detected (claimed by system): %v\n",
		len(conflicts), conflicts)
	slogLogger.Warn("port_conflicts_detected",
		"conflict_count", len(conflicts),
		"conflict_ports", conflicts,
	)
	// Note: closed listeners auto-recover on next restart. For runtime
	// recovery we would need a listener registry — kept simple because
	// conflicts are rare.
}

// printBanner writes the startup banner.
func printBanner() {
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
	conns *connectionTracker,
	hits *hitReporter,
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

		// Try to acquire a handler slot (non-blocking).
		// If at capacity, close immediately to prevent goroutine explosion.
		if conns.acquire() {
			go handleConnection(conn, port, cfg, log, stats, conns, hits)
		} else {
			// At capacity — close immediately, log throttle event
			secLog.LogThrottled(conn.RemoteAddr().String(), port)
			stats.throttled.Add(1)
			conn.Close()
		}
	}
}

func handleConnection(conn net.Conn, port int, cfg *config.Config, log *logger.Logger, stats *statsCounters, conns *connectionTracker, hits *hitReporter) {
	defer conn.Close()
	defer conns.release() // frees the slot and marks this handler finished
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

		// Console output, rate-limited: see hitReporter.
		hits.report(event.SourceIP, event.SourcePort, port,
			event.Size, event.Printable)
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
			case slices.Contains(cfg.Ports.Exclude, p):
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
	// Note: the format string must not carry its own closing paren — the
	// surrounding "(" and ")" are added here, and the original version
	// produced "(1, 2, 3, +2 more))".
	return "(" + formatPortList(ports[:max]) + fmt.Sprintf(", +%d more", len(ports)-max) + ")"
}
