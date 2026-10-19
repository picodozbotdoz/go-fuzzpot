# ROADMAP 1017 — go-fuzzpot

Living checklist and single source of truth for the continuous-improvement engagement.
Execution order: **A0 → B0 (other repo) → B1 (cross-repo pairs) → A1 → B2 → A2 → B3 → B4 → A3 → new candidates**.
Tick items as completed; append new findings with a one-line rationale; never delete items.
Companion file: `repo/fuzz-sec-intel/docs/ROADMAP_1017.md` (sections B0–B4 + C).

## A. go-fuzzpot

### A0 — Correctness & hygiene (do first)

- [x] **A0-1 Repair broken scripts** — `install.sh` invokes nonexistent `s2do` everywhere sudo belongs (17, 24-48, 59-62); `build-release.sh` invokes `g2t` where git belongs (62-65), hardcodes `cd /home/plain/.picoclaw/...` (4, 59, 269, 290), copies a systemd file from a path it never creates (195, 254, 277) and a missing `LICENSE` (279) — with `set -e` its later steps always fail. ✅ 2026-10-18: `s2do`→`SUDO` wrapper (root-aware), `g2t`→`git`, hardcoded paths→`$SCRIPT_DIR`, service path→`$BUILDDIR/deb/...`, added MIT `LICENSE`. `bash -n` passes both.
- [x] **A0-2 Remove committed build artifacts from git** — the 4.6 MB `fuzzpot` binary at repo root and ~43 MB of binaries/zips in `release/`; gitignore both patterns. ✅ 2026-10-18: `git rm --cached` (files kept on disk) + `.gitignore` `/fuzzpot` and `/release/`. History untouched per hard rules.
- [x] **A0-3 gofmt + stats race fix** — gofmt all 13 .go files (all currently fail); fix the factually wrong SO_BACKLOG/ListenBacklog comment (main.go:288); make all four stats counters uniformly atomic (`connections` is atomic-written at main.go:325 but mutex-read at 174/205/240 — race-detector-visible). ✅ 2026-10-18: `gofmt -w` all files; new named `statsCounters` (atomic.Int64 + snapshot()) replaces the triplicated anonymous mutex struct in main/tests; backlog comment corrected (listen(2) arg via ListenConfig.Backlog, no SO_BACKLOG option). Also fixed D-1 Windows build (see below) and filepath.Join path joins.
- [x] **A0-4 Config traps** — a missing config file silently applies defaults → binds ~4000 unintended ports (config.go:76-78): add a loud warning and a `--strict` flag that hard-fails; validate overlapping/duplicate ranges; fix `keep_files: 0` documented as "unlimited" but silently becoming 10 (logger.go:43-46). ✅ 2026-10-18: `config.Exists()` + warning/`--strict` in main (smoke-tested both paths); overlap validation in `Validate()`; `New()` no longer coerces explicit 0; **new find:** `pruneOldLogs()` with maxFiles<=0 deleted ALL rotated logs (toRemove = n-0) — now self-guards. Tests: overlap/duplicate/adjacent, Exists, keep-0-unlimited, default-10.
- [x] **A0-5 Accept-loop backoff** — accept loop hot-spins on permanent errors (main.go:317-323): classify temporary vs permanent net errors, exponential backoff, listener restart. ✅ 2026-10-18: `isTemporaryAcceptError()` (timeouts/ECONNABORTED/EMFILE/ENFILE/EAGAIN/EINTR = temporary); backoff 100ms→10s cap; rebind attempt every 5 consecutive permanent errors; per-listener ctx watcher closes the listener on shutdown so a parked Accept unblocks (previously shutdown relied on process exit). Tests: classifier table + ctx-cancel loop exit.

### A1 — Reliability & observability

- [x] **A1-6 Graceful shutdown** — WaitGroup over `handleConnection` goroutines with a bounded drain window, `Sync()` the payload log before exit (today in-flight payloads are lost and writes can hit a closed file). ✅ Closed by D-3 (`6e90096`): listeners → handlers → `Sync()` → close, with a bounded grace period and a loud timeout event. Verified behaviourally in run-3 by `TestTwoPortLoopbackSmoke`, which cancels mid-flight and asserts the JSONL is complete and synced.
- [x] **A1-7 Rotation overhaul** (logger.go:122-208) — optional gzip archive instead of straight delete; fix same-second rotation collisions overwriting the earlier backup; move the 50 MB copy out of the logger mutex (all logging currently stalls); optional fsync knob. **Cross-repo: coordinate with B1-7** — prefer rename-based rotation; sec-intel's parser must handle it without loss. ✅ 2026-10-18: rename-based rotation primary (O(1) under the write mutex — the copy only remains as cross-device fallback), same-second collisions get `-N` suffix, optional `logging.compress` + `compress_delay_sec` (60 s default, giving the analyzer's drain window) gzip archive, optional `logging.fsync_writes`, prune counts `.gz` files, `NewWithOptions` API. Windows fix found: gzip path must close the source before removing it. Contract test pairs with sec-intel `TestRotationSafety`.
- [ ] **A1-8 Prometheus metrics endpoint** — localhost-only, stdlib `net/http` (no new deps): connections, payloads, bytes, throttled, errors, per-port top-N, listener failures, rotations.
- [ ] **A1-9 Zero-byte connection events** — opt-in config, default off: pure port scans currently produce no record at all.
- [x] **A1-10 Per-port fairness caps** — alongside the global 4096 semaphore (one flooded port can starve all others). ✅ Closed by D-5 (`4e37e63`): `fairness.go` caps per-port and per-IP concurrency alongside the global tracker.
- [x] **A1-11 Runtime conflict recovery** — on refresh-interval conflict detection, close affected listeners and re-bind when the port frees (today conflicts are only logged, main.go:260-262). ❌ Invalid as written, superseded by D-2 (`9e33fc3`): conflict detection no longer compares our own sockets, so "re-bind when the port frees" has no trigger. Left ticked-invalid rather than deleted, per the append-only rule.

### A2 — Capability (purpose-aligned; each opt-in where noted)

- [ ] **A2-12 `sensor` identity field** — config name + hostname in every `LogEntry` (main.go:36-46) and `SecurityEvent`. **Cross-repo: consumed by B4-22.**
- [ ] **A2-13 UDP capture** — opt-in, default off: per-port UDP sockets with SO_RCVBUF, per-datagram events (`proto: "udp"`), `/proc/net/udp{,6}` conflict detection.
- [ ] **A2-14 SIGHUP config reload** — reconciling the listener set (add/remove/rebind without dropping captures). Note: SIGHUP is currently unhandled → terminates the process.
- [ ] **A2-15 Raw payload artifact capture** — opt-in, default off: raw bytes to a daily spool dir for analyzer replay; JSONL stays the primary contract.

### A3 — Performance & quality

- [ ] **A3-16 Zero-alloc hot path** — `sync.Pool` for capture buffers, dedicated log-writer goroutine with group commit, reused hex/printable buffers; add benchmarks and record numbers here.
- [ ] **A3-17 Fuzz tests + CI gate** — native Go fuzz tests (`extractPrintable`, hex conversion, /proc parsers); linux-tagged unit tests for `portscan_linux.go` (zero coverage today); CI gate: gofmt + vet + race + build matrix.

### C. Perpetual practices (never-ending layer)

- [ ] **C-1 Cross-repo contract tests** — run in BOTH repos' verification gates.
- [ ] **C-2 Quarterly drift assessment** — tooling exists; record score trend here.
- [ ] **C-3 Benchmarks tracked per release** — fuzzpot captures/sec (recorded here per release).
- [ ] **C-4 Debt tax** — every feature item completed pays for one B0/B1-class debt fix before the next feature.

## Newly discovered improvements (append-only)

- [x] **D-1 Windows build broken by unix.Getrlimit** (found 2026-10-18 during A0-3): main.go queried RLIMIT_NOFILE unconditionally; `unix.Rlimit`/`Getrlimit`/`SetsockoptInt` and `syscall.SIGUSR1` are undefined on windows in x/sys → `go vet`/`go build` failed on Windows. ✅ Fixed same day: platform split `platform_unix.go`/`platform_windows.go` (`maxConnections()`, `healthSignals()`, `listenControl`); main.go no longer imports x/sys. Cross-compile verified linux/freebsd/darwin; `go test ./...` green on Windows. Sub-fixes: `filepath.Join` in logger.New and Config.LogPath (+2 tests updated from hardcoded `/`).

- [x] **D-2 Conflict detector is self-referential** (found 2026-10-18, review): `DetectConflicts` (`portscan/portscan.go:97-109`) tests our own `listenPorts` against `/proc/net/tcp`, which includes our own sockets → all ~4000 ports reported as conflicts every 60 s (~24 KB/min into `security.log`, rolling the 30×10 MB audit trail in <9 h). Fix: diff against a startup snapshot of foreign ports, or detect own-listener death via bind/accept failure. **Supersedes A1-11 as written.** ✅ 9e33fc3 — `MarkLost` + listener-death semantics; test rewritten.
- [x] **D-3 Shutdown drain order inverted** (found 2026-10-18, review): `main.go:492-502` awaits handlers before listeners, so a late accept can `wg.Add(1)` after the counter hits 0 and write after `log.Close()`; `Sync()` is still missing. Order: listeners → `conns.wait()` → `Sync()` → close. Closes A1-6. ✅ 6e90096 — listeners → handlers → `Sync()` → close.
- [x] **D-4 No in-flight byte budget** (found 2026-10-18, review): ~0.45 MB per 64 KB event × 4096 slots ≫ `MemoryMax=128M`; a slow-drip sender OOM-kills the sensor. Add a global byte budget, derive slots from `MemoryMax`, default `max_payload_size` 16 KB. ✅ 4e37e63.
- [x] **D-5 No per-source fairness** (found 2026-10-18, review): one flooded port or ~409 conn/s starves every other port for the full 10 s deadline. Per-IP/per-port counters + short idle deadline. ✅ 4e37e63.
- [x] **D-6 `max_payload_size` is not a hard cap** (found 2026-10-18, review): 4096-byte reads overshoot by up to 4095 and truncation is invisible. Read `min(remaining, …)`; add `truncated` to `LogEntry` + schema v2 (paired with sec-intel contract test). ✅ `14cc79d` — `capture.Capture` reads `min(remaining, chunk)` and sets `Truncated`; schema v2 carries the flag. Verified in run-3 by `TestTwoPortLoopbackSmoke` (`size == len(hex)`, `truncated` absent under the cap).
- [x] **D-7 `ts` is completion time at 1 s resolution** (found 2026-10-18, review): taken after EOF/timeout, `RFC3339` without fractions, while the fixture advertises ms. Record first-byte time, `RFC3339Nano`, document in `contract/README.md`. ✅ `14cc79d` — `firstByte` captured at the first successful read, written as `RFC3339Nano`; contract v2 documents it.
- [x] **D-8 Logger error paths are unrecoverable** (found 2026-10-18, review): short write leaves a torn JSONL line; failed reopen leaves the descriptor closed forever; `f.Stat()` nil-deref (`logger/logger.go:66,96-101,175-195`). ✅ `b3b80cf` — torn-write recovery (`writeLine`), closed-state semantics (`ErrLoggerClosed`), reopen by path. Verified in run-3: no logger error path is reachable from the tests without a log line.
- [x] **D-9 Readiness and exit codes lie** (found 2026-10-18, review): banner counts targets, not successful binds; total bind failure exits 0 (`main.go:418,480`). ✅ `1897f4a` — `bound == 0 && targets > 0` returns an error (non-zero exit); the banner reports bound-of-target with a `partial_bind` event.
- [x] **D-10 SIGHUP terminates the sensor** (found 2026-10-18, review): unregistered signal; logrotate rename strands writes on the old inode. Treat as reopen-by-path. ✅ `1897f4a` — `SIGHUP` registered, `reopenLogs()` re-opens both logs by path (logrotate-safe). Config reload is still A2-14.
- [x] **D-11 Config validation gaps** (found 2026-10-18, review): non-strict YAML hides typos, unbounded `max_payload_size`, unvalidated `logging.dir`/`file` (`config/config.go:93,126-128`). ✅ `1897f4a` — `dec.KnownFields(true)`, `Validate()` bounds `max_payload_size` and requires an absolute `logging.dir`.
- [x] **D-12 Throttle path blocks accept** (found 2026-10-18, review): mutex + write + rotation check on the accept goroutine, attacker-controlled volume (`main.go:692`). ✅ `1897f4a`/`4e37e63` — the accept path only increments an atomic counter; the aggregate reaches `security.log` from the stats ticker and the shutdown flush (`flushThrottled`).

- [x] **D-13 Throttle delta can be logged twice** (found 2026-10-19, run-3 review): `reportStats` claimed the delta with a plain `Store` after writing it while `drain` used `CompareAndSwap`; when both ran in the same tick the same rejections were written to `security.log` twice — an audit trail that overcounts exactly during a flood. ✅ `1000205` — one `flushThrottled()` helper, CAS-only, used by the ticker and the shutdown path; `TestFlushThrottled_ClaimsDeltaOnce` drives 8 concurrent flushes and asserts one line with the exact count.
- [x] **D-14 CI lint job could never pass** (found 2026-10-19, run-3 review): `golangci-lint v1.61` was built with Go 1.23 and refuses a module targeting go 1.25, so the job failed before analysing anything; `--disable-all` no longer exists in v2. ✅ `f2832cc` — action v9 + linter v2.15.0 + `--default=none`.
- [x] **D-15 Two CI gaps left** (found 2026-10-19, run-3 review): (a) the race lane only runs on Linux — correct, but `go test -race` is never run against the `portscan` build-tag variants that only exist on other OSes; (b) `install.sh` ships a unit with `CapabilityBoundingSet=` empty, so a config that includes a privileged port (22/80/443) fails to bind with `EACCES` and the operator sees only a per-port error. Add a `README`/unit note, or an `AmbientCapabilities=CAP_NET_BIND_SERVICE` opt-in. ✅ (b) `7d8255b` — `listenPort` names the cause on `EACCES` below 1024 (`hint=privileged port requires CAP_NET_BIND_SERVICE`), and the unit + README document the opt-in; linux `/proc` parsers got `portscan_linux_test.go`, which the Linux race lane now exercises. (a) new `cross-vet` CI job vets + builds freebsd/darwin/windows, so every `portscan_*` variant compiles against the shared API on each push. `-race` itself cannot run cross-OS; that limit is accepted, not open.

## Benchmarks

_(record capture/sec numbers per release here as A3-16 lands)_

## Blockers

- 2026-10-18: `go test -race` unavailable on this Windows dev box (needs cgo + gcc; neither present). Race gate must run in Linux CI (see A3-17). Cross-compile checks (linux/freebsd/darwin) used as a partial substitute.

## Changelog of roadmap changes

- 2026-10-18: roadmap materialized from engagement brief (Step 0).

- 2026-10-18 (B1-8 cross-repo, landed): `v:1` field in every LogEntry; contract/log_schema.json + sample fixture byte-identical in both repos; contract tests run under both gates.
- 2026-10-18 (review): appended D-2..D-12 from `outputs/engineering/PROJECT_REVIEW_2026-10-18.md`; marked A1-11 invalid as written (superseded by D-2) and A1-6 closable via D-3. No items deleted.
- 2026-10-19 (run-3): ticked A1-6 (D-3 shipped it); appended D-13 (throttle double-count, fixed), D-14 (CI linter, fixed), D-15 (CI/unit gaps, open). Verification: `gofmt -l` empty, `go vet` clean, `go test ./...` green, four cross-builds OK, `--dry-run` exit 0.
- 2026-10-19 (close-out): ticked D-15 (`7d8255b` + cross-vet CI job).
