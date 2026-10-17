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

- [ ] **A1-6 Graceful shutdown** — WaitGroup over `handleConnection` goroutines with a bounded drain window, `Sync()` the payload log before exit (today in-flight payloads are lost and writes can hit a closed file).
- [x] **A1-7 Rotation overhaul** (logger.go:122-208) — optional gzip archive instead of straight delete; fix same-second rotation collisions overwriting the earlier backup; move the 50 MB copy out of the logger mutex (all logging currently stalls); optional fsync knob. **Cross-repo: coordinate with B1-7** — prefer rename-based rotation; sec-intel's parser must handle it without loss. ✅ 2026-10-18: rename-based rotation primary (O(1) under the write mutex — the copy only remains as cross-device fallback), same-second collisions get `-N` suffix, optional `logging.compress` + `compress_delay_sec` (60 s default, giving the analyzer's drain window) gzip archive, optional `logging.fsync_writes`, prune counts `.gz` files, `NewWithOptions` API. Windows fix found: gzip path must close the source before removing it. Contract test pairs with sec-intel `TestRotationSafety`.
- [ ] **A1-8 Prometheus metrics endpoint** — localhost-only, stdlib `net/http` (no new deps): connections, payloads, bytes, throttled, errors, per-port top-N, listener failures, rotations.
- [ ] **A1-9 Zero-byte connection events** — opt-in config, default off: pure port scans currently produce no record at all.
- [ ] **A1-10 Per-port fairness caps** — alongside the global 4096 semaphore (one flooded port can starve all others).
- [ ] **A1-11 Runtime conflict recovery** — on refresh-interval conflict detection, close affected listeners and re-bind when the port frees (today conflicts are only logged, main.go:260-262).

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

## Benchmarks

_(record capture/sec numbers per release here as A3-16 lands)_

## Blockers

- 2026-10-18: `go test -race` unavailable on this Windows dev box (needs cgo + gcc; neither present). Race gate must run in Linux CI (see A3-17). Cross-compile checks (linux/freebsd/darwin) used as a partial substitute.

## Changelog of roadmap changes

- 2026-10-18: roadmap materialized from engagement brief (Step 0).
