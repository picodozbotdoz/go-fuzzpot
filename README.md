# fuzzpot

**Protocol Fuzzing Honeypot** — a lightweight Go binary that listens on thousands of TCP ports and silently captures whatever scanners, bots, and attackers throw at them.

```
  ██▀███   ██▀███   ▒█████   ███▄    █  ▒█████
 ▓██ ▒ ██▒▓██ ▒ ██▒▒██▒  ██▒ ██ ▀█   █ ▒██▒  ██▒
 ▓██ ░▄█ ▒▓██ ░▄█ ▒▒██░  ██▒▓██  ▀█ ██▒▒██░  ██▒
 ▒██▀▀█▄  ▒██▀▀█▄  ▒██   ██ ░▓██▒  ▐▌██▒▒██   ██░
 ░██▓ ▒██▒░██▓ ▒██▒░ ████▓▒░░▒██░   ▓██░░ ████▓▒░
 ░ ▒▓ ░▒▓░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░ ▒░▒░▒░
   ░▒ ░ ▒░  ░▒ ░ ▒░  ░ ▒ ▒░   ░ ░░ ░ ░ ▒   ░ ▒ ▒░
   ░░   ░   ░░   ░ ░ ░ ░ ▒     ░░   ░  ░   ░ ░ ▒
    ░        ░           ░ ░      ░          ░  ░
                Protocol Fuzzing Honeypot
```

## What it does

fuzzpot opens TCP listeners across configurable port ranges and **captures every byte** that comes in — no protocol emulation, no fake responses. It's a pure payload sink.

Every connection is logged as a JSON line with:

| Field | Description |
|---|---|
| `v` | Schema version (`1` or `2`; lines from pre-versioning builds lack it and are v1-compatible) |
| `ts` | Timestamp of the **first payload byte** (ISO 8601, sub-second precision since v2) |
| `src_ip` | Attacker IP |
| `src_port` | Attacker source port |
| `dst_port` | Target port hit |
| `proto` | Protocol (`tcp`) |
| `size` | Payload size in bytes — never exceeds `max_payload_size` (v2) |
| `printable` | Printable ASCII representation |
| `hex` | Full hex dump of the payload |
| `truncated` | v2 only: `true` when capture stopped at `max_payload_size` (more bytes may have followed; an exactly-cap-sized payload is also flagged). Omitted when `false` |

**v2 changes (vs v1):** `size` is a hard cap (v1 could overshoot by one read chunk), `ts` is the first-byte time rather than capture completion, and `truncated` makes cap-truncation visible downstream.

The machine-readable schema lives in [`contract/log_schema.json`](contract/log_schema.json) and is validated by contract tests in both fuzzpot and [fuzz-sec-intel](https://github.com/picodozbotdoz/fuzz-sec-intel) — changes must land as coordinated commits in both repos.

## Why?

Most honeypots emulate specific services (SSH, HTTP, Telnet, etc.) to interact with attackers. fuzzpot takes the opposite approach — **emulate nothing, capture everything**. This gives you:

- **Visibility into scan patterns** — see which ports attackers probe and what they send
- **Zero interaction risk** — no protocol emulation means no accidental RCE in the honeypot itself
- **Raw threat intel** — collect exploit payloads, malware handshakes, and scanner fingerprints directly
- **Zero dependencies** — single Go binary, no databases, no Docker, no external services

## Features

- **Mass port binding** — listens on thousands of ports concurrently (configurable ranges)
- **Smart port management** — auto-detects system-used ports via `/proc/net/tcp`, excludes ephemeral ranges, and supports user-defined exclusions
- **Conflict detection** — periodic re-scans warn if a new system service claims a honeypot port
- **Connection throttling** — 4096-goroutine semaphore prevents resource exhaustion under flood
- **Rotating logs** — size-based rotation (50 MB/file) with automatic pruning (~500 MB max on disk)
- **Dry-run mode** — preview port analysis without starting listeners
- **Hardened by default** — systemd sandbox with read-only filesystem, dropped capabilities, isolated `/tmp`, no new privileges
- **Single binary** — ~3 MB stripped, zero runtime dependencies

## Quick Start

### Build

```bash
# Requires Go 1.22+
go build -o fuzzpot .
```

### Run (foreground)

```bash
# Dry run — see port analysis without listening
./fuzzpot --dry-run

# Start with default config
./fuzzpot

# Custom config path
./fuzzpot --config /path/to/config.yaml

# Refuse to start if the config file is missing
# (otherwise fuzzpot falls back to built-in defaults with a loud warning)
./fuzzpot --strict
```

### Install as systemd service

```bash
sudo ./install.sh
sudo systemctl enable --now fuzzpot
```

This creates:
| Path | Description |
|---|---|
| `/opt/fuzzpot/fuzzpot` | Binary |
| `/etc/fuzzpot/config.yaml` | Configuration |
| `/var/log/fuzzpot/` | Log directory |
| `fuzzpot.service` | Systemd unit |

### Check status

```bash
sudo systemctl status fuzzpot
journalctl -u fuzzpot -f
```

## Configuration

```yaml
# /etc/fuzzpot/config.yaml

ports:
  ranges:
    - from: 2000
      to: 5000
    - from: 8000
      to: 9000
  exclude:
    - 2222    # Cowrie SSH
    - 2223    # Cowrie Telnet
    - 3306    # MySQL
    - 5432    # PostgreSQL
    - 6379    # Redis
    - 27017   # MongoDB

capture:
  read_timeout_sec: 10       # seconds to wait for payload data
  max_payload_size: 65536    # max bytes to capture per connection (64 KB)

logging:
  dir: /var/log/fuzzpot
  file: payloads.log

refresh:
  interval_sec: 60           # re-scan /proc/net/tcp for conflicts
```

### Port selection logic

Ports are selected from configured ranges, then **excluded** if:

1. Already in use by a system service (read from `/proc/net/tcp` + `/proc/net/tcp6`)
2. In the ephemeral range (read from `/proc/sys/net/ipv4/ip_local_port_range`)
3. Listed in the `exclude` config

## Resource Limits

fuzzpot is designed to be invisible. The systemd service enforces:

| Limit | Value |
|---|---|
| Memory | 128 MB |
| Tasks (goroutines) | 8,192 |
| File descriptors | 16,384 |
| CPU quota | 50% of one core |
| Concurrent connections | 4,096 (semaphore) |
| Log disk usage | ~500 MB (10 × 50 MB rotated files) |

## Sandbox (systemd)

The service runs under a strict sandbox:

- `ProtectSystem=strict` — read-only root filesystem
- `ProtectHome=true` — no access to `/home`, `/root`
- `NoNewPrivileges=true` — cannot gain elevated permissions
- `PrivateTmp=true` — isolated `/tmp`
- `PrivateDevices=true` — no device access
- `CapabilityBoundingSet=` — all Linux capabilities dropped
- `RestrictAddressFamilies=AF_INET AF_INET6` — TCP only
- `SystemCallFilter=@system-service ~@privileged` — dangerous syscalls blocked
- `LockPersonality=true`, `RemoveIPC=true`

## Log Format

Each captured payload is one JSON line:

```json
{"ts":"2026-04-17T21:15:03.000+07:00","src_ip":"185.220.101.42","src_port":54321,"dst_port":3389,"proto":"tcp","size":48,"printable":"\x03\x00\x00*ÛÈ\x00\x00\x00\x00\x00Cookie: mstshash=test","hex":"0300002bdbc8000000000000000000000436f6f6b69653a206d737473686173683d74657374"}
```

## Development & tests

```bash
gofmt -l . && go vet ./... && go test ./...
```

Test binaries bind **127.0.0.1 only** (`TestMain` sets `listenHost`). This is a
Windows requirement, not a preference: `go test` executes the package binary
from a fresh `%TEMP%\go-build*` directory on every run, and Windows Firewall
prompts once per executable path when a program listens on a wildcard address
— so a `:port` bind in a test pops a dialog on every single run. Keep new
tests on loopback. Production is unchanged: `listenHost` is empty outside
tests, so the sensor binds all interfaces.

To run the same test binary repeatedly without the toolchain rebuilding it
into a new temp directory:

```bash
go test -c -o bin/fuzzpot.test.exe .
./bin/fuzzpot.test.exe -test.v
```

## Project Structure

```
fuzzpot/
├── main.go              # Entry point, listener orchestration, stats
├── capture/
│   └── capture.go       # TCP payload capture (read + hex + printable)
├── config/
│   ├── config.go        # YAML config loading and validation
│   └── config.yaml      # Default configuration
├── logger/
│   └── logger.go        # Size-based rotating log writer
├── portscan/
│   └── portscan.go      # /proc/net/tcp parsing, ephemeral range, PortManager
├── install.sh           # System installer (creates user, copies files, enables service)
├── fuzzpot.service      # Systemd unit with full sandbox
├── go.mod
└── go.sum
```

**~890 lines of Go. One dependency** (`gopkg.in/yaml.v3`).

## Comparison with Other Honeypots

| Project | Approach | Protocols | Language | Dependencies |
|---|---|---|---|---|
| **fuzzpot** | Capture everything, emulate nothing | All TCP (raw sink) | Go | None (1 lib) |
| [Cowrie](https://github.com/cowrie/cowrie) | SSH/Telnet emulation | SSH, Telnet | Python | Redis, 20+ libs |
| [T-Pot](https://github.com/telekom-security/tpotce) | Multi-honeypot platform | 20+ protocols | Multi | Docker, ELK, 15+ containers |
| [Tanner](https://github.com/mushorg/tanner) | HTTP vulnerability emulation | HTTP | Python | Redis, Docker, PHP |
| [HellPot](https://github.com/yunginnanet/HellPot) | Infinite HTTP response | HTTP only | Go | None |
| [Canarytokens](https://github.com/thinkst/canarytokens) | Alert-based decoys | Various (token-based) | Python | Docker, MySQL, Nginx |
| [Honeytrap](https://github.com/honeytrap/honeytrap) | Protocol-aware framework | Extensible | Go | Plugins, Redis |
| [qeeqbox/honeypots](https://github.com/qeeqbox/honeypots) | 30 emulated services | 30 protocols | Python | Many |

fuzzpot fills a niche that none of these cover: **a zero-configuration, zero-emulation, mass-port payload sink**. It doesn't try to fool attackers — it silently records what they do.

## Requirements

- Linux (uses `/proc/net/tcp` for port detection)
- Go 1.22+ (to build)
- systemd (for service mode — optional, can run standalone)

## License

MIT
