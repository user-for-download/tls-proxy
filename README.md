# TLS Proxy 🛡️⚡

A ridiculously fast, zero-copy SNI/HTTPS proxy and domain router written in async Rust. 

Engineered strictly for Linux, `tls-proxy` bypasses user-space memory copying by leveraging the kernel's `splice(2)` system call. It is designed for ultra-low latency, massive concurrency, and evading DPI (Deep Packet Inspection) via TLS ClientHello fragmentation.

## ✨ Features

* **Zero-Copy Forwarding:** Uses Linux `splice` with 1MB kernel pipes to stream data directly between sockets.
* **Advanced Socket Tuning:** Squeezes every drop of performance out of the Linux network stack using `TCP_NODELAY`, `TCP_QUICKACK`, `TCP_DEFER_ACCEPT`, `TCP_FASTOPEN`, `SO_BUSY_POLL`, and `TCP_NOTSENT_LOWAT`.
* **TCP BBR:** Native support for the BBR congestion control algorithm to maximize network throughput and minimize latency.
* **DPI Evasion / SNI Obfuscation:** Automatically fragments the TLS `ClientHello` packet to bypass SNI-based firewalls (automatically disabled for whitelisted domains).
* **Ad-Block Style Domain Routing:** Blazing fast domain filtering using Radix Tries (`radix_trie`). Natively parses standard ad-block lists (ignores `!`, `#`, handles `||domain.com`, `*.domain.com`).
* **Hardware Optimized:** Features CPU affinity pinning (`sched_setaffinity`) and cache-line padded atomic counters (`#[repr(align(128))]`) to completely eliminate CPU false-sharing.
* **Anti-Smuggling:** Hardened HTTP parser (`httparse`) instantly drops requests attempting HTTP Request Smuggling (multiple `Content-Length` or `Transfer-Encoding` headers).
* **Built-in Endpoints:** Provides fast `/health` and `/bench` endpoints for load-balancer integration.

## 🚀 Installation

### Option 1: Pre-built Binaries (Recommended)
Download the pre-compiled, heavily optimized (stripped/LTO) binaries for Linux directly from the [GitHub Releases](../../releases) page:
* `tls-proxy-linux-x64` (Standard Intel/AMD servers)
* `tls-proxy-linux-arm64` (AWS Graviton, Raspberry Pi, ARM servers)

### Option 2: Build from Source
Ensure you have the Rust toolchain installed. **Note: This project will only compile on Linux** due to extensive use of `libc` system calls.

```bash
git clone https://github.com/user-for-download/tls-proxy.git
cd tls-proxy
cargo build --release
./target/release/tls-proxy --help
```

## 💻 Usage

Run the proxy using the CLI arguments. By default, it binds to `0.0.0.0:8101` and utilizes all available CPU cores.

```bash
./tls-proxy --host 0.0.0.0 --port 443 --workers 4 --cpu-affinity --use-bbr --blacklist ./ads.txt
```

### ⚙️ CLI Configuration

| Argument | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--host` | `String` | `0.0.0.0` | IP address to bind the proxy to. |
| `--port` | `u16` | `8101` | Port to listen on. |
| `--blacklist` | `Path` | `None` | Path to a file containing blocked domains. |
| `--whitelist` | `Path` | `None` | Path to a file containing allowed domains. |
| `--timeout-connect` | `u64` | `10` | Upstream connection timeout in seconds. |
| `--timeout-idle` | `u64` | `60` | Idle connection timeout in seconds. |
| `--stats-interval` | `u64` | `60` | Print performance/traffic stats every X seconds (0 to disable). |
| `--max-connections` | `usize` | `65535` | Maximum concurrent connections. |
| `--drain-timeout` | `u64` | `30` | Graceful shutdown connection drain time in seconds. |
| `--log-level` | `String` | `info` | Log verbosity (`trace`, `debug`, `info`, `warn`, `error`). |
| `--allow-private` | `Flag` | `false` | Allow proxying to local/private IPs (e.g., `127.0.0.1`, `.local`). |
| `--use-splice` | `Flag` | `true` | Enable zero-copy `splice(2)` forwarding. |
| `--workers` | `usize` | `0` (Auto) | Number of Tokio worker threads (0 = CPU core count). |
| `--cpu-affinity` | `Flag` | `false` | Pin worker threads to dedicated CPU cores for L3 cache locality. |
| `--use-bbr` | `Flag` | `true` | Enable TCP BBR congestion control on all sockets. |

## 🛡️ Domain Filtering Format

The proxy accepts standard domain lists for both `--blacklist` and `--whitelist`. It natively understands wildcards, exact matches, and common Adblock syntax.

**Example `blacklist.txt`:**
```text
# Comments are ignored
! This is also ignored
// So is this

# Exact match
bad-site.com

# Suffix / Subdomain matches
*.ads.com
||tracking.net
```

## 🏗️ Architecture & Tech Stack

* **Async Runtime:** `tokio` (Multi-threaded, work-stealing)
* **Zero-Copy:** Linux `splice` with bidirectional non-blocking pipes.
* **Routing Tree:** `radix_trie` for extremely fast suffix lookups.
* **HTTP/SNI Parsing:** `httparse`
* **Concurrency:** `parking_lot` for lock-contention reduction, and cache-aligned `AtomicU64` for stats.
* **CLI:** `clap`
* **Logging:** `tracing` & `tracing-subscriber`

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).
