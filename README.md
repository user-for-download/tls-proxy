# Rust TLS Proxy

A high-performance, asynchronous HTTP/HTTPS proxy written in Rust. It features Deep Packet Inspection (DPI) evasion via TLS ClientHello fragmentation and efficient domain filtering using Radix Tries.

## Features

*   **High Performance:** Built on `tokio` with multi-threading and minimized memory copying.
*   **DPI Evasion:** Automatically fragments TLS ClientHello packets to bypass SNI-based filtering/throttling.
*   **Domain Filtering:** fast `O(k)` blacklisting and whitelisting (supports adblock-style syntax).
*   **Observability:** Structured logging via `tracing` and internal stats endpoints.
*   **Resilience:** Connection pooling limits, timeouts, and RAII-based resource management.

## Installation

Ensure you have Rust installed.

```bash
# Build for release (optimized)
cargo build --release
```
```bash
❯ oha -c 400 -n 1000000 http://127.0.0.1:8100/bench
Summary:
  Success rate:	99.99%
  Total:	14700.9164 ms
  Slowest:	123.6573 ms
  Fastest:	0.0517 ms
  Average:	5.8673 ms
  Requests/sec:	68022.9705

  Total data:	1.91 MiB
  Size/request:	2 B
  Size/sec:	132.85 KiB

Response time histogram:
    0.052 ms [1]      |
   12.412 ms [971012] |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
   24.773 ms [28297]  |
   37.133 ms [536]    |
   49.494 ms [68]     |
   61.855 ms [0]      |
   74.215 ms [0]      |
   86.576 ms [0]      |
   98.936 ms [6]      |
  111.297 ms [3]      |
  123.657 ms [2]      |

Response time distribution:
  10.00% in 2.8038 ms
  25.00% in 3.9102 ms
  50.00% in 5.4274 ms
  75.00% in 7.2152 ms
  90.00% in 9.3969 ms
  95.00% in 11.0675 ms
  99.00% in 15.2254 ms
  99.90% in 22.6648 ms
  99.99% in 35.9506 ms


Details (average, fastest, slowest):
  DNS+dialup:	3.9301 ms, 0.0731 ms, 85.7917 ms
  DNS-lookup:	0.0068 ms, 0.0015 ms, 6.0484 ms

Status code distribution:
  [200] 999925 responses

```

## Usage

Run the binary from the target directory:

```bash
./target/release/tls-proxy --port 8101 --blacklist blocked.txt
```

### Command Line Arguments

| Argument | Default | Description |
| :--- | :--- | :--- |
| `--host` | `0.0.0.0` | IP address to bind to. |
| `--port` | `8101` | Port to listen on. |
| `--blacklist` | `None` | Path to a file containing domains to block (returns 403). |
| `--whitelist` | `None` | Path to a file containing domains to **exclude** from TLS fragmentation. |
| `--log-level` | `info` | Logging level (`trace`, `debug`, `info`, `warn`, `error`). |
| `--stats-interval`| `60` | Seconds between printing stats to stdout. |

### Environment Variables

You can also control logging via `RUST_LOG`:

```bash
RUST_LOG=debug ./tls-proxy
```

## Filter List Syntax

The proxy supports a subset of standard adblock syntax for blacklists and whitelists.

**Supported formats:**
*   `example.com` (Exact match)
*   `||example.com` (normalized to exact match)
*   `*.example.com` (Wildcard suffix)
*   `.example.com` (Wildcard suffix)

**Comments:** Lines starting with `#` or `//` are ignored.

## Internal Endpoints

The proxy intercepts specific HTTP requests for health checks and monitoring (these are not forwarded upstream):

1.  **Health Check:**
    *   Request: `GET /health HTTP/1.1`
    *   Response: `200 OK`

2.  **Benchmarking:**
    *   Request: `GET /bench HTTP/1.1`
    *   Response: `200 OK` (Minimal keep-alive response)

3.  **Live Stats (JSON):**
    *   Request: `GET /stats HTTP/1.1`
    *   Response: JSON object containing active connections, total bytes, blocked count, etc.

## License

MIT
