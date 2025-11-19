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
running 10 tests
test domain_filter::tests::test_filter_integration ... ok
test domain_filter::tests::test_parsing_lines ... ok
test domain_filter::tests::test_file_loading ... ok
test domain_filter::tests::test_trie_matching_logic ... ok
test domain_filter::tests::test_validation ... ok
test tests::test_parse_http_basic ... ok
test tests::test_parse_http_connect ... ok
test tests::test_parse_http_partial ... ok
test tests::test_should_keep_alive ... ok
test tests::test_stats_increment ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```
```bash
❯ oha -c 400 -n 100000 http://127.0.0.1:8101/bench
Summary:
  Success rate:	99.72%
  Total:	6347.8329 ms
  Slowest:	70.7065 ms
  Fastest:	1.2383 ms
  Average:	25.3339 ms
  Requests/sec:	15753.4078

  Total data:	194.76 KiB
  Size/request:	2 B
  Size/sec:	30.68 KiB

Response time histogram:
   1.238 ms [1]     |
   8.185 ms [852]   |
  15.132 ms [9814]  |■■■■■■■■■■
  22.079 ms [27558] |■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  29.026 ms [31042] |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  35.972 ms [18936] |■■■■■■■■■■■■■■■■■■■
  42.919 ms [7919]  |■■■■■■■■
  49.866 ms [2715]  |■■
  56.813 ms [719]   |
  63.760 ms [145]   |
  70.706 ms [14]    |

Response time distribution:
  10.00% in 14.8712 ms
  25.00% in 19.1837 ms
  50.00% in 24.5265 ms
  75.00% in 30.6089 ms
  90.00% in 36.9056 ms
  95.00% in 41.1199 ms
  99.00% in 49.3038 ms
  99.90% in 58.2519 ms
  99.99% in 66.7251 ms


Details (average, fastest, slowest):
  DNS+dialup:	11.4076 ms, 0.0725 ms, 42.0992 ms
  DNS-lookup:	0.0040 ms, 0.0016 ms, 5.6722 ms

Status code distribution:
  [200] 99715 responses
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
