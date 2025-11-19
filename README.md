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
-------------
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
