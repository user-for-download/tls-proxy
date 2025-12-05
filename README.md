# Rust TLS Proxy

A high-performance, asynchronous HTTP/HTTPS proxy written in Rust. 

## Features

*   **High Performance:** Built on `tokio` with multi-threading and minimized memory copying.
*   **Domain Filtering:** fast `O(k)` blacklisting and whitelisting (supports adblock-style syntax).
*   **Observability:** Structured logging via `tracing` and internal stats endpoints.
*   **Resilience:** Connection pooling limits, timeouts, and RAII-based resource management.

## Installation

Ensure you have Rust installed.

```bash
cargo build --release
```

## Usage
### Command Line Arguments

| Argument | Default | Description |
| :--- | :--- | :--- |
| `--host` | `0.0.0.0` | IP address to bind to. |
| `--port` | `8101` | Port to listen on. |
| `--blacklist` | `None` | Path to a file containing domains to block (returns 403). |
| `--whitelist` | `None` | Path to a file containing domains to **exclude** from TLS fragmentation. |
| `--timeout-connect` | `10` | Connection timeout in seconds. |
| `--timeout-idle` | `60` | Idle connection timeout in seconds. |
| `--stats-interval` | `60` | Seconds between printing stats to stdout. |
| `--max-connections` | `10000` | Maximum number of concurrent connections. |
| `--drain-timeout` | `30` | Graceful shutdown drain timeout in seconds. |
| `--log-level` | `info` | Logging level (`trace`, `debug`, `info`, `warn`, `error`). |
| `--allow-private` | `false` | Allow connections to private/internal IP ranges (e.g., 10.x.x.x, 192.168.x.x). |



Run the binary from the target directory:
```bash
 ./target/release/tls-proxy --help                                                                                                                                                                                 
High-performance HTTPS proxy with TLS fragmentation

Options:
      --host <HOST>                        [default: 0.0.0.0]
      --port <PORT>                        [default: 8101]
      --blacklist <BLACKLIST>              
      --whitelist <WHITELIST>              
      --timeout-connect <TIMEOUT_CONNECT>  [default: 10]
      --timeout-idle <TIMEOUT_IDLE>        [default: 60]
      --stats-interval <STATS_INTERVAL>    [default: 60]
      --max-connections <MAX_CONNECTIONS>  [default: 10000]
      --drain-timeout <DRAIN_TIMEOUT>      [default: 30]
      --log-level <LOG_LEVEL>              [default: info]
      --allow-private                      Allow connections to private/internal IP ranges
  -h, --help                               Print help
  -V, --version                            Print version
```
### Example 
```bash
./target/release/tls-proxy --host 0.0.0.0 --port 8101 --blacklist ./blacklist.txt --whitelist ./whitelist.txt --timeout-connect 10 --timeout-idle 60 --max-connections 10000 --stats-interval 60 --log-level debug
```
```bash
oha -c 400 -n 1000000 http://127.0.0.1:8101/bench
Summary:
  Success rate:	100.00%
  Total:	14135.5881 ms
  Slowest:	55.9926 ms
  Fastest:	0.0496 ms
  Average:	5.6414 ms
  Requests/sec:	70743.4310

  Total data:	1.91 MiB
  Size/request:	2 B
  Size/sec:	138.17 KiB

Response time histogram:
   0.050 ms [1]      |
   5.644 ms [563199] |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  11.238 ms [404590] |■■■■■■■■■■■■■■■■■■■■■■
  16.832 ms [28726]  |■
  22.427 ms [2615]   |

Details (average, fastest, slowest):
  DNS+dialup:	17.4072 ms, 0.1554 ms, 41.8514 ms
  DNS-lookup:	0.0026 ms, 0.0017 ms, 0.0394 ms

Status code distribution:
  [200] 1000000 responses

```

## Filter List Syntax

The proxy supports a subset of standard adblock syntax for blacklists and whitelists.

**Supported formats:**
*   `example.com` (Exact match)
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

## License

MIT
