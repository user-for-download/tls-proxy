# 🚀 TLS Proxy 
### (README.md is powered by AI)

High-performance TLS proxy server with domain filtering and TLS handshake fragmentation.

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## ✨ Features 

- **🔒 TLS Fragmentation** - Splits TLS ClientHello packets
- **🚫 Domain Filtering** - Blacklist and whitelist support with wildcard patterns
- **⚡ High Performance** - Multi-threaded async I/O with tokio runtime
- **📊 Real-time Statistics** - Monitor connections, traffic, and blocked domains
- **🔄 HTTP Keep-Alive** - Connection pooling for health checks and benchmarks
- **🎯 Smart Matching** - Radix trie for efficient wildcard domain matching
- **🛡️ Thread-Safe** - Concurrent reads and atomic updates

## 📦 Installation

### Prerequisites

- Rust 1.91 or higher
- Linux/macOS/Windows

### Build from source

```bash
# Clone repository
git clone <your-repo-url>
cd tls-proxy

# Build release version
cargo build --release

# Binary will be at target/release/tls-proxy
```

### Production build

```bash
# Maximum optimization
cargo build --profile production
```

## 🚀 Quick Start

### Basic usage

```bash
# Run on default port 8100
./target/release/tls-proxy

# Custom host and port
./target/release/tls-proxy --host 0.0.0.0 --port 8080

# With domain filtering
./target/release/tls-proxy \
  --blacklist blacklist.txt \
  --whitelist whitelist.txt
```

### Configure your browser/system

Set HTTP/HTTPS proxy to:
```
Host: 127.0.0.1
Port: 8100
```

## 📋 Command Line Options

```bash
./tls-proxy [OPTIONS]

Options:
  --host <HOST>                  Bind address [default: 0.0.0.0]
  --port <PORT>                  Listen port [default: 8100]
  --blacklist <FILE>             Blacklist domains file
  --whitelist <FILE>             Whitelist domains file
  --timeout-connect <SECONDS>    Upstream connect timeout [default: 10]
  --timeout-idle <SECONDS>       Idle connection timeout [default: 0 (disabled)]
  --stats-interval <SECONDS>     Statistics print interval [default: 60]
  --log-level <LEVEL>            Log level: error|warn|info|debug [default: info]
  -q, --quiet                    Quiet mode (errors only)
  -v, --verbose                  Verbose mode (debug)
  -h, --help                     Print help
  -V, --version                  Print version
```

## 📝 Domain List Format

Create `blacklist.txt` or `whitelist.txt` with one domain per line.

### Supported formats

```bash
# Comments
# Lines starting with # or // are ignored

# Exact match
example.com

# Subdomain wildcard (*.example.com and example.com)
*.example.com
.example.com

# Generic wildcard (matches anywhere)
*tracking

# URL formats (automatically parsed)
https://example.com/path
http://example.com:8080
||example.com^

# AdBlock format
@@whitelisted.com
||blocked.com

# Case insensitive
Example.COM
EXAMPLE.com
```

### Example blacklist.txt

```bash
# Ad networks
doubleclick.net
*.googlesyndication.com
*.googleadservices.com

# Tracking
*analytics
*tracking
*.metrics.com
```

### Example whitelist.txt

```bash
# Russian banks (no fragmentation)
sberbank.ru
*.sberbank.ru
alfabank.ru
*.alfabank.ru

# Government services
gosuslugi.ru
*.gosuslugi.ru
nalog.ru
*.nalog.ru

# Local services
mos.ru
*.mos.ru
```

## 🔍 How It Works

### TLS Fragmentation

For non-whitelisted domains:

1. **Intercept** - Proxy intercepts TLS ClientHello packet
2. **Fragment** - Splits packet at SNI (Server Name Indication) field
3. **Send** - Sends fragments with 1ms delay between them
4. **Bypass** - Fail to detect complete SNI

### Domain Filtering

Three matching strategies:

- **Exact match** - HashSet O(1) lookup: `example.com`
- **Suffix wildcard (trie)** - Radix trie O(k): `*.example.com`
- **Generic wildcard (vec)** - Vector scan: `*tracking`

### Architecture

```
Client → Proxy → Upstream Server
         ↓
    [Domain Filter]
         ↓
    [TLS Fragment] (if not whitelisted)
         ↓
    [Bidirectional Copy]
```

## 📊 Monitoring

### Health check endpoint

```bash
curl http://localhost:8100/health
# Response: 200 OK
```

### Statistics endpoint

```bash
curl http://localhost:8100/stats

# Response (JSON):
{
  "total": 1543,
  "active": 12,
  "blocked": 89,
  "whitelisted": 234,
  "fragmented": 1220,
  "failed": 5,
  "bytes_in": 45678901,
  "bytes_out": 123456789
}
```

### Benchmark endpoint

```bash
# Test keep-alive performance
curl http://localhost:8100/bench
# Response: 200 OK
```

### Console statistics

Statistics are automatically printed every 60 seconds (configurable):

```
📊 total=1543 active=12 blocked=89 whitelisted=234 fragmented=1220 failed=5 in=43MB out=117MB
```

## ⚙️ Configuration Examples

### Basic proxy

```bash
./tls-proxy \
  --host 0.0.0.0 \
  --port 8100 \
  --log-level info
```

### With filtering and timeouts

```bash
./tls-proxy \
  --host 127.0.0.1 \
  --port 3128 \
  --blacklist blocked_domains.txt \
  --whitelist trusted_domains.txt \
  --timeout-connect 15 \
  --timeout-idle 300 \
  --stats-interval 30
```

### Silent mode for systemd

```bash
./tls-proxy \
  --quiet \
  --stats-interval 0 \
  --blacklist /etc/tls-proxy/blacklist.txt
```

### Development mode

```bash
./tls-proxy \
  --verbose \
  --stats-interval 10
```

## 🔧 Systemd Service

Create `/etc/systemd/system/tls-proxy.service`:

```ini
[Unit]
Description=TLS Proxy Server
After=network.target

[Service]
Type=simple
User=proxy
Group=proxy
WorkingDirectory=/opt/tls-proxy
ExecStart=/opt/tls-proxy/tls-proxy \
  --host 0.0.0.0 \
  --port 8100 \
  --blacklist /etc/tls-proxy/blacklist.txt \
  --whitelist /etc/tls-proxy/whitelist.txt \
  --log-level info
Restart=always
RestartSec=5

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/tls-proxy

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable tls-proxy
sudo systemctl start tls-proxy
sudo systemctl status tls-proxy
```

View logs:

```bash
journalctl -u tls-proxy -f
```

## 🧪 Testing

### Run all tests

```bash
cargo test
```

### Run specific test

```bash
cargo test test_domain_filter
```

### With output

```bash
cargo test -- --nocapture
```

### Benchmarks

```bash
cargo bench
```

## 📈 Performance

### Benchmarks (VM Ubuntu 24.04.3 LTS,4CPUs,8Gb)
```bash
❯ rustc -V
rustc 1.91.1 (ed61e7d7e 2025-11-07)
❯ wrk -t12 -c400 -d30s --latency http://localhost:8100/bench
Running 30s test @ http://localhost:8100/bench
12 threads and 400 connections
Thread Stats   Avg      Stdev     Max   +/- Stdev
Latency     4.36ms    3.05ms  32.84ms   67.67%
Req/Sec     7.16k     1.07k   13.52k    70.08%
Latency Distribution
50%    4.08ms
75%    6.05ms
90%    8.26ms
99%   13.64ms
2566311 requests in 30.09s, 303.48MB read
Socket errors: connect 0, read 25218, write 0, timeout 0
Requests/sec:  85279.89
Transfer/sec:     10.08MB
```

### Optimization tips

1. **Use production profile**:
   ```bash
   cargo build --profile production
   ```

2. **Increase file descriptors**:
   ```bash
   ulimit -n 65535
   ```

3. **Disable statistics** in production:
   ```bash
   --stats-interval 0 --quiet
   ```

4. **Use whitelist** for trusted domains (no fragmentation)

## 🐛 Troubleshooting

### Connection refused

```bash
# Check if proxy is running
netstat -tlnp | grep 8100

# Check firewall
sudo ufw allow 8100/tcp
```

### High memory usage

```bash
# Enable idle timeout
--timeout-idle 300

# Reduce stats interval
--stats-interval 0
```

### Domains not blocked

```bash
# Test with verbose logging
./tls-proxy --verbose --blacklist blacklist.txt

# Check domain format (lowercase, no protocol)
echo "example.com" > test.txt  # ✅ Good
echo "https://example.com" > test.txt  # ⚠️ Will be parsed, but avoid
```

### TLS errors

```bash
# Some sites may reject fragmented ClientHello
# Add them to whitelist:
echo "problematic-site.com" >> whitelist.txt
```

## 🔐 Security Considerations

- **Not an anonymity tool** - Logs contain domain information
- **No authentication** - Use firewall rules to restrict access
- **Plain HTTP proxy** - No MITM SSL inspection
- **Trust DNS** - Relies on system DNS resolution
- **Rate limiting** - Not implemented, add external solution if needed

## 📚 Project Structure

```
tls-proxy/
├── src/
│   ├── main.rs           # Proxy server, connection handling
│   └── domain_filter.rs  # Domain filtering logic
├── Cargo.toml            # Dependencies and build config
├── blacklist.txt         # Example blacklist
├── whitelist.txt         # Example whitelist
└── README.md            # This file
```


## 📄 License

MIT License - see LICENSE file for details
