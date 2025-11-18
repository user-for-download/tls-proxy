#![warn(clippy::all)]

mod domain_filter;

use crate::domain_filter::DomainFilter;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info, warn};

// ============================================================================
// CONSTANTS
// ============================================================================

const MAX_TLS_RECORD_SIZE: usize = 16384;
const TLS_HANDSHAKE_TYPE: u8 = 0x16;
const MAX_KEEPALIVE: usize = 100;

// ============================================================================
// STATIC RESPONSES (Zero allocation)
// ============================================================================

const RESPONSE_HEALTH: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/plain\r\n\
Content-Length: 2\r\n\
Connection: close\r\n\
\r\n\
OK";

const RESPONSE_HEALTH_KEEPALIVE: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/plain\r\n\
Content-Length: 2\r\n\
Connection: keep-alive\r\n\
\r\n\
OK";

const RESPONSE_BENCH: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/plain\r\n\
Content-Length: 2\r\n\
Connection: keep-alive\r\n\
\r\n\
OK";

const RESPONSE_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\r\n";
const RESPONSE_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\r\n";
const RESPONSE_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";
const RESPONSE_200_CONNECT: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

// ============================================================================
// CLI ARGUMENTS
// ============================================================================

#[derive(Parser, Debug, Clone)]
#[command(author, version, about)]
struct Args {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    #[arg(long, default_value_t = 8100)]
    port: u16,

    #[arg(long)]
    blacklist: Option<PathBuf>,

    #[arg(long)]
    whitelist: Option<PathBuf>,

    #[arg(long, default_value_t = 10)]
    timeout_connect: u64,

    #[arg(long, default_value_t = 0)]
    timeout_idle: u64,

    #[arg(long, default_value_t = 60)]
    stats_interval: u64,

    #[arg(long, short = 'q')]
    quiet: bool,

    #[arg(long, short = 'v')]
    verbose: bool,

    #[arg(long, default_value = "info")]
    log_level: String,
}

// ============================================================================
// STATISTICS
// ============================================================================

struct Stats {
    total: AtomicU64,
    active: AtomicU64,
    blocked: AtomicU64,
    whitelisted: AtomicU64,
    fragmented: AtomicU64,
    failed: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            active: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            whitelisted: AtomicU64::new(0),
            fragmented: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        }
    }

    fn print(&self) {
        info!(
            "📊 total={} active={} blocked={} whitelisted={} fragmented={} failed={} in={}MB out={}MB",
            self.total.load(Ordering::Relaxed),
            self.active.load(Ordering::Relaxed),
            self.blocked.load(Ordering::Relaxed),
            self.whitelisted.load(Ordering::Relaxed),
            self.fragmented.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
            self.bytes_in.load(Ordering::Relaxed) / 1_000_000,
            self.bytes_out.load(Ordering::Relaxed) / 1_000_000,
        );
    }
}

// ============================================================================
// PROXY CONFIGURATION
// ============================================================================

#[derive(Clone)]
struct ProxyConfig {
    filter: Arc<DomainFilter>,
    stats: Arc<Stats>,
    connect_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
}

// ============================================================================
// MAIN
// ============================================================================

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let log_level = if args.quiet {
        "error"
    } else if args.verbose {
        "debug"
    } else {
        &args.log_level
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .with_target(false)
        .compact()
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus::get() * 2)
        .thread_stack_size(2 * 1024 * 1024)
        .enable_all()
        .build()?;

    runtime.block_on(run(args))
}

async fn run(args: Args) -> anyhow::Result<()> {
    let filter = Arc::new(DomainFilter::new());

    if let Some(ref path) = args.blacklist {
        filter.load_blacklist(path)?;
    }

    if let Some(ref path) = args.whitelist {
        filter.load_whitelist(path)?;
    }

    let stats = Arc::new(Stats::new());

    if args.stats_interval > 0 {
        let stats_clone = stats.clone();
        let interval = args.stats_interval;
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(interval));
            loop {
                timer.tick().await;
                stats_clone.print();
            }
        });
    }

    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;

    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;

    socket.set_nonblocking(true)?;

    match socket.bind(&addr.into()) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            eprintln!("\n❌ PORT {} ALREADY IN USE\n", args.port);
            eprintln!("   Active processes on port {}:", args.port);
            let _ = std::process::Command::new("sh")
                .arg("-c")
                .arg(&format!(
                    "lsof -i:{} -P -n | grep LISTEN || echo ''",
                    args.port
                ))
                .status();
            eprintln!(
                "\n   Kill them all: sudo kill -9 $(lsof -t -i:{})",
                args.port
            );
            eprintln!("\n   Or just run with different port: --port 8101\n");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Bind failed: {}", e);
            std::process::exit(1);
        }
    }

    socket.listen(1024)?;
    let listener = TcpListener::from_std(socket.into())?;

    info!("🚀 Proxy listening on http://{}", addr);
    info!("⚡ Optimized for maximum performance");

    let connect_timeout = if args.timeout_connect > 0 {
        Some(Duration::from_secs(args.timeout_connect))
    } else {
        None
    };

    let idle_timeout = if args.timeout_idle > 0 {
        Some(Duration::from_secs(args.timeout_idle))
    } else {
        None
    };

    loop {
        let (client_stream, client_addr) = listener.accept().await?;

        let config = ProxyConfig {
            filter: filter.clone(),
            stats: stats.clone(),
            connect_timeout,
            idle_timeout,
        };

        stats.total.fetch_add(1, Ordering::Relaxed);
        stats.active.fetch_add(1, Ordering::Relaxed);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(client_stream, client_addr, config.clone()).await {
                debug!("Connection error from {}: {}", client_addr, e);
                config.stats.failed.fetch_add(1, Ordering::Relaxed);
            }

            config.stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

// ============================================================================
// OPTIMIZED HTTP HANDLER WITH KEEP-ALIVE
// ============================================================================

async fn handle_direct_http(
    request: &[u8],
    client: &mut TcpStream,
    stats: &Arc<Stats>,
) -> anyhow::Result<bool> {
    if request.len() < 13 {
        return Ok(false);
    }

    let is_health = request.len() >= 14 && &request[4..14] == b"/health HT";
    let is_bench = request.len() >= 13 && &request[4..13] == b"/bench HT";
    let is_stats = request.len() >= 13 && &request[4..13] == b"/stats HT";

    if !is_health && !is_bench && !is_stats {
        return Ok(false);
    }

    let wants_keepalive = request
        .windows(17)
        .any(|w| w.eq_ignore_ascii_case(b"connection: keep-"))
        || request.windows(10).any(|w| w == b"keep-alive");

    if is_health {
        if wants_keepalive {
            client.write_all(RESPONSE_HEALTH_KEEPALIVE).await?;
        } else {
            client.write_all(RESPONSE_HEALTH).await?;
        }
        return Ok(true);
    }

    if is_bench {
        client.write_all(RESPONSE_BENCH).await?;
        return Ok(true);
    }

    if is_stats {
        let json = format!(
            r#"{{"total":{},"active":{},"blocked":{},"whitelisted":{},"fragmented":{},"failed":{},"bytes_in":{},"bytes_out":{}}}"#,
            stats.total.load(Ordering::Relaxed),
            stats.active.load(Ordering::Relaxed),
            stats.blocked.load(Ordering::Relaxed),
            stats.whitelisted.load(Ordering::Relaxed),
            stats.fragmented.load(Ordering::Relaxed),
            stats.failed.load(Ordering::Relaxed),
            stats.bytes_in.load(Ordering::Relaxed),
            stats.bytes_out.load(Ordering::Relaxed),
        );

        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: {}\r\n\
             \r\n\
             {}",
            json.len(),
            if wants_keepalive {
                "keep-alive"
            } else {
                "close"
            },
            json
        );

        client.write_all(response.as_bytes()).await?;
        return Ok(true);
    }

    Ok(false)
}

// ============================================================================
// CONNECTION HANDLER WITH KEEP-ALIVE LOOP
// ============================================================================

async fn handle_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
    config: ProxyConfig,
) -> anyhow::Result<()> {
    let _ = client.set_nodelay(true);

    let mut keepalive_count = 0;

    loop {
        let mut buf = [0u8; 4096];

        let read_timeout = if keepalive_count == 0 {
            Duration::from_secs(5)
        } else {
            Duration::from_secs(2)
        };

        let n = match timeout(read_timeout, client.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            Ok(Ok(_)) => break,
            Ok(Err(e)) => {
                if keepalive_count > 0 {
                    break;
                }
                debug!("Read error from {}: {}", client_addr, e);
                return Err(e.into());
            }
            Err(_) => {
                if keepalive_count > 0 {
                    break;
                }
                debug!("Read timeout from {}", client_addr);
                return Ok(());
            }
        };

        match handle_direct_http(&buf[..n], &mut client, &config.stats).await {
            Ok(true) => {
                let wants_keepalive = buf[..n].windows(10).any(|w| w == b"keep-alive")
                    || buf[..n]
                        .windows(17)
                        .any(|w| w.eq_ignore_ascii_case(b"connection: keep-"));

                if wants_keepalive && keepalive_count < MAX_KEEPALIVE {
                    keepalive_count += 1;
                    continue;
                } else {
                    break;
                }
            }
            Ok(false) => {}
            Err(e) => {
                debug!("Handler error: {}", e);
                break;
            }
        }

        let request = String::from_utf8_lossy(&buf[..n]);
        let lines: Vec<&str> = request.lines().collect();

        if lines.is_empty() {
            break;
        }

        let parts: Vec<&str> = lines[0].split_whitespace().collect();

        if parts.len() < 2 {
            break;
        }

        let method = parts[0];
        let target = parts[1];

        if method == "CONNECT" {
            handle_connect(client, target, &config).await?;
            break;
        } else {
            handle_http(client, &lines, &buf[..n], &config).await?;
            break;
        }
    }

    Ok(())
}

// ============================================================================
// CONNECT HANDLER
// ============================================================================

async fn handle_connect(
    mut client: TcpStream,
    target: &str,
    config: &ProxyConfig,
) -> anyhow::Result<()> {
    let (host, port) = if let Some(idx) = target.rfind(':') {
        let h = &target[..idx];
        let p = target[idx + 1..].parse::<u16>().unwrap_or(443);
        (h, p)
    } else {
        (target, 443)
    };

    let is_whitelisted = config.filter.is_whitelisted(host);
    let is_blacklisted = config.filter.is_blacklisted(host);

    if is_blacklisted {
        config.stats.blocked.fetch_add(1, Ordering::Relaxed);
        warn!("🚫 Blocked: {}", host);
        client.write_all(RESPONSE_403).await?;
        return Ok(());
    }

    client.write_all(RESPONSE_200_CONNECT).await?;
    client.flush().await?;

    let connect_future = TcpStream::connect((host, port));

    let mut server = match config.connect_timeout {
        Some(timeout_duration) => match timeout(timeout_duration, connect_future).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                debug!("Upstream connect failed {}: {}", host, e);
                return Err(e.into());
            }
            Err(_) => {
                debug!("Upstream timeout {}", host);
                return Ok(());
            }
        },
        None => connect_future.await?,
    };

    let _ = server.set_nodelay(true);

    let should_fragment = !is_whitelisted;

    if is_whitelisted {
        config.stats.whitelisted.fetch_add(1, Ordering::Relaxed);
    }

    if should_fragment {
        let _ = fragment_tls_handshake(&mut client, &mut server, &config.stats).await;
    }

    let copy_result = match config.idle_timeout {
        Some(timeout_duration) => {
            timeout(
                timeout_duration,
                tokio::io::copy_bidirectional(&mut client, &mut server),
            )
            .await
        }
        None => Ok(tokio::io::copy_bidirectional(&mut client, &mut server).await),
    };

    match copy_result {
        Ok(Ok((sent, received))) => {
            config.stats.bytes_out.fetch_add(sent, Ordering::Relaxed);
            config.stats.bytes_in.fetch_add(received, Ordering::Relaxed);
        }
        Ok(Err(e)) => {
            if e.kind() != std::io::ErrorKind::UnexpectedEof
                && e.kind() != std::io::ErrorKind::BrokenPipe
            {
                debug!("Copy error: {}", e);
            }
        }
        Err(_) => {
            debug!("Idle timeout for {}", host);
        }
    }

    Ok(())
}

// ============================================================================
// HTTP HANDLER
// ============================================================================

async fn handle_http(
    mut client: TcpStream,
    lines: &[&str],
    initial_data: &[u8],
    config: &ProxyConfig,
) -> anyhow::Result<()> {
    let host_line = lines.iter().find(|l| l.to_lowercase().starts_with("host:"));

    let (host, port) = if let Some(host_header) = host_line {
        let host_parts: Vec<&str> = host_header.split_whitespace().collect();
        if host_parts.len() >= 2 {
            let host_port = host_parts[1];
            if let Some(idx) = host_port.rfind(':') {
                let h = &host_port[..idx];
                let p = host_port[idx + 1..].parse::<u16>().unwrap_or(80);
                (h, p)
            } else {
                (host_port, 80)
            }
        } else {
            client.write_all(RESPONSE_400).await?;
            return Ok(());
        }
    } else {
        client.write_all(RESPONSE_400).await?;
        return Ok(());
    };

    if config.filter.is_blacklisted(host) {
        config.stats.blocked.fetch_add(1, Ordering::Relaxed);
        client.write_all(RESPONSE_403).await?;
        return Ok(());
    }

    let connect_future = TcpStream::connect((host, port));

    let mut server = match config.connect_timeout {
        Some(timeout_duration) => match timeout(timeout_duration, connect_future).await {
            Ok(Ok(s)) => s,
            _ => {
                client.write_all(RESPONSE_502).await?;
                return Ok(());
            }
        },
        None => match connect_future.await {
            Ok(s) => s,
            Err(_) => {
                client.write_all(RESPONSE_502).await?;
                return Ok(());
            }
        },
    };

    let _ = server.set_nodelay(true);

    server.write_all(initial_data).await?;
    server.flush().await?;

    let copy_result = match config.idle_timeout {
        Some(timeout_duration) => {
            timeout(
                timeout_duration,
                tokio::io::copy_bidirectional(&mut client, &mut server),
            )
            .await
        }
        None => Ok(tokio::io::copy_bidirectional(&mut client, &mut server).await),
    };

    if let Ok(Ok((sent, received))) = copy_result {
        config.stats.bytes_out.fetch_add(sent, Ordering::Relaxed);
        config.stats.bytes_in.fetch_add(received, Ordering::Relaxed);
    }

    Ok(())
}

// ============================================================================
// TLS FRAGMENTATION
// ============================================================================
// ============================================================================
// TLS FRAGMENTATION
// ============================================================================

async fn fragment_tls_handshake(
    client: &mut TcpStream,
    server: &mut TcpStream,
    stats: &Stats,
) -> anyhow::Result<()> {
    let mut header = [0u8; 5];

    match timeout(Duration::from_secs(5), client.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(anyhow::anyhow!("TLS header timeout")),
    }

    if header[0] != TLS_HANDSHAKE_TYPE {
        server.write_all(&header).await?;
        return Ok(());
    }

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;

    if record_len == 0 || record_len > MAX_TLS_RECORD_SIZE {
        server.write_all(&header).await?;
        return Ok(());
    }

    let mut body = vec![0u8; record_len];

    match timeout(Duration::from_secs(5), client.read_exact(&mut body)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            server.write_all(&header).await?;
            return Err(e.into());
        }
        Err(_) => {
            server.write_all(&header).await?;
            return Err(anyhow::anyhow!("TLS body timeout"));
        }
    }

    stats.fragmented.fetch_add(1, Ordering::Relaxed);

    let split_point = body
        .iter()
        .position(|&b| b == 0x00)
        .map(|pos| pos + 1)
        .unwrap_or(record_len / 2);

    let mut packet1 = Vec::with_capacity(5 + split_point);
    packet1.extend_from_slice(&header[0..3]);
    packet1.extend_from_slice(&(split_point as u16).to_be_bytes());
    packet1.extend_from_slice(&body[..split_point]);

    server.write_all(&packet1).await?;
    server.flush().await?;

    tokio::time::sleep(Duration::from_millis(1)).await;

    if split_point < record_len {
        let remaining_len = record_len - split_point;
        let mut packet2 = Vec::with_capacity(5 + remaining_len);
        packet2.extend_from_slice(&header[0..3]);
        packet2.extend_from_slice(&(remaining_len as u16).to_be_bytes());
        packet2.extend_from_slice(&body[split_point..]);

        server.write_all(&packet2).await?;
        server.flush().await?;
    }

    Ok(())
}
// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_initialization() {
        let stats = Stats::new();
        assert_eq!(stats.total.load(Ordering::Relaxed), 0);
        assert_eq!(stats.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_tls_header_detection() {
        let tls_header = [0x16, 0x03, 0x01, 0x00, 0x10];
        assert_eq!(tls_header[0], TLS_HANDSHAKE_TYPE);
    }

    #[test]
    fn test_parse_connect_request() {
        let request = "CONNECT example.com:443 HTTP/1.1\r\n\r\n";
        let lines: Vec<&str> = request.lines().collect();
        let parts: Vec<&str> = lines[0].split_whitespace().collect();

        assert_eq!(parts[0], "CONNECT");
        assert_eq!(parts[1], "example.com:443");
    }

    #[tokio::test]
    async fn test_tcp_listener_binding() {
        let listener = TcpListener::bind("127.0.0.1:0").await;
        assert!(listener.is_ok());
    }
}
