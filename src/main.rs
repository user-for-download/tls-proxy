#![warn(clippy::all)]

mod domain_filter;

use crate::domain_filter::DomainFilter;
use clap::Parser;
use rand::{rngs::OsRng, RngCore};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info, warn};

const MAX_TLS_RECORD_SIZE: usize = 16384;
const MAX_KEEPALIVE: usize = 100;
const MAX_HEADER_SIZE: usize = 8192;

const RESPONSE_HEALTH: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
const RESPONSE_HEALTH_KEEPALIVE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK";
const RESPONSE_BENCH: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK";
const RESPONSE_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESPONSE_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESPONSE_200_CONNECT: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Rust HTTPS proxy")]
struct Args {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    #[arg(long, default_value_t = 8101)]
    port: u16,

    #[arg(long)]
    blacklist: Option<PathBuf>,

    #[arg(long)]
    whitelist: Option<PathBuf>,

    #[arg(long, default_value_t = 10)]
    timeout_connect: u64,

    #[arg(long, default_value_t = 60)]
    timeout_idle: u64,

    #[arg(long, default_value_t = 60)]
    stats_interval: u64,

    #[arg(long, default_value = "info")]
    log_level: String,
}

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
            "total={} active={} blocked={} whitelisted={} fragmented={} failed={} in={}MB out={}MB",
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

// RAII Guard to ensure active count is always decremented
struct ConnectionGuard {
    stats: Arc<Stats>,
}

impl ConnectionGuard {
    fn new(stats: Arc<Stats>) -> Self {
        stats.active.fetch_add(1, Ordering::Relaxed);
        stats.total.fetch_add(1, Ordering::Relaxed);
        Self { stats }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.stats.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
struct ProxyConfig {
    filter: Arc<DomainFilter>,
    stats: Arc<Stats>,
    connect_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level)),
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
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(args.stats_interval));
            loop {
                interval.tick().await;
                stats_clone.print();
            }
        });
    }

    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    match socket.bind(&addr.into()) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            eprintln!("\nERROR: Port {} is already in use.", args.port);
            eprintln!("Check active processes with: lsof -i:{}", args.port);
            std::process::exit(1);
        }
        Err(e) => return Err(e.into()),
    }

    socket.listen(1024)?;
    let listener = TcpListener::from_std(socket.into())?;

    info!("Rust proxy listening on http://{}", addr);

    let connect_timeout = (args.timeout_connect > 0).then_some(Duration::from_secs(args.timeout_connect));
    let idle_timeout = (args.timeout_idle > 0).then_some(Duration::from_secs(args.timeout_idle));

    let config = ProxyConfig {
        filter,
        stats: stats.clone(),
        connect_timeout,
        idle_timeout,
    };

    loop {
        let (client_stream, client_addr) = listener.accept().await?;
        let config = config.clone();

        tokio::spawn(async move {
            // Guard manages increment/decrement of active stats automatically
            let _guard = ConnectionGuard::new(config.stats.clone());

            if let Err(e) = handle_connection(client_stream, config.clone()).await {
                debug!("Connection error from {}: {}", client_addr, e);
                config.stats.failed.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
}

async fn handle_connection(mut client: TcpStream, config: ProxyConfig) -> anyhow::Result<()> {
    let _ = client.set_nodelay(true);
    let mut keepalive_count = 0usize;
    let mut buf = [0u8; MAX_HEADER_SIZE];

    loop {
        // Reset buffer read position handling not required as we re-parse from 0
        // But for a persistent connection, we need to handle previous data.
        // Simplified: We assume client sends headers in one go or we wait up to buffer limit.

        let read_timeout = if keepalive_count == 0 {
            Duration::from_secs(5)
        } else {
            Duration::from_secs(2)
        };

        let n = match timeout(read_timeout, client.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            Ok(Ok(_)) => break, // EOF
            Ok(Err(_)) | Err(_) => break, // Error or Timeout
        };

        let data = &buf[..n];

        // 1. Check special internal endpoints
        if handle_direct_http(data, &mut client, &config.stats).await? {
            if !should_keep_alive(data) {
                break;
            }
            if keepalive_count >= MAX_KEEPALIVE {
                break;
            }
            keepalive_count += 1;
            continue;
        }

        // 2. Parse HTTP
        match parse_http_request(data) {
            Ok(Some((method, path, headers))) => {
                if method == "CONNECT" {
                    handle_connect(client, &path, &config).await?;
                    // CONNECT takes over the stream, so we exit the loop
                    return Ok(());
                } else {
                    handle_http(client, headers, data, &config).await?;
                    // Standard HTTP proxy usually closes or requires complex state management
                    // For simplicity, we exit after one request unless we implement full pipelining
                    return Ok(());
                }
            }
            Ok(None) => {
                // Incomplete headers. In a full implementation, we would read more.
                // Here we just drop to avoid complexity.
                debug!("Incomplete headers received, dropping.");
                break;
            }
            Err(_) => {
                break;
            }
        }
    }

    Ok(())
}

fn should_keep_alive(req: &[u8]) -> bool {
    req.windows(17).any(|w| w.eq_ignore_ascii_case(b"connection: keep-"))
        || req.windows(10).any(|w| w == b"keep-alive")
}

async fn handle_direct_http(
    request: &[u8],
    client: &mut TcpStream,
    stats: &Arc<Stats>,
) -> anyhow::Result<bool> {
    if request.len() < 13 {
        return Ok(false);
    }

    // Fast path for internal checks
    if !request.starts_with(b"GET ") {
        return Ok(false);
    }

    let is_health = request.len() >= 14 && &request[4..14] == b"/health HT";
    let is_bench = request.len() >= 13 && &request[4..13] == b"/bench HT";
    let is_stats = request.len() >= 13 && &request[4..13] == b"/stats HT";

    if !is_health && !is_bench && !is_stats {
        return Ok(false);
    }

    let keepalive = should_keep_alive(request);

    if is_health {
        client.write_all(if keepalive { RESPONSE_HEALTH_KEEPALIVE } else { RESPONSE_HEALTH }).await?;
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
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n{}",
            json.len(),
            if keepalive { "keep-alive" } else { "close" },
            json
        );
        client.write_all(resp.as_bytes()).await?;
        return Ok(true);
    }

    Ok(false)
}

fn parse_http_request(
    buf: &[u8],
) -> anyhow::Result<Option<(String, String, Vec<(String, String)>)>> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    match req.parse(buf) {
        Ok(httparse::Status::Complete(_)) => {
            let method = req.method.unwrap_or("").to_string();
            let path = req.path.unwrap_or("").to_string();
            let headers = req.headers.iter()
                .filter(|h| !h.name.is_empty())
                .map(|h| (
                    h.name.to_ascii_lowercase(),
                    String::from_utf8_lossy(h.value).to_string()
                ))
                .collect();
            Ok(Some((method, path, headers)))
        },
        Ok(httparse::Status::Partial) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

async fn handle_connect(
    mut client: TcpStream,
    target: &str,
    config: &ProxyConfig,
) -> anyhow::Result<()> {
    let (host, port) = if let Some((h, p)) = target.rsplit_once(':') {
        (h, p.parse::<u16>().unwrap_or(443))
    } else {
        (target, 443)
    };

    if config.filter.is_blacklisted(host) {
        config.stats.blocked.fetch_add(1, Ordering::Relaxed);
        debug!("Blocked CONNECT: {}", host);
        let _ = client.write_all(RESPONSE_403).await;
        return Ok(());
    }

    // 1. Reply 200 to Client
    client.write_all(RESPONSE_200_CONNECT).await?;
    // Ensure the 200 OK is sent before we start connecting to upstream,
    // though some proxies wait. Standard is to establish upstream first, then 200.

    // Connect upstream
    let server_connect = match config.connect_timeout {
        Some(to) => timeout(to, TcpStream::connect((host, port))).await.map_err(|_| anyhow::anyhow!("Timeout"))?,
        None => TcpStream::connect((host, port)).await,
    };

    let mut server = match server_connect {
        Ok(s) => s,
        Err(e) => {
            // If we failed to connect upstream, we already sent 200 OK, which is problematic.
            // ideally we connect first, then send 200. But if we connect first, we might verify
            // an SNI that isn't there yet.
            warn!("Failed to connect to upstream {}: {}", target, e);
            return Err(e.into());
        }
    };

    let _ = server.set_nodelay(true);

    // Check whitelist for fragmentation
    let should_fragment = !config.filter.is_whitelisted(host);
    if !should_fragment {
        config.stats.whitelisted.fetch_add(1, Ordering::Relaxed);
    } else {
        // Try to fragment the TLS handshake
        let _ = fragment_tls_handshake(&mut client, &mut server, &config.stats).await;
    }

    // Tunnel
    let copy = match config.idle_timeout {
        Some(to) => timeout(to, tokio::io::copy_bidirectional(&mut client, &mut server)).await,
        None => Ok(tokio::io::copy_bidirectional(&mut client, &mut server).await),
    };

    if let Ok(Ok((a, b))) = copy {
        config.stats.bytes_out.fetch_add(a, Ordering::Relaxed);
        config.stats.bytes_in.fetch_add(b, Ordering::Relaxed);
    }

    Ok(())
}

async fn handle_http(
    mut client: TcpStream,
    headers: Vec<(String, String)>,
    initial_data: &[u8],
    config: &ProxyConfig,
) -> anyhow::Result<()> {
    let host = headers.iter()
        .find(|(k, _)| k == "host")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    if host.is_empty() {
        let _ = client.write_all(RESPONSE_400).await;
        return Ok(());
    }

    let (host_name, port) = if let Some((h, p)) = host.rsplit_once(':') {
        (h, p.parse::<u16>().unwrap_or(80))
    } else {
        (host, 80)
    };

    if config.filter.is_blacklisted(host_name) {
        config.stats.blocked.fetch_add(1, Ordering::Relaxed);
        debug!("Blocked HTTP: {}", host_name);
        let _ = client.write_all(RESPONSE_403).await;
        return Ok(());
    }

    let mut server = match config.connect_timeout {
        Some(to) => timeout(to, TcpStream::connect((host_name, port))).await.map_err(|_| anyhow::anyhow!("Timeout"))?,
        None => TcpStream::connect((host_name, port)).await,
    }?;

    let _ = server.set_nodelay(true);
    let _ = server.write_all(initial_data).await;

    let copy = match config.idle_timeout {
        Some(to) => timeout(to, tokio::io::copy_bidirectional(&mut client, &mut server)).await,
        None => Ok(tokio::io::copy_bidirectional(&mut client, &mut server).await),
    };

    if let Ok(Ok((a, b))) = copy {
        config.stats.bytes_out.fetch_add(a, Ordering::Relaxed);
        config.stats.bytes_in.fetch_add(b, Ordering::Relaxed);
    }

    Ok(())
}

async fn fragment_tls_handshake(
    client: &mut TcpStream,
    server: &mut TcpStream,
    stats: &Arc<Stats>,
) -> anyhow::Result<()> {
    let mut header = [0u8; 5];
    let mut body = vec![0u8; MAX_TLS_RECORD_SIZE];

    // Read header with timeout
    if timeout(Duration::from_secs(5), client.read_exact(&mut header)).await.is_err() {
        return Ok(());
    }

    // Validate TLS Handshake (Content Type 22 (0x16), Version 3.1-3.3)
    if header[0] != 0x16 || header[1] != 0x03 || (header[2] < 0x01 || header[2] > 0x03) {
        let _ = server.write_all(&header).await;
        return Ok(());
    }

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if record_len > MAX_TLS_RECORD_SIZE || record_len == 0 {
        let _ = server.write_all(&header).await;
        return Ok(());
    }

    // Read full body
    if timeout(Duration::from_secs(5), client.read_exact(&mut body[..record_len])).await.is_err() {
        // If we fail to read the full body, we can't fragment.
        // We can try to forward what we read, but state is messy. Just drop.
        return Ok(());
    }

    let body_slice = &body[..record_len];
    stats.fragmented.fetch_add(1, Ordering::Relaxed);

    let mut rng = OsRng;
    let strategy = rng.next_u32() % 100;

    // Determine cut points
    let fragments: Vec<usize> = if strategy < 60 {
        // Split into 2: small random start, rest
        let first = (rng.next_u32() as usize % 8) + 1;
        let first = first.min(record_len);
        vec![first, record_len - first]
    } else if strategy < 90 {
        // Split into 3
        let p1 = (rng.next_u32() as usize % 12) + 1;
        let p1 = p1.min(record_len);
        let remaining = record_len - p1;
        let p2 = if remaining > 0 { (rng.next_u32() as usize % 80) + 20 } else { 0 };
        let p2 = p2.min(remaining);
        vec![p1, p2, remaining - p2]
    } else {
        // Tiny first byte
        if record_len > 1 {
            vec![1, record_len - 1]
        } else {
            vec![record_len]
        }
    };

    let mut pos = 0;
    for (i, &size) in fragments.iter().enumerate() {
        if size == 0 { continue; }

        let chunk = &body_slice[pos..pos + size];
        pos += size;

        let mut frag_header = [0u8; 5];
        frag_header[0] = 0x16;
        frag_header[1] = header[1];
        frag_header[2] = header[2];
        frag_header[3..5].copy_from_slice(&(chunk.len() as u16).to_be_bytes());

        server.write_all(&frag_header).await?;
        server.write_all(chunk).await?;
        server.flush().await?;

        if i == 0 {
            let delay_ms = if size <= 4 {
                rng.next_u32() % 70 + 20
            } else {
                rng.next_u32() % 40 + 5
            };
            tokio::time::sleep(Duration::from_millis(delay_ms as u64)).await;
        }
    }

    Ok(())
}