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
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

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
            "STATS | total={} active={} blocked={} whitelisted={} fragmented={} failed={} in={}MB out={}MB",
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
        info!("Loading blacklist from {:?}", path);
        filter.load_blacklist(path)?;
    }
    if let Some(ref path) = args.whitelist {
        info!("Loading whitelist from {:?}", path);
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
            error!("Port {} is already in use.", args.port);
            std::process::exit(1);
        }
        Err(e) => return Err(e.into()),
    }

    // OPTIMIZATION: Increased backlog to handle high concurrency benchmarks
    socket.listen(4096)?;
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
            let _guard = ConnectionGuard::new(config.stats.clone());

            if let Err(e) = handle_connection(client_stream, config.clone()).await {
                if e.downcast_ref::<std::io::Error>().map_or(true, |io_e| io_e.kind() != ErrorKind::UnexpectedEof) {
                    debug!("Connection error from {}: {}", client_addr, e);
                    config.stats.failed.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }
}

#[tracing::instrument(skip(client, config))]
async fn handle_connection(
    mut client: TcpStream,
    config: ProxyConfig
) -> anyhow::Result<()> {
    let _ = client.set_nodelay(true);
    let peer_addr = client.peer_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());

    let mut keepalive_count = 0usize;

    // Buffer management for pipelining and partial reads
    let mut buf = [0u8; MAX_HEADER_SIZE];
    let mut pos = 0;

    loop {
        // 1. Read data into buffer
        let read_timeout = if keepalive_count == 0 { Duration::from_secs(5) } else { Duration::from_secs(2) };

        // Only read if we don't have a full request yet
        // We try to parse what we have first (pipelining support)
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        let status = req.parse(&buf[..pos]);

        match status {
            Ok(httparse::Status::Complete(parsed_len)) => {
                // We have a full header!
                let method = req.method.unwrap_or("").to_string();
                let path = req.path.unwrap_or("").to_string();
                let headers_vec: Vec<(String, String)> = req.headers.iter()
                    .filter(|h| !h.name.is_empty())
                    .map(|h| (h.name.to_ascii_lowercase(), String::from_utf8_lossy(h.value).to_string()))
                    .collect();

                let current_slice = &buf[..parsed_len];

                // Handle Internal Endpoints
                if handle_direct_http(current_slice, &mut client, &config.stats).await? {
                    if !should_keep_alive(current_slice) || keepalive_count >= MAX_KEEPALIVE {
                        break;
                    }
                    keepalive_count += 1;

                    // Advance buffer: shift remaining data to start
                    if parsed_len < pos {
                        buf.copy_within(parsed_len..pos, 0);
                        pos -= parsed_len;
                    } else {
                        pos = 0;
                    }
                    continue;
                }

                // Handle Proxying
                debug!(method = %method, path = %path, client = %peer_addr, "Parsed Request");

                if method == "CONNECT" {
                    handle_connect(client, &path, &config).await?;
                    return Ok(()); // CONNECT takes over socket
                } else {
                    // For HTTP forwarding, we need to send the bytes we already read
                    handle_http(client, headers_vec, current_slice, &config).await?;
                    return Ok(());
                }
            }
            Ok(httparse::Status::Partial) => {
                // Need more data
                if pos >= MAX_HEADER_SIZE {
                    return Err(anyhow::anyhow!("Header too large"));
                }

                // FIXED MATCH BLOCK BELOW
                match timeout(read_timeout, client.read(&mut buf[pos..])).await {
                    Ok(Ok(0)) => break, // EOF - Closed by peer
                    Ok(Ok(n)) => {
                        pos += n;
                        continue; // Loop back to try parsing again
                    },
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) => break, // Timeout
                }
            }
            Err(e) => return Err(e.into()),
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
        warn!("BLOCKED CONNECT: {}", host);
        let _ = client.write_all(RESPONSE_403).await;
        return Ok(());
    }

    client.write_all(RESPONSE_200_CONNECT).await?;

    let start = Instant::now();
    let server_connect = match config.connect_timeout {
        Some(to) => timeout(to, TcpStream::connect((host, port))).await.map_err(|_| anyhow::anyhow!("Timeout"))?,
        None => TcpStream::connect((host, port)).await,
    };

    let mut server = match server_connect {
        Ok(s) => {
            debug!("Connected to upstream {}:{} in {:.2?}", host, port, start.elapsed());
            s
        },
        Err(e) => {
            warn!("Failed to connect to upstream {}:{}: {}", host, port, e);
            return Err(e.into());
        }
    };

    let _ = server.set_nodelay(true);

    let should_fragment = !config.filter.is_whitelisted(host);
    if !should_fragment {
        config.stats.whitelisted.fetch_add(1, Ordering::Relaxed);
    } else {
        trace!("Applying fragmentation to {}", host);
        let _ = fragment_tls_handshake(&mut client, &mut server, &config.stats).await;
    }

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
        warn!("BLOCKED HTTP: {}", host_name);
        let _ = client.write_all(RESPONSE_403).await;
        return Ok(());
    }

    let start = Instant::now();
    let mut server = match config.connect_timeout {
        Some(to) => timeout(to, TcpStream::connect((host_name, port))).await.map_err(|_| anyhow::anyhow!("Timeout"))?,
        None => TcpStream::connect((host_name, port)).await,
    }?;

    debug!("Connected to HTTP upstream {}:{} in {:.2?}", host_name, port, start.elapsed());

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

    if timeout(Duration::from_secs(5), client.read_exact(&mut header)).await.is_err() {
        return Ok(());
    }

    if header[0] != 0x16 || header[1] != 0x03 || (header[2] < 0x01 || header[2] > 0x03) {
        trace!("Not a standard TLS ClientHello, forwarding directly");
        let _ = server.write_all(&header).await;
        return Ok(());
    }

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if record_len > MAX_TLS_RECORD_SIZE || record_len == 0 {
        let _ = server.write_all(&header).await;
        return Ok(());
    }

    if timeout(Duration::from_secs(5), client.read_exact(&mut body[..record_len])).await.is_err() {
        return Ok(());
    }

    let body_slice = &body[..record_len];
    stats.fragmented.fetch_add(1, Ordering::Relaxed);

    let mut rng = OsRng;
    let strategy = rng.next_u32() % 100;

    let fragments: Vec<usize> = if strategy < 60 {
        let first = (rng.next_u32() as usize % 8) + 1;
        let first = first.min(record_len);
        vec![first, record_len - first]
    } else if strategy < 90 {
        let p1 = (rng.next_u32() as usize % 12) + 1;
        let p1 = p1.min(record_len);
        let remaining = record_len - p1;
        let p2 = if remaining > 0 { (rng.next_u32() as usize % 80) + 20 } else { 0 };
        let p2 = p2.min(remaining);
        vec![p1, p2, remaining - p2]
    } else {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_keep_alive() {
        let case1 = b"GET / HTTP/1.1\r\nHost: foo\r\nConnection: keep-alive\r\n\r\n";
        assert!(should_keep_alive(case1));

        let case2 = b"GET / HTTP/1.1\r\nHost: foo\r\nConnection: close\r\n\r\n";
        assert!(!should_keep_alive(case2));
    }

    #[test]
    fn test_stats_increment() {
        let stats = Arc::new(Stats::new());
        let _guard = ConnectionGuard::new(stats.clone());
        assert_eq!(stats.active.load(Ordering::Relaxed), 1);
        assert_eq!(stats.total.load(Ordering::Relaxed), 1);
        drop(_guard);
        assert_eq!(stats.active.load(Ordering::Relaxed), 0);
        assert_eq!(stats.total.load(Ordering::Relaxed), 1);
    }
}