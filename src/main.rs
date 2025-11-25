#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::similar_names, clippy::module_name_repetitions)]

mod domain_filter;

use crate::domain_filter::DomainFilter;
use anyhow::{Context, Result};
use clap::Parser;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use socket2::{Domain, Protocol, Socket, Type};
use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

// ============================================================================
// Constants
// ============================================================================

const MAX_TLS_RECORD_SIZE: usize = 16384;
const MAX_KEEPALIVE: usize = 100;
const MAX_HEADER_SIZE: usize = 8192;
const DEFAULT_MAX_CONNECTIONS: usize = 10000;
const DRAIN_TIMEOUT_SECS: u64 = 30;
const GRACE_PERIOD_SECS: u64 = 5;

// Pre-computed HTTP responses (optimized for common cases)
const RESPONSE_BENCH: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/plain\r\n\
Content-Length: 2\r\n\
Connection: keep-alive\r\n\r\nOK";

const RESPONSE_HEALTH: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/plain\r\n\
Content-Length: 2\r\n\
Connection: close\r\n\r\nOK";

const RESPONSE_HEALTH_KEEPALIVE: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/plain\r\n\
Content-Length: 2\r\n\
Connection: keep-alive\r\n\r\nOK";

const RESPONSE_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\r\n";

const RESPONSE_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\r\n";

const RESPONSE_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\r\n";

const RESPONSE_503: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\r\n";

const RESPONSE_200_CONNECT: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

// ============================================================================
// CLI Arguments
// ============================================================================

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "High-performance HTTPS proxy with TLS fragmentation")]
struct Args {
    /// Bind address
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// Bind port
    #[arg(long, default_value_t = 8101)]
    port: u16,

    /// Path to blacklist file
    #[arg(long)]
    blacklist: Option<PathBuf>,

    /// Path to whitelist file (domains that won't be fragmented)
    #[arg(long)]
    whitelist: Option<PathBuf>,

    /// Connection timeout in seconds (0 = no timeout)
    #[arg(long, default_value_t = 10)]
    timeout_connect: u64,

    /// Idle timeout in seconds (0 = no timeout)
    #[arg(long, default_value_t = 60)]
    timeout_idle: u64,

    /// Stats logging interval in seconds (0 = disabled)
    #[arg(long, default_value_t = 60)]
    stats_interval: u64,

    /// Maximum concurrent connections
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS)]
    max_connections: usize,

    /// Drain timeout in seconds during shutdown
    #[arg(long, default_value_t = DRAIN_TIMEOUT_SECS)]
    drain_timeout: u64,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

// ============================================================================
// Statistics
// ============================================================================

#[derive(Debug, Default)]
struct Stats {
    total: AtomicU64,
    active: AtomicU64,
    blocked: AtomicU64,
    whitelisted: AtomicU64,
    fragmented: AtomicU64,
    failed: AtomicU64,
    rejected: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn inc_total(&self) {
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_active(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn dec_active(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_blocked(&self) {
        self.blocked.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_whitelisted(&self) {
        self.whitelisted.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_fragmented(&self) {
        self.fragmented.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn inc_rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn add_bytes(&self, bytes_in: u64, bytes_out: u64) {
        self.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
    }

    #[inline]
    fn active_count(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            total: self.total.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            whitelisted: self.whitelisted.load(Ordering::Relaxed),
            fragmented: self.fragmented.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct StatsSnapshot {
    total: u64,
    active: u64,
    blocked: u64,
    whitelisted: u64,
    fragmented: u64,
    failed: u64,
    rejected: u64,
    bytes_in: u64,
    bytes_out: u64,
}

impl StatsSnapshot {
    fn log(&self) {
        info!(
            "STATS | total={} active={} blocked={} whitelisted={} fragmented={} failed={} rejected={} in={}MB out={}MB",
            self.total,
            self.active,
            self.blocked,
            self.whitelisted,
            self.fragmented,
            self.failed,
            self.rejected,
            self.bytes_in / 1_000_000,
            self.bytes_out / 1_000_000,
        );
    }

    fn to_json(&self) -> String {
        format!(
            r#"{{"total":{},"active":{},"blocked":{},"whitelisted":{},"fragmented":{},"failed":{},"rejected":{},"bytes_in":{},"bytes_out":{}}}"#,
            self.total,
            self.active,
            self.blocked,
            self.whitelisted,
            self.fragmented,
            self.failed,
            self.rejected,
            self.bytes_in,
            self.bytes_out,
        )
    }
}

// ============================================================================
// Connection Guard (RAII for stats)
// ============================================================================

struct ConnectionGuard {
    stats: Arc<Stats>,
}

impl ConnectionGuard {
    #[inline]
    fn new(stats: Arc<Stats>) -> Self {
        stats.inc_active();
        stats.inc_total();
        Self { stats }
    }
}

impl Drop for ConnectionGuard {
    #[inline]
    fn drop(&mut self) {
        self.stats.dec_active();
    }
}

// ============================================================================
// Proxy Configuration
// ============================================================================

#[derive(Clone)]
struct ProxyConfig {
    filter: Arc<DomainFilter>,
    stats: Arc<Stats>,
    connect_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
}

impl ProxyConfig {
    fn new(filter: Arc<DomainFilter>, stats: Arc<Stats>, args: &Args) -> Self {
        let connect_timeout =
            (args.timeout_connect > 0).then(|| Duration::from_secs(args.timeout_connect));
        let idle_timeout =
            (args.timeout_idle > 0).then(|| Duration::from_secs(args.timeout_idle));

        Self {
            filter,
            stats,
            connect_timeout,
            idle_timeout,
        }
    }

    /// Thread-local RNG for zero-contention random number generation
    #[inline]
    fn random_u32(&self) -> u32 {
        thread_local! {
            static RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_os_rng());
        }
        RNG.with(|rng| rng.borrow_mut().random())
    }
}

// ============================================================================
// Shutdown Signal Handler
// ============================================================================

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!("Received Ctrl+C"),
        () = terminate => info!("Received SIGTERM"),
    }
}

async fn wait_for_drain(stats: &Stats, timeout_duration: Duration) -> bool {
    let drain_start = Instant::now();

    while stats.active_count() > 0 {
        if drain_start.elapsed() > timeout_duration {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    true
}

// ============================================================================
// Main Entry Point
// ============================================================================

fn main() -> Result<()> {
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
        .worker_threads(num_cpus::get().saturating_mul(2).max(4))
        .thread_stack_size(2 * 1024 * 1024)
        .enable_all()
        .build()
        .context("Failed to build Tokio runtime")?;

    runtime.block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
    let filter = Arc::new(DomainFilter::new());

    if let Some(ref path) = args.blacklist {
        info!("Loading blacklist from {:?}", path);
        filter
            .load_blacklist(path)
            .with_context(|| format!("Failed to load blacklist from {:?}", path))?;
    }

    if let Some(ref path) = args.whitelist {
        info!("Loading whitelist from {:?}", path);
        filter
            .load_whitelist(path)
            .with_context(|| format!("Failed to load whitelist from {:?}", path))?;
    }

    let filter_stats = filter.stats();
    if filter_stats.total() > 0 {
        info!(
            "Filter loaded: {} blacklist rules ({} exact, {} suffix), {} whitelist rules ({} exact, {} suffix)",
            filter_stats.blacklist_exact + filter_stats.blacklist_suffix,
            filter_stats.blacklist_exact,
            filter_stats.blacklist_suffix,
            filter_stats.whitelist_exact + filter_stats.whitelist_suffix,
            filter_stats.whitelist_exact,
            filter_stats.whitelist_suffix,
        );
    }

    let stats = Arc::new(Stats::new());
    let config = ProxyConfig::new(filter, stats.clone(), &args);

    let cancel_token = CancellationToken::new();

    if args.stats_interval > 0 {
        let stats_clone = stats.clone();
        let cancel = cancel_token.clone();
        let interval = Duration::from_secs(args.stats_interval);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    _ = ticker.tick() => stats_clone.snapshot().log(),
                }
            }
            debug!("Stats logging task stopped");
        });
    }

    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .context("Invalid bind address")?;

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .context("Failed to create socket")?;
    socket
        .set_reuse_address(true)
        .context("Failed to set SO_REUSEADDR")?;

    // Try to set reuse_port (Linux-specific, ignore errors on other platforms)
    #[cfg(unix)]
    let _ = socket.set_reuse_port(true);

    socket
        .set_nonblocking(true)
        .context("Failed to set non-blocking")?;

    // TCP optimizations
    let _ = socket.set_tcp_nodelay(true);
    let _ = socket.set_recv_buffer_size(256 * 1024);
    let _ = socket.set_send_buffer_size(256 * 1024);

    if let Err(e) = socket.bind(&addr.into()) {
        if e.kind() == ErrorKind::AddrInUse {
            error!("Port {} is already in use", args.port);
            std::process::exit(1);
        }
        return Err(e).context("Failed to bind socket");
    }

    socket.listen(4096).context("Failed to listen on socket")?;
    let listener = TcpListener::from_std(socket.into())?;

    info!("Proxy listening on http://{}", addr);
    info!(
        "Max connections: {}, Connect timeout: {:?}, Idle timeout: {:?}",
        args.max_connections, config.connect_timeout, config.idle_timeout
    );

    let shutdown_token = cancel_token.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        info!("Shutdown signal received, stopping new connections...");
        shutdown_token.cancel();
    });

    let semaphore = Arc::new(Semaphore::new(args.max_connections));
    let drain_timeout = Duration::from_secs(args.drain_timeout);

    loop {
        tokio::select! {
            biased;

            () = cancel_token.cancelled() => {
                let active = stats.active_count();
                if active > 0 {
                    info!("Waiting for {} active connections to finish...", active);
                }
                break;
            }

            accept_result = listener.accept() => {
                let (client_stream, client_addr) = accept_result?;

                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        stats.inc_rejected();
                        warn!("Connection limit reached, rejecting {}", client_addr);
                        let _ = client_stream.try_write(RESPONSE_503);
                        continue;
                    }
                };

                let config = config.clone();
                let conn_cancel = cancel_token.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    let _guard = ConnectionGuard::new(config.stats.clone());

                    let result = tokio::select! {
                        biased;
                        () = conn_cancel.cancelled() => {
                            debug!("Connection {} entering grace period", client_addr);
                            tokio::time::sleep(Duration::from_secs(GRACE_PERIOD_SECS)).await;
                            Ok(())
                        }
                        r = handle_connection(client_stream, client_addr, config.clone()) => r,
                    };

                    if let Err(e) = result {
                        let is_eof = e
                            .downcast_ref::<std::io::Error>()
                            .map_or(false, |io_e| io_e.kind() == ErrorKind::UnexpectedEof);

                        if !is_eof {
                            debug!("Connection error from {}: {:#}", client_addr, e);
                            config.stats.inc_failed();
                        }
                    }
                });
            }
        }
    }

    if stats.active_count() > 0 {
        if wait_for_drain(&stats, drain_timeout).await {
            info!("All connections drained successfully");
        } else {
            warn!(
                "Drain timeout reached, {} connections still active",
                stats.active_count()
            );
        }
    }

    info!("Shutdown complete");
    stats.snapshot().log();

    Ok(())
}

// ============================================================================
// Connection Handler
// ============================================================================

async fn handle_connection(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    config: ProxyConfig,
) -> Result<()> {
    let _ = client.set_nodelay(true);

    let mut buf = [0u8; MAX_HEADER_SIZE];
    let mut pos = 0usize;
    let mut keepalive_count = 0usize;

    loop {
        let read_timeout = if keepalive_count == 0 {
            Duration::from_secs(5)
        } else {
            Duration::from_secs(2)
        };

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(&buf[..pos]) {
            Ok(httparse::Status::Complete(parsed_len)) => {
                let method = req.method.unwrap_or("");
                let path = req.path.unwrap_or("");

                // Fast path for internal endpoints
                if let Some(handled) =
                    handle_internal_endpoint(&buf[..parsed_len], &mut client, &config).await?
                {
                    if !handled || keepalive_count >= MAX_KEEPALIVE {
                        break;
                    }
                    keepalive_count += 1;
                    shift_buffer(&mut buf, &mut pos, parsed_len);
                    continue;
                }

                debug!(
                    method = %method,
                    path = %path,
                    client = %peer_addr,
                    "Processing request"
                );

                return if method.eq_ignore_ascii_case("CONNECT") {
                    handle_connect(client, path, &config).await
                } else {
                    let headers_vec = extract_headers(&req);
                    handle_http(client, headers_vec, &buf[..parsed_len], &config).await
                };
            }
            Ok(httparse::Status::Partial) => {
                if pos >= MAX_HEADER_SIZE {
                    warn!("Header too large from {}", peer_addr);
                    let _ = client.write_all(RESPONSE_400).await;
                    return Ok(());
                }

                match timeout(read_timeout, client.read(&mut buf[pos..])).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        pos += n;
                        continue;
                    }
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) => break,
                }
            }
            Err(e) => {
                debug!("Parse error from {}: {}", peer_addr, e);
                let _ = client.write_all(RESPONSE_400).await;
                return Ok(());
            }
        }
    }

    Ok(())
}

#[inline]
fn shift_buffer(buf: &mut [u8], pos: &mut usize, consumed: usize) {
    if consumed < *pos {
        buf.copy_within(consumed..*pos, 0);
        *pos -= consumed;
    } else {
        *pos = 0;
    }
}

#[inline]
fn extract_headers(req: &httparse::Request<'_, '_>) -> Vec<(String, String)> {
    req.headers
        .iter()
        .filter(|h| !h.name.is_empty())
        .map(|h| {
            (
                h.name.to_ascii_lowercase(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect()
}

// ============================================================================
// Keep-Alive Detection (Optimized)
// ============================================================================

#[inline]
fn should_keep_alive(request: &[u8]) -> bool {
    // Find end of first line to locate HTTP version
    let first_line_end = request
        .iter()
        .position(|&b| b == b'\r')
        .unwrap_or(request.len());

    // Check for HTTP/1.1 (default keep-alive)
    if first_line_end >= 8 {
        let check_start = first_line_end.saturating_sub(8);
        if request[check_start..first_line_end].eq_ignore_ascii_case(b"HTTP/1.1") {
            // HTTP/1.1: keep-alive unless "Connection: close"
            return !contains_header_value(request, b"close");
        }
    }

    // HTTP/1.0 or unknown: only keep-alive if explicitly requested
    contains_header_value(request, b"keep-alive")
}

#[inline]
fn contains_header_value(request: &[u8], value: &[u8]) -> bool {
    // Look for "Connection:" header
    let conn_header = b"connection:";

    for i in 0..request.len().saturating_sub(conn_header.len()) {
        if request[i..].len() >= conn_header.len()
            && request[i..i + conn_header.len()].eq_ignore_ascii_case(conn_header)
        {
            // Find end of header line
            let start = i + conn_header.len();
            let end = request[start..]
                .iter()
                .position(|&b| b == b'\r' || b == b'\n')
                .map(|p| start + p)
                .unwrap_or(request.len());

            // Check if value exists in header
            return request[start..end]
                .windows(value.len())
                .any(|w| w.eq_ignore_ascii_case(value));
        }
    }
    false
}

// ============================================================================
// Internal Endpoints (Optimized for /bench)
// ============================================================================

async fn handle_internal_endpoint(
    request: &[u8],
    client: &mut TcpStream,
    config: &ProxyConfig,
) -> Result<Option<bool>> {
    // Minimum: "GET /x HTTP/1.1\r\n" = 16 bytes
    if request.len() < 14 {
        return Ok(None);
    }

    // Fast check for "GET /"
    if &request[0..5] != b"GET /" {
        return Ok(None);
    }

    // Ultra-fast path for /bench (most common in benchmarks)
    if request.len() >= 11 && &request[5..10] == b"bench" && (request[10] == b' ' || request[10] == b'\r') {
        client.write_all(RESPONSE_BENCH).await?;
        return Ok(Some(true));
    }

    // Fast path for /health
    if request.len() >= 12 && &request[5..11] == b"health" && (request[11] == b' ' || request[11] == b'\r') {
        let keepalive = should_keep_alive(request);
        let response = if keepalive {
            RESPONSE_HEALTH_KEEPALIVE
        } else {
            RESPONSE_HEALTH
        };
        client.write_all(response).await?;
        return Ok(Some(keepalive));
    }

    // Extract path for other endpoints
    let path_end = request[5..]
        .iter()
        .position(|&b| b == b' ' || b == b'\r')
        .map(|p| 5 + p)
        .unwrap_or(request.len());

    let path = &request[4..path_end];
    let keepalive = should_keep_alive(request);

    match path {
        b"/stats" => {
            let json = config.stats.snapshot().to_json();
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: {}\r\n\r\n{}",
                json.len(),
                if keepalive { "keep-alive" } else { "close" },
                json
            );
            client.write_all(response.as_bytes()).await?;
            Ok(Some(keepalive))
        }
        b"/filter-stats" => {
            let fs = config.filter.stats();
            let json = format!(
                r#"{{"blacklist_exact":{},"blacklist_suffix":{},"whitelist_exact":{},"whitelist_suffix":{},"total":{}}}"#,
                fs.blacklist_exact,
                fs.blacklist_suffix,
                fs.whitelist_exact,
                fs.whitelist_suffix,
                fs.total()
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: {}\r\n\r\n{}",
                json.len(),
                if keepalive { "keep-alive" } else { "close" },
                json
            );
            client.write_all(response.as_bytes()).await?;
            Ok(Some(keepalive))
        }
        _ => Ok(None),
    }
}

// ============================================================================
// Host Parsing (IPv6 aware)
// ============================================================================

#[inline]
fn parse_host_port(target: &str, default_port: u16) -> (&str, u16) {
    if target.starts_with('[') {
        if let Some(bracket_end) = target.find(']') {
            let host = &target[1..bracket_end];
            let port = target
                .get(bracket_end + 1..)
                .and_then(|s| s.strip_prefix(':'))
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (host, port);
        }
    }

    if let Some((host, port_str)) = target.rsplit_once(':') {
        if !host.contains(':') {
            if let Ok(port) = port_str.parse() {
                return (host, port);
            }
        }
    }

    (target, default_port)
}

// ============================================================================
// CONNECT Handler
// ============================================================================

async fn handle_connect(mut client: TcpStream, target: &str, config: &ProxyConfig) -> Result<()> {
    let (host, port) = parse_host_port(target, 443);

    if config.filter.is_blacklisted(host) {
        config.stats.inc_blocked();
        warn!(host = %host, "BLOCKED CONNECT");
        let _ = client.write_all(RESPONSE_403).await;
        return Ok(());
    }

    let start = Instant::now();
    let server_result = match config.connect_timeout {
        Some(to) => timeout(to, TcpStream::connect((host, port)))
            .await
            .map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "Connection timeout"))?,
        None => TcpStream::connect((host, port)).await,
    };

    let mut server = match server_result {
        Ok(s) => {
            debug!(
                host = %host,
                port = %port,
                elapsed = ?start.elapsed(),
                "Connected to upstream"
            );
            s
        }
        Err(e) => {
            warn!(host = %host, port = %port, error = %e, "Upstream connection failed");
            let _ = client.write_all(RESPONSE_502).await;
            return Ok(());
        }
    };

    client.write_all(RESPONSE_200_CONNECT).await?;

    let _ = server.set_nodelay(true);

    let should_fragment = !config.filter.is_whitelisted(host);
    if should_fragment {
        trace!(host = %host, "Applying TLS fragmentation");
        if let Err(e) = fragment_tls_handshake(&mut client, &mut server, config).await {
            debug!(host = %host, error = %e, "Fragmentation error");
        }
    } else {
        config.stats.inc_whitelisted();
    }

    let result = match config.idle_timeout {
        Some(to) => timeout(to, tokio::io::copy_bidirectional(&mut client, &mut server)).await,
        None => Ok(tokio::io::copy_bidirectional(&mut client, &mut server).await),
    };

    if let Ok(Ok((client_to_server, server_to_client))) = result {
        config.stats.add_bytes(server_to_client, client_to_server);
    }

    Ok(())
}

// ============================================================================
// HTTP Handler
// ============================================================================

async fn handle_http(
    mut client: TcpStream,
    headers: Vec<(String, String)>,
    initial_data: &[u8],
    config: &ProxyConfig,
) -> Result<()> {
    let host_header = headers
        .iter()
        .find(|(k, _)| k == "host")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    if host_header.is_empty() {
        let _ = client.write_all(RESPONSE_400).await;
        return Ok(());
    }

    let (host, port) = parse_host_port(host_header, 80);

    if config.filter.is_blacklisted(host) {
        config.stats.inc_blocked();
        warn!(host = %host, "BLOCKED HTTP");
        let _ = client.write_all(RESPONSE_403).await;
        return Ok(());
    }

    let start = Instant::now();
    let server_result = match config.connect_timeout {
        Some(to) => timeout(to, TcpStream::connect((host, port)))
            .await
            .map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "Connection timeout"))?,
        None => TcpStream::connect((host, port)).await,
    };

    let mut server = match server_result {
        Ok(s) => {
            debug!(
                host = %host,
                port = %port,
                elapsed = ?start.elapsed(),
                "Connected to HTTP upstream"
            );
            s
        }
        Err(e) => {
            warn!(host = %host, port = %port, error = %e, "HTTP upstream connection failed");
            let _ = client.write_all(RESPONSE_502).await;
            return Ok(());
        }
    };

    let _ = server.set_nodelay(true);

    server.write_all(initial_data).await?;

    let result = match config.idle_timeout {
        Some(to) => timeout(to, tokio::io::copy_bidirectional(&mut client, &mut server)).await,
        None => Ok(tokio::io::copy_bidirectional(&mut client, &mut server).await),
    };

    if let Ok(Ok((client_to_server, server_to_client))) = result {
        config.stats.add_bytes(server_to_client, client_to_server);
    }

    Ok(())
}

// ============================================================================
// TLS Fragmentation
// ============================================================================

async fn fragment_tls_handshake(
    client: &mut TcpStream,
    server: &mut TcpStream,
    config: &ProxyConfig,
) -> Result<()> {
    let mut header = [0u8; 5];

    match timeout(Duration::from_secs(5), client.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()),
    }

    // Validate TLS record: 0x16 = Handshake, 0x03 0x0X = TLS version
    if header[0] != 0x16 || header[1] != 0x03 || header[2] > 0x03 {
        trace!("Non-TLS or unsupported record, forwarding directly");
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
            let _ = server.write_all(&header).await;
            return Err(e.into());
        }
        Err(_) => {
            let _ = server.write_all(&header).await;
            return Ok(());
        }
    }

    config.stats.inc_fragmented();

    let fragments = generate_fragment_sizes(record_len, config);

    let mut pos = 0;
    for (i, size) in fragments.iter().enumerate() {
        if *size == 0 {
            continue;
        }

        let chunk = &body[pos..pos + size];
        pos += size;

        let frag_header = [
            0x16,
            header[1],
            header[2],
            (chunk.len() >> 8) as u8,
            (chunk.len() & 0xFF) as u8,
        ];

        server.write_all(&frag_header).await?;
        server.write_all(chunk).await?;
        server.flush().await?;

        if i == 0 && fragments.len() > 1 {
            let delay_ms = if *size <= 4 {
                (config.random_u32() % 70 + 20) as u64
            } else {
                (config.random_u32() % 40 + 5) as u64
            };
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
    }

    Ok(())
}

#[inline]
fn generate_fragment_sizes(record_len: usize, config: &ProxyConfig) -> Vec<usize> {
    let strategy = config.random_u32() % 100;

    if strategy < 60 {
        let first = ((config.random_u32() as usize % 8) + 1).min(record_len);
        vec![first, record_len - first]
    } else if strategy < 90 {
        let p1 = ((config.random_u32() as usize % 12) + 1).min(record_len);
        let remaining = record_len - p1;
        let p2 = if remaining > 0 {
            ((config.random_u32() as usize % 80) + 20).min(remaining)
        } else {
            0
        };
        vec![p1, p2, remaining.saturating_sub(p2)]
    } else {
        if record_len > 1 {
            vec![1, record_len - 1]
        } else {
            vec![record_len]
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_keep_alive_http11() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(should_keep_alive(req));

        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        assert!(!should_keep_alive(req));

        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
        assert!(should_keep_alive(req));
    }

    #[test]
    fn test_should_keep_alive_http10() {
        let req = b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
        assert!(!should_keep_alive(req));

        let req = b"GET / HTTP/1.0\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
        assert!(should_keep_alive(req));
    }

    #[test]
    fn test_parse_host_port() {
        assert_eq!(parse_host_port("example.com", 80), ("example.com", 80));
        assert_eq!(parse_host_port("example.com:8080", 80), ("example.com", 8080));
        assert_eq!(parse_host_port("[::1]:8080", 80), ("::1", 8080));
        assert_eq!(parse_host_port("[::1]", 80), ("::1", 80));
    }

    #[test]
    fn test_stats_snapshot() {
        let stats = Stats::new();
        stats.inc_total();
        stats.inc_active();
        stats.inc_blocked();
        stats.add_bytes(100, 200);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.total, 1);
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.blocked, 1);
        assert_eq!(snapshot.bytes_in, 100);
        assert_eq!(snapshot.bytes_out, 200);
    }

    #[test]
    fn test_fragment_sizes() {
        let config = ProxyConfig {
            filter: Arc::new(DomainFilter::new()),
            stats: Arc::new(Stats::new()),
            connect_timeout: None,
            idle_timeout: None,
        };

        for _ in 0..100 {
            let sizes = generate_fragment_sizes(1000, &config);
            let total: usize = sizes.iter().sum();
            assert_eq!(total, 1000);
        }
    }

    #[test]
    fn test_connection_guard() {
        let stats = Arc::new(Stats::new());
        assert_eq!(stats.active.load(Ordering::Relaxed), 0);

        {
            let _guard = ConnectionGuard::new(stats.clone());
            assert_eq!(stats.active.load(Ordering::Relaxed), 1);
        }

        assert_eq!(stats.active.load(Ordering::Relaxed), 0);
    }
}