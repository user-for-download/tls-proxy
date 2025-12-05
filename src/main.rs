#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::similar_names, clippy::module_name_repetitions)]

mod domain_filter;

use crate::domain_filter::DomainFilter;
use anyhow::{Context, Result};
use clap::Parser;
use parking_lot::Mutex;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use smallvec::SmallVec;
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
const MAX_HEADER_SIZE: usize = 8192;
const DEFAULT_MAX_CONNECTIONS: usize = 10000;
const DRAIN_TIMEOUT_SECS: u64 = 30;
const GRACE_PERIOD_SECS: u64 = 5;
const INITIAL_READ_TIMEOUT_SECS: u64 = 5;
const ACCEPT_ERROR_BACKOFF_MS: u64 = 10;
const BUFFER_POOL_SIZE: usize = 256;
const MAX_HOST_LEN: usize = 253;

// Pre-computed HTTP responses
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
#[command(
    author,
    version,
    about = "High-performance HTTPS proxy with TLS fragmentation"
)]
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

    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS)]
    max_connections: usize,

    #[arg(long, default_value_t = DRAIN_TIMEOUT_SECS)]
    drain_timeout: u64,

    #[arg(long, default_value = "info")]
    log_level: String,

    /// Allow connections to private/internal IP ranges
    #[arg(long, default_value_t = false)]
    allow_private: bool,
}

// ============================================================================
// Buffer Pool
// ============================================================================

struct BufferPool {
    buffers: Mutex<Vec<Vec<u8>>>,
    buffer_size: usize,
}

impl BufferPool {
    fn new(capacity: usize, buffer_size: usize) -> Self {
        Self {
            buffers: Mutex::new(Vec::with_capacity(capacity)),
            buffer_size,
        }
    }

    fn acquire(&self, required_size: usize) -> PooledBuffer<'_> {
        let size = required_size.max(self.buffer_size);
        let mut buf = self
            .buffers
            .lock()
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(size));
        buf.resize(required_size, 0);
        PooledBuffer { buf, pool: self }
    }

    fn release(&self, mut buf: Vec<u8>) {
        buf.clear();
        let mut buffers = self.buffers.lock();
        if buffers.len() < buffers.capacity() {
            buffers.push(buf);
        }
    }
}

struct PooledBuffer<'a> {
    buf: Vec<u8>,
    pool: &'a BufferPool,
}

impl std::ops::Deref for PooledBuffer<'_> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl std::ops::DerefMut for PooledBuffer<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

impl Drop for PooledBuffer<'_> {
    fn drop(&mut self) {
        self.pool.release(std::mem::take(&mut self.buf));
    }
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
        self.active.fetch_add(1, Ordering::Release);
    }

    #[inline]
    fn dec_active(&self) {
        self.active.fetch_sub(1, Ordering::Release);
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
        self.active.load(Ordering::Acquire)
    }

    fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            total: self.total.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Acquire),
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
            "STATS | total={} active={} blocked={} whitelisted={} \
             fragmented={} failed={} rejected={} in={}MB out={}MB",
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

    fn to_string(&self) -> String {
        format!(
            "total={} active={} blocked={} whitelisted={} fragmented={} \
             failed={} rejected={} bytes_in={} bytes_out={}",
            self.total,
            self.active,
            self.blocked,
            self.whitelisted,
            self.fragmented,
            self.failed,
            self.rejected,
            self.bytes_in,
            self.bytes_out
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
    buffer_pool: Arc<BufferPool>,
    connect_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    allow_private: bool,
}

impl ProxyConfig {
    fn new(filter: Arc<DomainFilter>, stats: Arc<Stats>, args: &Args) -> Self {
        let connect_timeout =
            (args.timeout_connect > 0).then(|| Duration::from_secs(args.timeout_connect));
        let idle_timeout = (args.timeout_idle > 0).then(|| Duration::from_secs(args.timeout_idle));

        Self {
            filter,
            stats,
            buffer_pool: Arc::new(BufferPool::new(BUFFER_POOL_SIZE, MAX_TLS_RECORD_SIZE)),
            connect_timeout,
            idle_timeout,
            allow_private: args.allow_private,
        }
    }

    #[inline]
    fn random_u32(&self) -> u32 {
        thread_local! {
            static RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_os_rng());
        }
        RNG.with(|rng| rng.borrow_mut().random())
    }
}

// ============================================================================
// Response Builder
// ============================================================================

#[inline]
fn build_response(status: u16, body: &str, keep_alive: bool) -> String {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Unknown",
    };
    format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: {}\r\n\r\n{}",
        status,
        status_text,
        body.len(),
        if keep_alive { "keep-alive" } else { "close" },
        body
    )
}

// ============================================================================
// Security Helpers
// ============================================================================

/// Check if host is a private/internal address (SSRF protection)
fn is_private_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.octets()[0] == 0
                    || v4.is_broadcast()
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback(),
        };
    }

    host.ends_with(".local") || host.ends_with(".internal") || host.ends_with(".localhost")
}

/// Detect request smuggling indicators
fn has_smuggling_indicators(headers: &[httparse::Header]) -> bool {
    let mut has_content_length = false;
    let mut has_transfer_encoding = false;
    let mut content_length_count = 0;

    for h in headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            content_length_count += 1;
            has_content_length = true;
        }
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            has_transfer_encoding = true;
        }
    }

    content_length_count > 1 || (has_content_length && has_transfer_encoding)
}

/// Validate host header
fn validate_host(host: &str, allow_private: bool) -> bool {
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return false;
    }
    if !allow_private && is_private_host(host) {
        return false;
    }
    true
}

// ============================================================================
// Keep-Alive Detection (optimized with memchr)
// ============================================================================

#[inline]
fn find_connection_header(request: &[u8]) -> Option<&[u8]> {
    const HEADER: &[u8] = b"onnection:";

    let mut pos = 0;
    while pos < request.len() {
        let search_slice = &request[pos..];
        let idx =
            memchr::memchr(b'C', search_slice).or_else(|| memchr::memchr(b'c', search_slice))?;

        let abs_pos = pos + idx;
        if abs_pos + 1 + HEADER.len() <= request.len() {
            let slice = &request[abs_pos + 1..abs_pos + 1 + HEADER.len()];
            if slice.eq_ignore_ascii_case(HEADER) {
                let start = abs_pos + 1 + HEADER.len();
                let end = memchr::memchr2(b'\r', b'\n', &request[start..])
                    .map_or(request.len(), |p| start + p);
                return Some(&request[start..end]);
            }
        }
        pos = abs_pos + 1;
    }
    None
}

#[inline]
fn is_http11(request: &[u8]) -> bool {
    let line_end = memchr::memchr(b'\r', request).unwrap_or(request.len());
    if line_end >= 8 {
        let check_start = line_end - 8;
        request
            .get(check_start..line_end)
            .map_or(false, |s| s.eq_ignore_ascii_case(b"HTTP/1.1"))
    } else {
        false
    }
}

#[inline]
fn should_keep_alive(request: &[u8]) -> bool {
    let http11 = is_http11(request);

    match find_connection_header(request) {
        Some(val) => {
            let val_lower: SmallVec<[u8; 32]> =
                val.iter().map(|b| b.to_ascii_lowercase()).collect();
            if memchr::memmem::find(&val_lower, b"close").is_some() {
                false
            } else if memchr::memmem::find(&val_lower, b"keep-alive").is_some() {
                true
            } else {
                http11
            }
        }
        None => http11,
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
            "Filter loaded: {} blacklist ({} exact, {} suffix), \
             {} whitelist ({} exact, {} suffix)",
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

    // Stats logging task
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

    // Socket setup
    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .context("Invalid bind address")?;

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .context("Failed to create socket")?;
    socket
        .set_reuse_address(true)
        .context("Failed to set SO_REUSEADDR")?;

    #[cfg(unix)]
    let _ = socket.set_reuse_port(true);

    socket
        .set_nonblocking(true)
        .context("Failed to set non-blocking")?;
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
        "Max connections: {}, Connect timeout: {:?}, \
         Idle timeout: {:?}, Allow private: {}",
        args.max_connections, config.connect_timeout, config.idle_timeout, config.allow_private
    );

    // Shutdown handler
    let shutdown_token = cancel_token.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        info!("Shutdown signal received, stopping new connections...");
        shutdown_token.cancel();
    });

    let semaphore = Arc::new(Semaphore::new(args.max_connections));
    let drain_timeout = Duration::from_secs(args.drain_timeout);

    // Main accept loop
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
                let (client_stream, client_addr) = match accept_result {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(ACCEPT_ERROR_BACKOFF_MS)).await;
                        continue;
                    }
                };

                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        stats.inc_rejected();
                        warn!("Connection limit reached, rejecting {}", client_addr);
                        tokio::spawn(async move {
                            let _ = timeout(Duration::from_millis(100), async {
                                let _ = client_stream.writable().await;
                                let _ = client_stream.try_write(RESPONSE_503);
                            }).await;
                        });
                        continue;
                    }
                };

                let config = config.clone();
                let conn_cancel = cancel_token.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    let _guard = ConnectionGuard::new(config.stats.clone());

                    let handler = handle_connection(
                        client_stream, client_addr, config.clone()
                    );
                    tokio::pin!(handler);

                    let result = tokio::select! {
                        biased;
                        () = conn_cancel.cancelled() => {
                            debug!("Connection {} entering grace period", client_addr);
                            match timeout(
                                Duration::from_secs(GRACE_PERIOD_SECS),
                                &mut handler
                            ).await {
                                Ok(r) => r,
                                Err(_) => {
                                    debug!("Grace period timeout for {}", client_addr);
                                    Ok(())
                                }
                            }
                        }
                        r = &mut handler => r,
                    };

                    if let Err(e) = result {
                        let is_expected = e.downcast_ref::<std::io::Error>()
                            .map_or(false, |io_e| {
                                matches!(io_e.kind(),
                                    ErrorKind::UnexpectedEof
                                    | ErrorKind::ConnectionReset
                                    | ErrorKind::BrokenPipe)
                            });

                        if !is_expected {
                            debug!("Connection error from {}: {:#}", client_addr, e);
                            config.stats.inc_failed();
                        }
                    }
                });
            }
        }
    }

    // Graceful drain
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

    let mut pos = match timeout(
        Duration::from_secs(INITIAL_READ_TIMEOUT_SECS),
        client.read(&mut buf),
    )
    .await
    {
        Ok(Ok(0)) => return Ok(()),
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()),
    };

    loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(&buf[..pos]) {
            Ok(httparse::Status::Complete(parsed_len)) => {
                let method = req.method.unwrap_or("");
                let path = req.path.unwrap_or("");

                // Check for request smuggling
                if has_smuggling_indicators(req.headers) {
                    warn!(client = %peer_addr, "Request smuggling attempt detected");
                    let _ = client.write_all(RESPONSE_400).await;
                    return Ok(());
                }

                // Fast path for internal endpoints
                if let Some(result) =
                    handle_internal_endpoint(&buf[..parsed_len], &mut client, &config).await?
                {
                    if !result.keep_alive {
                        break;
                    }
                    shift_buffer(&mut buf, &mut pos, parsed_len);

                    if pos == 0 {
                        match timeout(Duration::from_secs(2), client.read(&mut buf)).await {
                            Ok(Ok(0)) => break,
                            Ok(Ok(n)) => pos = n,
                            Ok(Err(_)) | Err(_) => break,
                        }
                    }
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
                    handle_http(client, &req, &buf[..parsed_len], &config).await
                };
            }
            Ok(httparse::Status::Partial) => {
                if pos >= MAX_HEADER_SIZE {
                    warn!("Header too large from {}", peer_addr);
                    let _ = client.write_all(RESPONSE_400).await;
                    return Ok(());
                }

                match timeout(Duration::from_secs(5), client.read(&mut buf[pos..])).await {
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

// ============================================================================
// Internal Endpoint Result
// ============================================================================

struct InternalEndpointResult {
    keep_alive: bool,
}

// ============================================================================
// Internal Endpoints
// ============================================================================

async fn handle_internal_endpoint(
    request: &[u8],
    client: &mut TcpStream,
    config: &ProxyConfig,
) -> Result<Option<InternalEndpointResult>> {
    if request.len() < 14 || request.get(0..5) != Some(b"GET /") {
        return Ok(None);
    }

    let path_end = memchr::memchr2(b' ', b'\r', &request[5..]).map_or(request.len(), |p| 5 + p);
    let path = &request[5..path_end];
    let keepalive = should_keep_alive(request);

    match path {
        b"bench" => {
            client.write_all(RESPONSE_BENCH).await?;
            Ok(Some(InternalEndpointResult { keep_alive: true }))
        }
        b"health" => {
            let response = if keepalive {
                RESPONSE_HEALTH_KEEPALIVE
            } else {
                RESPONSE_HEALTH
            };
            client.write_all(response).await?;
            Ok(Some(InternalEndpointResult {
                keep_alive: keepalive,
            }))
        }
        b"stats" => {
            let body = config.stats.snapshot().to_string();
            let response = build_response(200, &body, keepalive);
            client.write_all(response.as_bytes()).await?;
            Ok(Some(InternalEndpointResult {
                keep_alive: keepalive,
            }))
        }
        b"filter-stats" => {
            let fs = config.filter.stats();
            let body = format!(
                "blacklist_exact={} blacklist_suffix={} \
                 whitelist_exact={} whitelist_suffix={} total={}",
                fs.blacklist_exact,
                fs.blacklist_suffix,
                fs.whitelist_exact,
                fs.whitelist_suffix,
                fs.total()
            );
            let response = build_response(200, &body, keepalive);
            client.write_all(response.as_bytes()).await?;
            Ok(Some(InternalEndpointResult {
                keep_alive: keepalive,
            }))
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

    if !validate_host(host, config.allow_private) {
        warn!(host = %host, "BLOCKED (invalid or private host)");
        config.stats.inc_blocked();
        let _ = client.write_all(RESPONSE_403).await;
        return Ok(());
    }

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
            warn!(
                host = %host,
                port = %port,
                error = %e,
                "Upstream connection failed"
            );
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
    req: &httparse::Request<'_, '_>,
    initial_data: &[u8],
    config: &ProxyConfig,
) -> Result<()> {
    let host_header = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .map(|h| std::str::from_utf8(h.value).unwrap_or(""))
        .unwrap_or("");

    if host_header.is_empty() {
        let _ = client.write_all(RESPONSE_400).await;
        return Ok(());
    }

    let (host, port) = parse_host_port(host_header, 80);

    if !validate_host(host, config.allow_private) {
        warn!(host = %host, "BLOCKED HTTP (invalid or private host)");
        config.stats.inc_blocked();
        let _ = client.write_all(RESPONSE_403).await;
        return Ok(());
    }

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
            warn!(
                host = %host,
                port = %port,
                error = %e,
                "HTTP upstream connection failed"
            );
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

    // Validate TLS record
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

    // Use buffer pool
    let mut body = config.buffer_pool.acquire(record_len);
    match timeout(Duration::from_secs(5), client.read_exact(&mut body)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Don't send partial record
    }

    config.stats.inc_fragmented();

    let fragments = generate_fragment_sizes(record_len, config);
    let mut write_buf = Vec::with_capacity(5 + record_len);
    let mut remaining = &body[..];

    for (i, &size) in fragments.iter().enumerate() {
        if size == 0 {
            continue;
        }

        let chunk_size = size.min(remaining.len());
        let (chunk, rest) = remaining.split_at(chunk_size);
        remaining = rest;

        // Consolidated write
        write_buf.clear();
        write_buf.extend_from_slice(&[
            0x16,
            header[1],
            header[2],
            (chunk.len() >> 8) as u8,
            (chunk.len() & 0xFF) as u8,
        ]);
        write_buf.extend_from_slice(chunk);

        server.write_all(&write_buf).await?;
        server.flush().await?;

        // Delay after first fragment
        if i == 0 && fragments.len() > 1 {
            let delay_ms = if size <= 4 {
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
fn generate_fragment_sizes(record_len: usize, config: &ProxyConfig) -> SmallVec<[usize; 4]> {
    let strategy = config.random_u32() % 100;

    if strategy < 60 {
        let first = ((config.random_u32() as usize % 8) + 1).min(record_len);
        smallvec::smallvec![first, record_len.saturating_sub(first)]
    } else if strategy < 90 {
        let p1 = ((config.random_u32() as usize % 12) + 1).min(record_len);
        let remaining = record_len.saturating_sub(p1);
        let p2 = if remaining > 0 {
            ((config.random_u32() as usize % 80) + 20).min(remaining)
        } else {
            0
        };
        smallvec::smallvec![p1, p2, remaining.saturating_sub(p2)]
    } else if record_len > 1 {
        smallvec::smallvec![1, record_len - 1]
    } else {
        smallvec::smallvec![record_len]
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

        let req = b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
        assert!(!should_keep_alive(req));

        let req = b"GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";
        assert!(should_keep_alive(req));
    }

    #[test]
    fn test_should_keep_alive_http10() {
        let req = b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
        assert!(!should_keep_alive(req));

        let req = b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n";
        assert!(should_keep_alive(req));
    }

    #[test]
    fn test_parse_host_port() {
        assert_eq!(parse_host_port("example.com", 80), ("example.com", 80));
        assert_eq!(
            parse_host_port("example.com:8080", 80),
            ("example.com", 8080)
        );
        assert_eq!(parse_host_port("[::1]:8080", 80), ("::1", 8080));
        assert_eq!(parse_host_port("[::1]", 80), ("::1", 80));
    }

    #[test]
    fn test_is_private_host() {
        assert!(is_private_host("localhost"));
        assert!(is_private_host("127.0.0.1"));
        assert!(is_private_host("10.0.0.1"));
        assert!(is_private_host("192.168.1.1"));
        assert!(is_private_host("::1"));
        assert!(is_private_host("foo.local"));

        assert!(!is_private_host("example.com"));
        assert!(!is_private_host("8.8.8.8"));
    }

    #[test]
    fn test_has_smuggling_indicators() {
        let ok = [
            httparse::Header {
                name: "Host",
                value: b"example.com",
            },
            httparse::Header {
                name: "Content-Length",
                value: b"10",
            },
        ];
        assert!(!has_smuggling_indicators(&ok));

        let dup_cl = [
            httparse::Header {
                name: "Content-Length",
                value: b"10",
            },
            httparse::Header {
                name: "Content-Length",
                value: b"20",
            },
        ];
        assert!(has_smuggling_indicators(&dup_cl));

        let cl_te = [
            httparse::Header {
                name: "Content-Length",
                value: b"10",
            },
            httparse::Header {
                name: "Transfer-Encoding",
                value: b"chunked",
            },
        ];
        assert!(has_smuggling_indicators(&cl_te));
    }

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(4, 1024);

        let buf1 = pool.acquire(100);
        assert_eq!(buf1.len(), 100);

        drop(buf1);

        let buf2 = pool.acquire(50);
        assert_eq!(buf2.len(), 50);
    }

    #[test]
    fn test_fragment_sizes() {
        let config = ProxyConfig {
            filter: Arc::new(DomainFilter::new()),
            stats: Arc::new(Stats::new()),
            buffer_pool: Arc::new(BufferPool::new(16, MAX_TLS_RECORD_SIZE)),
            connect_timeout: None,
            idle_timeout: None,
            allow_private: false,
        };

        for _ in 0..100 {
            let sizes = generate_fragment_sizes(1000, &config);
            let total: usize = sizes.iter().sum();
            assert_eq!(total, 1000);
            assert!(sizes.len() <= 4);
        }
    }
}
