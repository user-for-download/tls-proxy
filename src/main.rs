#![warn(clippy::all)]
#![allow(clippy::similar_names, clippy::module_name_repetitions)]

mod domain_filter;

use crate::domain_filter::DomainFilter;
use anyhow::{Context, Result};
use clap::Parser;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use smallvec::SmallVec;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::mem::zeroed;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const MAX_TLS_RECORD_SIZE: usize = 16384;
const MAX_HEADER_SIZE: usize = 8192;
const DEFAULT_MAX_CONNECTIONS: usize = 65535;
const DRAIN_TIMEOUT_SECS: u64 = 30;
const INITIAL_READ_TIMEOUT_SECS: u64 = 5;
const ACCEPT_ERROR_BACKOFF_MS: u64 = 1;
const MAX_HOST_LEN: usize = 253;

const TCP_FASTOPEN_QLEN: i32 = 256;
const BACKLOG: i32 = 65535;
const SPLICE_PIPE_SIZE: usize = 1024 * 1024;

static RESPONSE_403: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
static RESPONSE_400: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
static RESPONSE_502: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
static RESPONSE_200_CONNECT: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
static RESPONSE_BENCH: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK";
static RESPONSE_HEALTH: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Ubuntu-optimized HTTPS proxy")]
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
    #[arg(long, default_value_t = false)]
    allow_private: bool,
    #[arg(long, default_value_t = true)]
    use_splice: bool,
    #[arg(long, default_value_t = 0)]
    workers: usize,
    #[arg(long, default_value_t = false)]
    cpu_affinity: bool,
    #[arg(long, default_value_t = true)]
    use_bbr: bool,
}

#[inline]
fn optimize_socket_linux(fd: RawFd, is_listener: bool) {
    unsafe {
        let one: i32 = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            (&raw const one).cast(),
            std::mem::size_of::<i32>() as u32,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_QUICKACK,
            (&raw const one).cast(),
            std::mem::size_of::<i32>() as u32,
        );

        if is_listener {
            let defer: i32 = 5;
            let fastopen = TCP_FASTOPEN_QLEN;
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_DEFER_ACCEPT,
                (&raw const defer).cast(),
                std::mem::size_of::<i32>() as u32,
            );
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN,
                (&raw const fastopen).cast(),
                std::mem::size_of::<i32>() as u32,
            );
        }

        let busy_poll: i32 = 50;
        let lowat: i32 = 16384;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BUSY_POLL,
            (&raw const busy_poll).cast(),
            std::mem::size_of::<i32>() as u32,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NOTSENT_LOWAT,
            (&raw const lowat).cast(),
            std::mem::size_of::<i32>() as u32,
        );
    }
}

#[inline]
fn set_tcp_congestion(fd: RawFd, algo: &str) {
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            algo.as_ptr().cast(),
            algo.len() as u32,
        );
    }
}

struct SplicePipe {
    read_fd: RawFd,
    write_fd: RawFd,
    in_pipe: usize,
}

impl SplicePipe {
    fn new() -> std::io::Result<Self> {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        unsafe {
            libc::fcntl(fds[1], libc::F_SETPIPE_SZ, SPLICE_PIPE_SIZE as libc::c_int);
        }
        Ok(Self {
            read_fd: fds[0],
            write_fd: fds[1],
            in_pipe: 0,
        })
    }
}

impl Drop for SplicePipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}

async fn splice_unidirectional(
    read_stream: &TcpStream,
    write_stream: &TcpStream,
    pipe: &mut SplicePipe,
) -> std::io::Result<u64> {
    let src_fd = read_stream.as_raw_fd();
    let dst_fd = write_stream.as_raw_fd();
    let mut total = 0;

    loop {
        while pipe.in_pipe > 0 {
            let res = write_stream.try_io(tokio::io::Interest::WRITABLE, || {
                let w = unsafe {
                    libc::splice(
                        pipe.read_fd,
                        std::ptr::null_mut(),
                        dst_fd,
                        std::ptr::null_mut(),
                        pipe.in_pipe,
                        libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                    )
                };
                if w < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EAGAIN) {
                        return Err(std::io::Error::new(ErrorKind::WouldBlock, ""));
                    }
                    return Err(err);
                }
                Ok(w as usize)
            });

            match res {
                Ok(w) => pipe.in_pipe -= w,
                Err(e) if e.kind() == ErrorKind::WouldBlock => write_stream.writable().await?,
                Err(e) => return Err(e),
            }
        }

        let res = read_stream.try_io(tokio::io::Interest::READABLE, || {
            let r = unsafe {
                libc::splice(
                    src_fd,
                    std::ptr::null_mut(),
                    pipe.write_fd,
                    std::ptr::null_mut(),
                    65536,
                    libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                )
            };
            if r < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EAGAIN) {
                    return Err(std::io::Error::new(ErrorKind::WouldBlock, ""));
                }
                return Err(err);
            }
            Ok(r as usize)
        });

        match res {
            Ok(0) => {
                unsafe {
                    libc::shutdown(dst_fd, libc::SHUT_WR);
                }
                return Ok(total);
            }
            Ok(r) => {
                pipe.in_pipe += r;
                total += r as u64;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => read_stream.readable().await?,
            Err(e) => return Err(e),
        }
    }
}

async fn splice_bidirectional(
    client: &mut TcpStream,
    server: &mut TcpStream,
    idle_timeout: Option<Duration>,
) -> Result<(u64, u64)> {
    let mut pipe1 = SplicePipe::new()?;
    let mut pipe2 = SplicePipe::new()?;

    let c2s = splice_unidirectional(client, server, &mut pipe1);
    let s2c = splice_unidirectional(server, client, &mut pipe2);

    let res = if let Some(timeout_dur) = idle_timeout {
        timeout(timeout_dur, async { tokio::try_join!(c2s, s2c) })
            .await
            .unwrap_or(Ok((0, 0)))
    } else {
        tokio::try_join!(c2s, s2c)
    };

    res.map_err(Into::into)
}

fn set_cpu_affinity(cpu_id: usize) {
    unsafe {
        let mut cpuset: libc::cpu_set_t = zeroed();
        libc::CPU_ZERO(&mut cpuset);
        libc::CPU_SET(cpu_id % libc::CPU_SETSIZE as usize, &mut cpuset);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw const cpuset);
    }
}

#[repr(align(128))]
struct PaddedCounter(AtomicU64);
impl PaddedCounter {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
    #[inline]
    fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    fn add(&self, val: u64) {
        self.0.fetch_add(val, Ordering::Relaxed);
    }
    #[inline]
    fn load(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[repr(align(128))]
struct Stats {
    total: PaddedCounter,
    active: PaddedCounter,
    blocked: PaddedCounter,
    whitelisted: PaddedCounter,
    fragmented: PaddedCounter,
    failed: PaddedCounter,
    rejected: PaddedCounter,
    bytes_in: PaddedCounter,
    bytes_out: PaddedCounter,
    splice_ops: PaddedCounter,
}

impl Stats {
    const fn new() -> Self {
        Self {
            total: PaddedCounter::new(),
            active: PaddedCounter::new(),
            blocked: PaddedCounter::new(),
            whitelisted: PaddedCounter::new(),
            fragmented: PaddedCounter::new(),
            failed: PaddedCounter::new(),
            rejected: PaddedCounter::new(),
            bytes_in: PaddedCounter::new(),
            bytes_out: PaddedCounter::new(),
            splice_ops: PaddedCounter::new(),
        }
    }
    #[inline]
    fn inc_total(&self) {
        self.total.inc();
    }
    #[inline]
    fn inc_active(&self) {
        self.active.0.fetch_add(1, Ordering::Release);
    }
    #[inline]
    fn dec_active(&self) {
        self.active.0.fetch_sub(1, Ordering::Release);
    }
    #[inline]
    fn inc_blocked(&self) {
        self.blocked.inc();
    }
    #[inline]
    fn inc_whitelisted(&self) {
        self.whitelisted.inc();
    }
    #[inline]
    fn inc_fragmented(&self) {
        self.fragmented.inc();
    }
    #[inline]
    fn inc_failed(&self) {
        self.failed.inc();
    }
    #[inline]
    fn inc_rejected(&self) {
        self.rejected.inc();
    }
    #[inline]
    fn inc_splice(&self) {
        self.splice_ops.inc();
    }
    #[inline]
    fn add_bytes(&self, bytes_in: u64, bytes_out: u64) {
        self.bytes_in.add(bytes_in);
        self.bytes_out.add(bytes_out);
    }

    fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            total: self.total.load(),
            active: self.active.0.load(Ordering::Acquire),
            blocked: self.blocked.load(),
            fragmented: self.fragmented.load(),
            bytes_in: self.bytes_in.load(),
            bytes_out: self.bytes_out.load(),
            splice_ops: self.splice_ops.load(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct StatsSnapshot {
    total: u64,
    active: u64,
    blocked: u64,
    fragmented: u64,
    bytes_in: u64,
    bytes_out: u64,
    splice_ops: u64,
}

impl StatsSnapshot {
    fn log(&self) {
        info!(
            "STATS | total={} active={} blocked={} fragmented={} splice={} in={}MB out={}MB",
            self.total,
            self.active,
            self.blocked,
            self.fragmented,
            self.splice_ops,
            self.bytes_in / 1_000_000,
            self.bytes_out / 1_000_000
        );
    }
}

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

#[derive(Clone)]
struct ProxyConfig {
    filter: Arc<DomainFilter>,
    stats: Arc<Stats>,
    connect_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    allow_private: bool,
    use_splice: bool,
    use_bbr: bool,
}

impl ProxyConfig {
    fn new(filter: Arc<DomainFilter>, stats: Arc<Stats>, args: &Args) -> Self {
        Self {
            filter,
            stats,
            connect_timeout: (args.timeout_connect > 0)
                .then(|| Duration::from_secs(args.timeout_connect)),
            idle_timeout: (args.timeout_idle > 0).then(|| Duration::from_secs(args.timeout_idle)),
            allow_private: args.allow_private,
            use_splice: args.use_splice,
            use_bbr: args.use_bbr,
        }
    }
    #[inline]
    fn random_u32(&self) -> u32 {
        thread_local! { static RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_os_rng()); }
        RNG.with(|rng| rng.borrow_mut().random())
    }
}

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

fn has_smuggling_indicators(headers: &[httparse::Header]) -> bool {
    let mut cl = 0;
    let mut te = false;
    for h in headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            cl += 1;
        }
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            te = true;
        }
    }
    cl > 1 || (cl > 0 && te)
}

#[inline]
fn validate_host(host: &str, allow_private: bool) -> bool {
    !host.is_empty() && host.len() <= MAX_HOST_LEN && (allow_private || !is_private_host(host))
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Failed to install SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => info!("Received Ctrl+C"),
        _ = sigterm.recv() => info!("Received SIGTERM"),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    tune_system();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level)),
        )
        .with_target(false)
        .compact()
        .init();

    let workers = if args.workers == 0 {
        std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
    } else {
        args.workers
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_stack_size(2 * 1024 * 1024)
        .enable_all()
        .on_thread_start({
            let cpu_affinity = args.cpu_affinity;
            let counter = Arc::new(AtomicU64::new(0));
            move || {
                if cpu_affinity {
                    set_cpu_affinity(counter.fetch_add(1, Ordering::SeqCst) as usize);
                }
            }
        })
        .build()
        .context("Failed to build Tokio runtime")?;

    runtime.block_on(run(args))
}

fn tune_system() {
    unsafe {
        let mut rlim: libc::rlimit = zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rlim) == 0 {
            rlim.rlim_cur = rlim.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &raw const rlim);
        }
    }
}

async fn run(args: Args) -> Result<()> {
    let filter = Arc::new(DomainFilter::new());
    if let Some(ref path) = args.blacklist {
        filter.load_blacklist(path)?;
    }
    if let Some(ref path) = args.whitelist {
        filter.load_whitelist(path)?;
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
        });
    }

    let listener = create_listener(&args)?;
    info!("Proxy listening on http://{}:{}", args.host, args.port);

    let shutdown_token = cancel_token.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        shutdown_token.cancel();
    });

    let semaphore = Arc::new(Semaphore::new(args.max_connections));
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            biased;
            () = cancel_token.cancelled() => break,
            accept_result = listener.accept() => {
                let (client_stream, client_addr) = match accept_result {
                    Ok(v) => v,
                    Err(e) => {
                        if e.kind() != ErrorKind::WouldBlock { tokio::time::sleep(Duration::from_millis(ACCEPT_ERROR_BACKOFF_MS)).await; }
                        continue;
                    }
                };
                let permit = if let Ok(p) = semaphore.clone().try_acquire_owned() { p } else { stats.inc_rejected(); drop(client_stream); continue; };

                let fd = client_stream.as_raw_fd();
                optimize_socket_linux(fd, false);
                if config.use_bbr { set_tcp_congestion(fd, "bbr"); }

                let config = config.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _guard = ConnectionGuard::new(config.stats.clone());
                    if let Err(e) = handle_connection(client_stream, client_addr, config.clone()).await {
                        let is_expected = e.downcast_ref::<std::io::Error>()
                            .is_some_and(|io_e| matches!(io_e.kind(), ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe));
                        if !is_expected { config.stats.inc_failed(); }
                    }
                });
            }
            Some(_) = tasks.join_next() => {}
        }
    }

    info!(
        "Draining connections for up to {} seconds...",
        args.drain_timeout
    );
    let _ = timeout(Duration::from_secs(args.drain_timeout), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;

    info!("Shutdown complete");
    stats.snapshot().log();
    Ok(())
}

fn create_listener(args: &Args) -> Result<TcpListener> {
    let socket = unsafe {
        let fd = libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        );
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let one: i32 = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&raw const one).cast(),
            4,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            (&raw const one).cast(),
            4,
        );
        let addr_in = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: args.port.to_be(),
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        if libc::bind(
            fd,
            (&raw const addr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        ) < 0
        {
            libc::close(fd);
            return Err(std::io::Error::last_os_error().into());
        }
        if libc::listen(fd, BACKLOG) < 0 {
            libc::close(fd);
            return Err(std::io::Error::last_os_error().into());
        }
        optimize_socket_linux(fd, true);
        std::net::TcpListener::from_raw_fd(fd)
    };
    TcpListener::from_std(socket).context("Failed to create async listener")
}

async fn handle_connection(
    mut client: TcpStream,
    _peer_addr: SocketAddr,
    config: ProxyConfig,
) -> Result<()> {
    let mut buf = [0u8; MAX_HEADER_SIZE];
    let mut pos = match timeout(
        Duration::from_secs(INITIAL_READ_TIMEOUT_SECS),
        client.read(&mut buf),
    )
    .await
    {
        Ok(Ok(0)) | Err(_) => return Ok(()),
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.into()),
    };

    loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(&buf[..pos]) {
            Ok(httparse::Status::Complete(parsed_len)) => {
                let method = req.method.unwrap_or("");
                let path = req.path.unwrap_or("");

                if has_smuggling_indicators(req.headers) {
                    let _ = client.write_all(RESPONSE_400).await;
                    return Ok(());
                }

                if method.eq_ignore_ascii_case("GET") {
                    if path == "/bench" {
                        client.write_all(RESPONSE_BENCH).await?;
                        shift_buffer(&mut buf, &mut pos, parsed_len);
                        if pos == 0 {
                            match timeout(Duration::from_secs(2), client.read(&mut buf)).await {
                                Ok(Ok(n)) if n > 0 => pos = n,
                                _ => break,
                            }
                        }
                        continue;
                    }
                    if path == "/health" {
                        client.write_all(RESPONSE_HEALTH).await?;
                        break;
                    }
                }

                return if method.eq_ignore_ascii_case("CONNECT") {
                    handle_connect(client, path, &buf[parsed_len..pos], &config).await
                } else {
                    handle_http(client, &req, &buf[..pos], &config).await
                };
            }
            Ok(httparse::Status::Partial) => {
                if pos == buf.len() {
                    let _ = client.write_all(RESPONSE_400).await;
                    return Ok(());
                }
                match timeout(Duration::from_secs(5), client.read(&mut buf[pos..])).await {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => {
                        pos += n;
                        continue;
                    }
                    Ok(Err(e)) => return Err(e.into()),
                }
            }
            Err(_) => {
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

async fn handle_connect(
    mut client: TcpStream,
    target: &str,
    leftover_data: &[u8],
    config: &ProxyConfig,
) -> Result<()> {
    let (host, port) = parse_host_port(target, 443);

    if !validate_host(host, config.allow_private) || config.filter.is_blacklisted(host) {
        config.stats.inc_blocked();
        let _ = client.write_all(RESPONSE_403).await;
        return Ok(());
    }

    let mut server = match config.connect_timeout {
        Some(to) => timeout(to, TcpStream::connect((host, port)))
            .await
            .map_err(|_| std::io::Error::new(ErrorKind::TimedOut, ""))?,
        None => TcpStream::connect((host, port)).await,
    }
    .map_err(|_| std::io::Error::other("upstream failed"))?;

    let server_fd = server.as_raw_fd();
    optimize_socket_linux(server_fd, false);
    if config.use_bbr {
        set_tcp_congestion(server_fd, "bbr");
    }

    client.write_all(RESPONSE_200_CONNECT).await?;

    if leftover_data.is_empty() {
        let should_fragment = !config.filter.is_whitelisted(host);
        if should_fragment {
            if let Err(e) = fragment_tls_handshake(&mut client, &mut server, config).await {
                debug!(error = %e, "Fragmentation error");
            }
        } else {
            config.stats.inc_whitelisted();
        }
    } else {
        server.write_all(leftover_data).await?;
    }

    let result = if config.use_splice {
        config.stats.inc_splice();
        splice_bidirectional(&mut client, &mut server, config.idle_timeout).await
    } else {
        match config.idle_timeout {
            Some(to) => timeout(to, tokio::io::copy_bidirectional(&mut client, &mut server))
                .await
                .unwrap_or(Ok((0, 0))),
            None => tokio::io::copy_bidirectional(&mut client, &mut server).await,
        }
        .map_err(Into::into)
    };

    if let Ok((c2s, s2c)) = result {
        config.stats.add_bytes(s2c, c2s);
    }
    Ok(())
}

async fn handle_http(
    mut client: TcpStream,
    req: &httparse::Request<'_, '_>,
    entire_buf: &[u8],
    config: &ProxyConfig,
) -> Result<()> {
    let host_header = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .unwrap_or("");
    if host_header.is_empty() {
        let _ = client.write_all(RESPONSE_400).await;
        return Ok(());
    }

    let (host, port) = parse_host_port(host_header, 80);
    if !validate_host(host, config.allow_private) || config.filter.is_blacklisted(host) {
        config.stats.inc_blocked();
        let _ = client.write_all(RESPONSE_403).await;
        return Ok(());
    }

    let server_res = match config.connect_timeout {
        Some(to) => timeout(to, TcpStream::connect((host, port)))
            .await
            .map_err(|_| std::io::Error::new(ErrorKind::TimedOut, ""))?,
        None => TcpStream::connect((host, port)).await,
    };

    let mut server = if let Ok(s) = server_res { s } else {
        let _ = client.write_all(RESPONSE_502).await;
        return Ok(());
    };

    optimize_socket_linux(server.as_raw_fd(), false);
    server.write_all(entire_buf).await?;

    let result = if config.use_splice {
        splice_bidirectional(&mut client, &mut server, config.idle_timeout).await
    } else {
        match config.idle_timeout {
            Some(to) => timeout(to, tokio::io::copy_bidirectional(&mut client, &mut server))
                .await
                .unwrap_or(Ok((0, 0))),
            None => tokio::io::copy_bidirectional(&mut client, &mut server).await,
        }
        .map_err(Into::into)
    };

    if let Ok((c2s, s2c)) = result {
        config.stats.add_bytes(s2c, c2s);
    }
    Ok(())
}

async fn fragment_tls_handshake(
    client: &mut TcpStream,
    server: &mut TcpStream,
    config: &ProxyConfig,
) -> Result<()> {
    let mut header = [0u8; 5];
    match timeout(Duration::from_secs(5), client.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        _ => return Ok(()),
    }

    if header[0] != 0x16 || header[1] != 0x03 || header[2] > 0x03 {
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
        _ => return Ok(()),
    }

    config.stats.inc_fragmented();
    let fragments = generate_fragment_sizes(record_len, config);
    let mut remaining = &body[..];
    let mut write_buf = Vec::with_capacity(5 + record_len);

    for (i, &size) in fragments.iter().enumerate() {
        if size == 0 {
            continue;
        }
        let chunk_size = size.min(remaining.len());
        let (chunk, rest) = remaining.split_at(chunk_size);
        remaining = rest;

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

        if i == 0 && fragments.len() > 1 {
            let delay = u64::from(config.random_u32() % 50 + 10);
            tokio::time::sleep(Duration::from_millis(delay)).await;
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
        let rem = record_len.saturating_sub(p1);
        let p2 = if rem > 0 {
            ((config.random_u32() as usize % 80) + 20).min(rem)
        } else {
            0
        };
        smallvec::smallvec![p1, p2, rem.saturating_sub(p2)]
    } else if record_len > 1 {
        smallvec::smallvec![1, record_len - 1]
    } else {
        smallvec::smallvec![record_len]
    }
}
