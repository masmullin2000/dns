use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, LazyLock, Mutex, RwLock},
    time::Duration,
};

use futures::future::select_all;
use simple_dns as dns;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::Sender as AsyncSender,
    sync::mpsc::channel as AsyncChannel,
    time::timeout,
};
use tracing::{debug, error, info, trace, warn};

use crate::{
    config::RuntimeConfig,
    dns_cache,
    dot_client::{self, DotPool},
};

const ADDR: &str = "0.0.0.0:53";
const LOCAL_ADDR: &str = "127.0.0.53:53";
const MAX_PKT_SIZE: usize = 65535;
const TCP_DNS_LEN_BYTES_SZ: usize = 2; // The first two bytes of a TCP DNS packet are the length of the packet
const WAIT_FOR_DNS_REQ: Duration = Duration::from_millis(500);

type Sender = AsyncSender<ChannelData>;
type TcpSender = AsyncSender<(Vec<u8>, tokio::net::TcpStream)>;

pub struct ChannelData {
    pub bytes: Vec<u8>,
    pub addr: SocketAddr,
    pub sock: Arc<tokio::net::UdpSocket>,
}

impl ChannelData {
    pub const fn new(bytes: Vec<u8>, addr: SocketAddr, sock: Arc<tokio::net::UdpSocket>) -> Self {
        Self { bytes, addr, sock }
    }
}

pub fn udp_sock(addr: impl AsRef<str>) -> anyhow::Result<tokio::net::UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    let addr: SocketAddr = addr.as_ref().parse()?;
    sock.set_reuse_port(true)?;
    sock.bind(&addr.into())?;
    sock.set_nonblocking(true)?;

    let sock: std::net::UdpSocket = sock.into();
    let sock = tokio::net::UdpSocket::from_std(sock)?;
    info!("Socket listening on {}", sock.local_addr()?);

    Ok(sock)
}

trait DnsAnswers {
    fn check(
        &self,
        config: &RuntimeConfig,
        cache: &Arc<RwLock<dns_cache::Cache>>,
    ) -> Option<Vec<dns::ResourceRecord<'_>>>;
}

impl DnsAnswers for dns::Question<'_> {
    fn check(
        &self,
        config: &RuntimeConfig,
        cache: &Arc<RwLock<dns_cache::Cache>>,
    ) -> Option<Vec<dns::ResourceRecord<'_>>> {
        const TTL: u32 = 300; // 5 minutes

        let name = self.qname.to_string();
        let dns::QTYPE::TYPE(ty) = self.qtype else {
            return None;
        };

        #[allow(
            clippy::significant_drop_tightening,
            clippy::significant_drop_in_scrutinee
        )]
        let addr = if config.has_block(&name) {
            debug!("Blocked domain: {name}");
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        } else if let Some(addr) = config.has_addr(&name) {
            debug!("Local domain: {name} -> {addr}");
            vec![addr]
        } else if let Some(addr) = cache
            .read()
            .expect("cache read lock poisoned")
            .get(&name, ty)
        {
            debug!("Cache hit for {name}: {addr:?}");
            addr
        } else {
            return None;
        };
        let class = match self.qclass {
            dns::QCLASS::CLASS(class) => class,
            dns::QCLASS::ANY => dns::CLASS::NONE,
        };
        match self.qtype {
            dns::QTYPE::TYPE(dns::TYPE::A | dns::TYPE::AAAA) => {}
            // dns::QTYPE::ANY => {}
            _ => return None,
        }
        Some(
            addr.into_iter()
                .map(|addr| {
                    let rdata = match addr {
                        IpAddr::V4(addr) => dns::rdata::RData::A(dns::rdata::A::from(addr)),
                        IpAddr::V6(addr) => dns::rdata::RData::AAAA(dns::rdata::AAAA::from(addr)),
                    };
                    dns::ResourceRecord::new(self.qname.clone(), class, TTL, rdata)
                })
                .collect(),
        )
    }
}

async fn dot_query(
    config: &RuntimeConfig,
    bytes: &Arc<Vec<u8>>,
    dns_start_location: usize,
) -> anyhow::Result<Option<(String, Vec<u8>)>> {
    const INITIAL_QUERY_TIME: Duration = Duration::from_millis(200);
    const FALLBACK_QUERY_TIME: Duration = Duration::from_millis(5000);

    static POOL: LazyLock<Arc<Mutex<DotPool>>> =
        LazyLock::new(|| Arc::new(Mutex::new(DotPool::default())));

    let query = if dns_start_location > 0 {
        // For TCP, skip the length prefix
        &bytes[dns_start_location..]
    } else {
        // For UDP, use the whole packet
        &bytes[..]
    };

    let servers = config.get_dot_servers();
    let mut query_time = if servers.len() > 1 {
        INITIAL_QUERY_TIME
    } else {
        FALLBACK_QUERY_TIME
    };

    for server in servers {
        let host = server.hostname.clone();
        let port = server.port;

        let get_new_conn = async || {
            dot_client::DotConnection::try_new(server, &config.tls_config)
                .await
                .inspect_err(|e| warn!("Failed to establish DoT connection to {host}:{port}: {e}"))
        };

        let get_conn = || POOL.lock().unwrap().get_connection(server);
        let put_conn = |conn| POOL.lock().unwrap().return_connection(server, conn);

        let value = get_conn();
        let mut conn = if let Some(conn) = value {
            debug!("Reusing DoT connection to {host}:{port}");
            conn
        } else {
            let Ok(conn) = get_new_conn().await else {
                query_time = FALLBACK_QUERY_TIME;
                continue;
            };
            conn
        };

        let res = timeout(query_time, conn.send_query(query)).await;
        let Ok(res) = res else {
            // timeout
            debug!("DoT query to {host}:{port} timed out");
            query_time = FALLBACK_QUERY_TIME;
            continue;
        };

        let res = if let Ok(res) = res {
            put_conn(conn);
            res
        } else {
            let Ok(mut conn) = get_new_conn().await else {
                query_time = FALLBACK_QUERY_TIME;
                continue;
            };
            let Ok(Ok(res)) = timeout(query_time, conn.send_query(query))
                .await
                .inspect_err(|e| {
                    warn!("DoT query to {host}:{port} failed: {e}");
                })
            else {
                query_time = FALLBACK_QUERY_TIME;
                continue;
            };
            put_conn(conn);
            res
        };

        return Ok(Some((host, res)));
    }
    Ok(None)
}

#[allow(clippy::significant_drop_tightening)]
fn cache_dns_packet(
    response_data: &[u8],
    dns_start_location: usize,
    cache: &Arc<RwLock<dns_cache::Cache>>,
    client_addr: &SocketAddr,
) -> anyhow::Result<()> {
    let pkt = dns::Packet::parse(&response_data[dns_start_location..])?;

    tracing::trace!("Received DNS response from upstream: {pkt:?}");

    if let Some(question) = pkt.questions.first() {
        let qname = &question.qname;
        let mut cache = cache.write().expect("cache write lock poisoned");
        for rr in &pkt.answers {
            let ttl = rr.ttl;
            if ttl == 0 {
                continue;
            }
            match &rr.rdata {
                dns::rdata::RData::A(a) => {
                    let addr = IpAddr::V4(Ipv4Addr::from(a.address));
                    cache.insert(qname, dns_cache::IpAddr::new(addr, ttl));
                    trace!("for {client_addr} - {qname}:{ttl} A: {addr} (via DoT)");
                }
                dns::rdata::RData::AAAA(a) => {
                    let addr = IpAddr::V6(Ipv6Addr::from(a.address));
                    cache.insert(qname, dns_cache::IpAddr::new(addr, ttl));
                    trace!("for {client_addr} - {qname}:{ttl} AAAA: {addr} (via DoT)");
                }
                _ => (),
            }
        }
    }
    Ok(())
}

fn dns_fail(pkt: &dns::Packet, err: dns::RCODE) -> Vec<u8> {
    let mut resp_pkt = pkt.clone().into_reply();
    resp_pkt.set_flags(
        dns::PacketFlag::RESPONSE
            | dns::PacketFlag::RECURSION_DESIRED
            | dns::PacketFlag::RECURSION_AVAILABLE,
    );
    *resp_pkt.rcode_mut() = err;
    resp_pkt.build_bytes_vec().unwrap_or_default()
}

#[allow(clippy::too_many_lines)]
async fn process_dns_request<F>(
    client_addr: &SocketAddr,
    config: &RuntimeConfig,
    cache: &Arc<RwLock<dns_cache::Cache>>,
    bytes: Vec<u8>,
    dns_start_location: usize, // for TCP this should be 2, for UDP it should be 0
    get_data: F,
) -> anyhow::Result<Vec<u8>>
where
    F: Clone + AsyncFn(&SocketAddr, &Arc<Vec<u8>>) -> anyhow::Result<Vec<u8>>,
{
    if bytes.len() < dns_start_location + 12 || (dns_start_location != 2 && dns_start_location != 0)
    {
        anyhow::bail!("DNS packet too short");
    }
    let bytes = Arc::new(bytes);

    let Ok(mut pkt) = dns::Packet::parse(&bytes[dns_start_location..])
        .inspect_err(|e| error!("failed to parse DNS Question: {e}"))
    else {
        error!("Failed to parse DNS packet: {:?}", &bytes);
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        return Ok(dns_fail(
            &dns::Packet::new_reply(id),
            dns::RCODE::FormatError,
        ));
    };

    debug!("Received DNS request from {client_addr}: {pkt:?}");

    // only check the cache for single question packets
    if pkt.questions.len() == 1 {
        pkt.set_flags(
            dns::PacketFlag::RESPONSE
                | dns::PacketFlag::RECURSION_DESIRED
                | dns::PacketFlag::RECURSION_AVAILABLE,
        );

        let answers: Vec<_> = pkt
            .questions
            .iter()
            .filter_map(|question| question.check(config, cache))
            .flatten()
            .collect();

        if !answers.is_empty() {
            pkt.answers = answers;
            if let Ok(reply_data) = pkt.build_bytes_vec() {
                let reply = if dns_start_location > 0 {
                    u16::try_from(reply_data.len()).map_or(None, |length| {
                        let mut reply = Vec::with_capacity(dns_start_location + reply_data.len());
                        reply.extend_from_slice(&length.to_be_bytes());
                        reply.extend_from_slice(&reply_data);
                        Some(reply)
                    })
                } else {
                    Some(reply_data)
                };
                if let Some(reply) = reply {
                    trace!("Cached DNS reply for {client_addr}");
                    return Ok(reply);
                }
            }
        }
    }

    // Try DoT servers first if available
    if let Ok(Some((ns, response))) = dot_query(config, &bytes, dns_start_location).await {
        _ = cache_dns_packet(&response, dns_start_location, cache, client_addr)
            .inspect(|()| debug!("Received DNS response from DoT {ns}"))
            .inspect_err(|e| error!("Failed to parse DNS packet: {e}"));

        return Ok(response);
    }

    if config.force_dot {
        return Ok(dns_fail(&pkt, dns::RCODE::ServerFailure));
        // anyhow::bail!("All DoT servers failed and force_dot is enabled");
    }

    // Fallback to plain DNS
    let futures = config.get_nameservers().iter().map(|ns| {
        let get_response_from_ns = get_data.clone();
        let b = bytes.clone();
        Box::pin({
            async move {
                // if TCP, the DNS is not trimmed, so we need to check the length
                let response_data = get_response_from_ns(ns, &b).await.inspect_err(|e| {
                    let ty = if dns_start_location > 0 { "TCP" } else { "UDP" };
                    debug!("get data for {ty}--{ns} failed: {e}");
                })?;

                Ok::<_, anyhow::Error>((ns, response_data))
            }
        })
    });

    let (Ok((ns, response_data)), _, _) = select_all(futures).await else {
        return Ok(dns_fail(&pkt, dns::RCODE::ServerFailure));
        // anyhow::bail!("Failed to get a response from any nameserver");
    };
    _ = cache_dns_packet(&response_data, dns_start_location, cache, client_addr)
        .inspect(|()| debug!("Received DNS response from {ns}"))
        .inspect_err(|e| error!("Failed to parse DNS packet: {e}"));
    Ok(response_data)
}

pub fn udp_server(
    config: Arc<RuntimeConfig>,
    cache: Arc<RwLock<dns_cache::Cache>>,
) -> anyhow::Result<()> {
    let remote_sock = Arc::new(udp_sock(ADDR)?);
    let local_sock = Arc::new(udp_sock(LOCAL_ADDR)?);

    let (tx, mut rx) = AsyncChannel::<ChannelData>(64);

    let get_data = async |ns: &SocketAddr, bytes: &Arc<Vec<u8>>| -> anyhow::Result<Vec<u8>> {
        let mut rec_buf = vec![0u8; MAX_PKT_SIZE];

        let dns_sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        dns_sock.connect(ns).await?;
        dns_sock.send(bytes).await?;

        let sz = timeout(WAIT_FOR_DNS_REQ, dns_sock.recv(&mut rec_buf)).await??;
        rec_buf.truncate(sz);
        Ok(rec_buf)
    };

    tokio::spawn(async move {
        while let Some(channel_data) = rx.recv().await {
            let config = config.clone();
            let cache = cache.clone();
            tokio::spawn(async move {
                let bytes = channel_data.bytes;
                let addr = channel_data.addr;
                let sock = channel_data.sock;

                if let Ok(reply_data) =
                    process_dns_request(&addr, &config, &cache, bytes, 0, get_data).await
                {
                    _ = sock.send_to(&reply_data, &addr).await.inspect_err(|e| {
                        error!("Failed to send DNS packet to {addr}: {e}");
                    });
                } else {
                    debug!("No reply data for {addr}");
                }
            });
        }
    });

    let recv_loop = |sock: Arc<tokio::net::UdpSocket>, tx: Sender| async move {
        let mut buf = vec![0u8; MAX_PKT_SIZE];
        loop {
            let Ok((sz, addr)) = sock
                .recv_from(&mut buf)
                .await
                .inspect(|(_, addr)| debug!("Received UDP DNS request from {addr}"))
                .inspect_err(|e| {
                    error!("Failed to receive DNS packet: {e}");
                })
            else {
                continue;
            };
            let buf = buf[..sz].to_vec();
            if let Err(e) = tx.send(ChannelData::new(buf, addr, sock.clone())).await {
                panic!("{sock:?} channel send failed: {e}");
            }
        }
    };

    tokio::spawn(recv_loop(remote_sock, tx.clone()));
    tokio::spawn(recv_loop(local_sock, tx));

    Ok(())
}

pub async fn tcp_server(
    config: Arc<RuntimeConfig>,
    cache: Arc<RwLock<dns_cache::Cache>>,
) -> anyhow::Result<()> {
    let sock = tokio::net::TcpListener::bind(ADDR)
        .await
        .inspect(|_| info!("TCP socket listening on {ADDR}"))
        .inspect_err(|e| error!("Failed to bind TCP socket: {e}"))?;

    let (tx, mut rx) = AsyncChannel::<(Vec<u8>, tokio::net::TcpStream)>(1000);

    let get_data = async move |ns: &SocketAddr, bytes: &Arc<Vec<u8>>| -> anyhow::Result<Vec<u8>> {
        let mut sock = tokio::net::TcpStream::connect(ns).await?;

        sock.write_all(bytes).await?;

        // dont remove the buffer length prefix
        let rec_buf = timeout(WAIT_FOR_DNS_REQ, sock.read_dns()).await??;
        warn!("TCP DNS request received: {} bytes", rec_buf.len());

        Ok(rec_buf)
    };

    tokio::spawn(async move {
        while let Some((bytes, mut sock)) = rx.recv().await {
            let config = config.clone();
            let cache = cache.clone();
            let peer = sock.peer_addr().expect("Failed to get peer address");
            tokio::spawn(async move {
                if let Ok(reply_data) = process_dns_request(
                    &peer,
                    &config,
                    &cache,
                    bytes,
                    TCP_DNS_LEN_BYTES_SZ,
                    get_data,
                )
                .await
                    && let Err(e) = sock.write_all(&reply_data).await
                {
                    error!("Failed to send DNS packet to {sock:?}: {e}");
                }
            });
        }
    });

    let recv_loop = |r_sock: tokio::net::TcpListener, tx: TcpSender| async move {
        loop {
            let Ok((mut sock, _)) = r_sock
                .accept()
                .await
                .inspect(|(_, addr)| debug!("Received TCP DNS request from {addr}"))
                .inspect_err(|e| {
                    error!("Failed to accept TCP connection: {e}");
                })
            else {
                continue;
            };

            let sock_addr = sock
                .peer_addr()
                .map_or_else(|_| "unknown socket".to_string(), |a| a.to_string());

            let buf = match timeout(WAIT_FOR_DNS_REQ, Box::pin(sock.read_dns())).await {
                Ok(Ok(buf)) => buf,
                Ok(Err(e)) => {
                    error!("Failed to read from TCP socket: {sock_addr} - {e}");
                    continue;
                }
                Err(_) => {
                    warn!("Timeout while waiting for data on TCP socket: {sock_addr}");
                    continue;
                }
            };

            if let Err(e) = tx.send((buf, sock)).await {
                panic!("channel send failed: {e}");
            }
        }
    };

    tokio::spawn(recv_loop(sock, tx));
    Ok(())
}

fn dns_break(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < TCP_DNS_LEN_BYTES_SZ {
        return None; // Not enough data to parse a DNS packet
    }

    if dns::Packet::parse(&buf[TCP_DNS_LEN_BYTES_SZ..]).is_ok() {
        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        // If we can parse the DNS packet, return the bytes after the length prefix
        return Some(buf[..len + TCP_DNS_LEN_BYTES_SZ].to_vec());
    }
    None
}

fn dns_eof() -> anyhow::Result<()> {
    anyhow::bail!("EOF reached while reading DNS packet")
}

pub trait Eof {
    async fn read_until<EOF, BF>(&mut self, eof: EOF, break_on: BF) -> anyhow::Result<Vec<u8>>
    where
        EOF: Fn() -> anyhow::Result<()>,
        BF: Fn(&[u8]) -> Option<Vec<u8>>;

    async fn read_dns(&mut self) -> anyhow::Result<Vec<u8>>;

    #[cfg(test)]
    async fn read_eof(&mut self) -> anyhow::Result<Vec<u8>>;
}

impl Eof for tokio::net::TcpStream {
    async fn read_until<EOF, BF>(&mut self, eof: EOF, break_on: BF) -> anyhow::Result<Vec<u8>>
    where
        EOF: Fn() -> anyhow::Result<()>,
        BF: Fn(&[u8]) -> Option<Vec<u8>>,
    {
        const EOF_DUR: Duration = Duration::from_millis(50);
        let mut data = vec![0u8; MAX_PKT_SIZE];

        let mut buf = Vec::default();
        loop {
            let sz = match timeout(EOF_DUR, self.read(&mut data)).await {
                Ok(Ok(0)) => {
                    eof()?;
                    break;
                }
                Ok(Ok(sz)) => {
                    trace!("Read {sz} bytes from TCP stream");
                    sz
                }
                Ok(Err(e)) => {
                    error!("Failed to read from TCP stream: {e}");
                    return Err(e.into());
                }
                Err(e) => {
                    debug!("TCP stream timeout: {e}");
                    eof()?;
                    break;
                }
            };

            buf.extend_from_slice(&data[..sz]);
            let Some(early_result) = break_on(&buf) else {
                continue;
            };
            return Ok(early_result);
        }

        Ok(buf)
    }
    async fn read_dns(&mut self) -> anyhow::Result<Vec<u8>> {
        self.read_until(dns_eof, dns_break).await
    }

    #[cfg(test)]
    async fn read_eof(&mut self) -> anyhow::Result<Vec<u8>> {
        self.read_until(|| Ok(()), |_| None).await
    }
}

#[cfg(test)]
pub async fn process_dns_request_test<F>(
    client_addr: &SocketAddr,
    config: &RuntimeConfig,
    cache: &Arc<RwLock<dns_cache::Cache>>,
    bytes: Vec<u8>,
    dns_start_location: usize, // for TCP this should be 2, for UDP it should be 0
    get_data: F,
) -> anyhow::Result<Vec<u8>>
where
    F: AsyncFn(&SocketAddr, &Arc<Vec<u8>>) -> anyhow::Result<Vec<u8>> + Clone,
{
    process_dns_request(
        client_addr,
        config,
        cache,
        bytes,
        dns_start_location,
        get_data,
    )
    .await
}
