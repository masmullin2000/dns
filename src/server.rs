use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use futures::future::select_all;
use simple_dns as dns;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net,
    sync::mpsc,
    time::timeout,
};
use tracing::{debug, error, info, trace, warn};

use crate::{config::RuntimeConfig, dns_cache};

const ADDR: &str = "0.0.0.0:53";
const LOCAL_ADDR: &str = "127.0.0.53:53";
const MAX_PKT_SIZE: usize = 65535;
const TCP_DNS_LEN_BYTES_SZ: usize = 2; // The first two bytes of a TCP DNS packet are the length of the packet

type Sender = mpsc::Sender<ChannelData>;

pub struct ChannelData {
    pub bytes: Vec<u8>,
    pub addr: std::net::SocketAddr,
    pub sock: Arc<net::UdpSocket>,
}

impl ChannelData {
    pub const fn new(
        bytes: Vec<u8>,
        addr: std::net::SocketAddr,
        sock: Arc<net::UdpSocket>,
    ) -> Self {
        Self { bytes, addr, sock }
    }
}

pub fn udp_sock(addr: impl AsRef<str>) -> Result<net::UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    let addr: std::net::SocketAddr = addr.as_ref().parse()?;
    sock.set_reuse_port(true)?;
    sock.bind(&addr.into())?;
    sock.set_nonblocking(true)?;

    let sock: std::net::UdpSocket = sock.into();
    let sock = net::UdpSocket::from_std(sock)?;
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

        #[allow(
            clippy::significant_drop_tightening,
            clippy::significant_drop_in_scrutinee
        )]
        let addr = if config.has_block(&name) {
            info!("Blocked domain: {name}");
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]
        } else if let Some(addr) = config.has_addr(&name) {
            vec![addr]
        } else if let Some(addr) = cache.read().expect("cache read lock poisoned").get(&name) {
            trace!("Cache hit for {name}: {addr:?}");
            addr
        } else {
            return None;
        };
        let class = match self.qclass {
            dns::QCLASS::CLASS(class) => class,
            dns::QCLASS::ANY => dns::CLASS::NONE,
        };
        Some(
            addr.into_iter()
                .map(|addr| {
                    let rdata = match addr {
                        std::net::IpAddr::V4(addr) => {
                            dns::rdata::RData::A(dns::rdata::A::from(addr))
                        }
                        std::net::IpAddr::V6(addr) => {
                            dns::rdata::RData::AAAA(dns::rdata::AAAA::from(addr))
                        }
                    };
                    dns::ResourceRecord::new(self.qname.clone(), class, TTL, rdata)
                })
                .collect(),
        )
    }
}

async fn process_dns_request<F>(
    who: &SocketAddr,
    config: &RuntimeConfig,
    cache: &Arc<RwLock<dns_cache::Cache>>,
    bytes: Vec<u8>,
    dns_start_location: usize, // for TCP this should be 2, for UDP it should be 0
    get_data: F,
) -> Result<Vec<u8>>
where
    F: AsyncFn(SocketAddr, &Arc<Vec<u8>>) -> Result<Vec<u8>> + Clone,
{
    let Ok(pkt) = dns::Packet::parse(&bytes[dns_start_location..])
        .inspect_err(|e| error!("failed to parse DNS Question: {e}"))
    else {
        error!("Failed to parse DNS packet: {:?}", &bytes);
        anyhow::bail!("Failed to parse DNS packet");
    };

    let answers: Vec<_> = pkt
        .questions
        .iter()
        .filter_map(|question| question.check(config, cache))
        .flatten()
        .collect();

    if !answers.is_empty() {
        let mut reply = pkt.clone().into_reply();
        reply.set_flags(
            dns::PacketFlag::RESPONSE
                | dns::PacketFlag::RECURSION_DESIRED
                | dns::PacketFlag::RECURSION_AVAILABLE,
        );
        reply.answers = answers;
        let Ok(reply_data) = reply.build_bytes_vec() else {
            anyhow::bail!("Failed to build custom DNS reply packet");
        };
        let reply = if dns_start_location > 0 {
            let length = u16::try_from(reply_data.len())
                .map_err(|_| anyhow::anyhow!("Reply data too long"))?;
            let mut reply = Vec::with_capacity(dns_start_location + reply_data.len());
            reply.extend_from_slice(&length.to_be_bytes());
            reply.extend_from_slice(&reply_data);
            reply
        } else {
            reply_data
        };
        trace!("Cached DNS reply for {who}");
        return Ok(reply);
    }

    let bytes = Arc::new(bytes);

    let futures = config.get_nameservers().iter().map(|&ns| {
        let get_response_from_ns = get_data.clone();
        Box::pin({
            let b = bytes.clone();
            async move {
                // if TCP, the DNS is not trimmed, so we need to check the length
                let response_data = get_response_from_ns(ns, &b)
                    .await
                    .inspect_err(|e| error!("get data failed: {e}"))?;

                let pkt = dns::Packet::parse(&response_data[dns_start_location..])
                    .inspect_err(|e| error!("Failed to parse DNS packet: {e}"))?;

                if let Some(question) = pkt.questions.first() {
                    let qname = &question.qname;
                    for rr in pkt.answers {
                        let ttl = rr.ttl;
                        if ttl == 0 {
                            continue;
                        }
                        match rr.rdata {
                            dns::rdata::RData::A(a) => {
                                let addr =
                                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(a.address));
                                cache
                                    .write()
                                    .expect("cache write lock poisoned")
                                    .insert(qname.to_string(), dns_cache::IpAddr::new(addr, ttl));
                                trace!("for {who} - {qname}:{ttl} A: {addr}");
                            }
                            dns::rdata::RData::AAAA(a) => {
                                let addr =
                                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(a.address));
                                cache
                                    .write()
                                    .expect("cache write lock poisoned")
                                    .insert(qname.to_string(), dns_cache::IpAddr::new(addr, ttl));
                                trace!("for {who} - {qname}:{ttl} AAAA: {addr}");
                            }
                            _ => (),
                        }
                    }
                }
                Ok::<Vec<u8>, anyhow::Error>(response_data)
            }
        })
    });

    match select_all(futures).await {
        (Ok(data), _, _) => Ok(data),
        _ => anyhow::bail!("Failed to get a response from any nameserver"),
    }
}

pub fn udp_server(config: Arc<RuntimeConfig>, cache: Arc<RwLock<dns_cache::Cache>>) -> Result<()> {
    let remote_sock = Arc::new(udp_sock(ADDR)?);
    let local_sock = Arc::new(udp_sock(LOCAL_ADDR)?);

    let (tx, mut rx) = mpsc::channel::<ChannelData>(64);

    let get_data = async |ns, bytes: &Arc<Vec<u8>>| -> Result<Vec<u8>> {
        let mut rec_buf = vec![0u8; MAX_PKT_SIZE];

        let dns_sock = net::UdpSocket::bind("0.0.0.0:0").await?;
        dns_sock.connect(ns).await?;
        dns_sock.send(bytes).await?;

        let dur = std::time::Duration::from_millis(500);
        let sz = timeout(dur, dns_sock.recv(&mut rec_buf)).await??;
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
                }
            });
        }
    });

    let recv_loop = |sock: Arc<net::UdpSocket>, tx: Sender| async move {
        let mut buf = vec![0u8; MAX_PKT_SIZE];
        loop {
            let Ok((sz, addr)) = sock.recv_from(&mut buf).await.inspect_err(|e| {
                error!("Failed to receive DNS packet: {e}");
            }) else {
                continue;
            };
            let buf = buf[..sz].to_vec();
            tx.send(ChannelData::new(buf, addr, sock.clone()))
                .await
                .unwrap_or_else(|e| panic!("{sock:?} channel send failed: {e}"));
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
    let sock = net::TcpListener::bind("0.0.0.0:53")
        .await
        .inspect_err(|e| error!("Failed to bind TCP socket: {e}"))?;
    let sock = Arc::new(sock);
    let r_sock = sock.clone();

    info!("TCP Socket listening on {}", sock.local_addr()?);

    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, net::TcpStream)>(1000);

    let get_data = async move |ns, bytes: &Arc<Vec<u8>>| -> Result<Vec<u8>> {
        let mut sock = net::TcpStream::connect(ns).await?;

        sock.write_all(bytes).await?;

        let dur = std::time::Duration::from_millis(5000);
        // dont trim the buffer, we need the full packet
        let rec_buf = timeout(dur, sock.read_dns()).await??;
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

    loop {
        let Ok((mut sock, _)) = r_sock.accept().await.inspect_err(|e| {
            error!("Failed to accept TCP connection: {e}");
        }) else {
            continue;
        };

        let sock_addr = sock
            .peer_addr()
            .map_or_else(|_| "unknown socket".to_string(), |a| a.to_string());

        let dur = std::time::Duration::from_millis(500);
        let buf = match timeout(dur, Box::pin(sock.read_dns())).await {
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
            anyhow::bail!("Channel send failed: {e}");
        }
    }
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

fn dns_eof() -> Result<()> {
    anyhow::bail!("EOF reached while reading DNS packet")
}

pub trait Eof {
    async fn read_until<EOF, BF>(&mut self, eof: EOF, break_on: BF) -> anyhow::Result<Vec<u8>>
    where
        EOF: Fn() -> Result<()>,
        BF: Fn(&[u8]) -> Option<Vec<u8>>;

    async fn read_dns(&mut self) -> anyhow::Result<Vec<u8>>;

    #[cfg(test)]
    async fn read_eof(&mut self) -> anyhow::Result<Vec<u8>>;
}

impl Eof for net::TcpStream {
    async fn read_until<EOF, BF>(&mut self, eof: EOF, break_on: BF) -> anyhow::Result<Vec<u8>>
    where
        EOF: Fn() -> Result<()>,
        BF: Fn(&[u8]) -> Option<Vec<u8>>,
    {
        let mut data = vec![0u8; MAX_PKT_SIZE];

        let mut buf = Vec::new();
        loop {
            let dur = std::time::Duration::from_millis(50);
            match timeout(dur, self.read(&mut data)).await {
                Ok(Ok(0)) => {
                    eof()?;
                    break;
                }
                Ok(Ok(sz)) => {
                    trace!("Read {sz} bytes from TCP stream");
                    data.truncate(sz);
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
            }

            buf.extend_from_slice(&data);
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
    who: &SocketAddr,
    config: &RuntimeConfig,
    cache: &Arc<RwLock<dns_cache::Cache>>,
    bytes: Vec<u8>,
    dns_start_location: usize, // for TCP this should be 2, for UDP it should be 0
    get_data: F,
) -> Result<Vec<u8>>
where
    F: AsyncFn(SocketAddr, &Arc<Vec<u8>>) -> Result<Vec<u8>> + Clone,
{
    process_dns_request(who, config, cache, bytes, dns_start_location, get_data).await
}
