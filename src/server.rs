use std::sync::{Arc, RwLock};

use anyhow::Result;
use futures::future::select_all;
use simple_dns as dns;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net,
    sync::mpsc,
    time::timeout,
};
use tracing::{error, info, trace, warn};

use crate::{config::Config, dns_cache};

const ADDR: &str = "0.0.0.0:53";
const LOCAL_ADDR: &str = "127.0.0.53:53";
const MAX_PKT_SIZE: usize = 65535;

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
        config: &Config,
        cache: &Arc<RwLock<dns_cache::Cache>>,
    ) -> Option<Vec<dns::ResourceRecord<'_>>>;
}

impl DnsAnswers for dns::Question<'_> {
    fn check(
        &self,
        config: &Config,
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

async fn process_dns_request(
    config: &Config,
    cache: &Arc<RwLock<dns_cache::Cache>>,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    let Ok(pkt) = dns::Packet::parse(bytes) else {
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
        return Ok(reply_data);
    }

    let futures = config.get_nameservers().iter().map(|&ns| {
        let mut rec_buf = vec![0u8; MAX_PKT_SIZE];
        Box::pin(async move {
            let Ok(dns_sock) = net::UdpSocket::bind("0.0.0.0:0").await else {
                return Err(anyhow::anyhow!("Failed to bind UDP socket"));
            };
            if dns_sock.connect(ns).await.is_err() {
                return Err(anyhow::anyhow!("Failed to connect to DNS server"));
            }
            if dns_sock.send(bytes).await.is_err() {
                return Err(anyhow::anyhow!("Failed to send DNS packet"));
            }
            let dur = std::time::Duration::from_millis(500);
            let Ok(Ok(sz)) = timeout(dur, dns_sock.recv(&mut rec_buf)).await else {
                return Err(anyhow::anyhow!("Timeout when connecting to {ns}"));
            };
            let data = &rec_buf[..sz];
            if let Ok(pkt) = dns::Packet::parse(data) {
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
                                trace!("{qname}:{ttl} A: {addr}");
                            }
                            dns::rdata::RData::AAAA(a) => {
                                let addr =
                                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(a.address));
                                cache
                                    .write()
                                    .expect("cache write lock poisoned")
                                    .insert(qname.to_string(), dns_cache::IpAddr::new(addr, ttl));
                                trace!("{qname}:{ttl} A: {addr}");
                            }
                            _ => (),
                        }
                    }
                }
                return Ok(data.to_vec());
            }
            Err(anyhow::anyhow!("Failed to parse DNS packet"))
        })
    });

    match select_all(futures).await {
        (Ok(data), _, _) => Ok(data),
        _ => anyhow::bail!("Failed to get a response from any nameserver"),
    }
}

pub fn udp_server(config: Arc<Config>, cache: Arc<RwLock<dns_cache::Cache>>) -> Result<()> {
    let remote_sock = Arc::new(udp_sock(ADDR)?);
    let local_sock = Arc::new(udp_sock(LOCAL_ADDR)?);

    let (tx, mut rx) = mpsc::channel::<ChannelData>(64);

    tokio::spawn(async move {
        while let Some(channel_data) = rx.recv().await {
            let config = config.clone();
            let cache = cache.clone();
            tokio::spawn(async move {
                let bytes = channel_data.bytes;
                let addr = channel_data.addr;
                let sock = channel_data.sock;

                if let Ok(reply_data) = process_dns_request(&config, &cache, &bytes).await {
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
    config: Arc<Config>,
    cache: Arc<RwLock<dns_cache::Cache>>,
) -> anyhow::Result<()> {
    let dur = std::time::Duration::from_millis(250);
    let sock = net::TcpListener::bind("0.0.0.0:53")
        .await
        .inspect_err(|e| error!("Failed to bind TCP socket: {e}"))?;
    let sock = Arc::new(sock);
    let r_sock = sock.clone();

    info!("Socket listening on {}", sock.local_addr()?);

    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, net::TcpStream)>(1000);

    tokio::spawn(async move {
        while let Some((bytes, mut sock)) = rx.recv().await {
            let config = config.clone();
            let cache = cache.clone();
            tokio::spawn(async move {
                if let Ok(reply_data) = process_dns_request(&config, &cache, &bytes).await
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
            .local_addr()
            .map_or_else(|_| "unknown socket".to_string(), |a| a.to_string());

        let buf = match timeout(dur, Box::pin(sock.read_eof())).await {
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
            error!("Failed to send TCP data to channel: {e}");
            anyhow::bail!("Channel send failed: {e}");
        }
    }
}

pub trait Eof {
    async fn read_eof(&mut self) -> anyhow::Result<Vec<u8>>;
}

impl Eof for net::TcpStream {
    async fn read_eof(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut tmp = vec![0u8; MAX_PKT_SIZE];

        let mut buf = Vec::new();
        loop {
            let sz = self.read(&mut tmp).await?;
            let data = &tmp[..sz];
            if sz == 0 {
                break;
            }

            buf.extend_from_slice(data);
            if buf.len() < 2 {
                continue; // Not enough data to parse a DNS packet
            }
            if dns::Packet::parse(&buf[2..]).is_ok() {
                break;
            }
        }

        Ok(buf)
    }
}
