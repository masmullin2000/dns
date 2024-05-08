use std::sync::Arc;

use anyhow::{bail, Result};
use simple_dns as dns;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net;
use tokio::sync::mpsc;

struct ChannelData {
    bytes: Vec<u8>,
    addr: std::net::SocketAddr,
    sock: Arc<net::UdpSocket>,
}

impl ChannelData {
    fn new(bytes: Vec<u8>, addr: std::net::SocketAddr, sock: Arc<net::UdpSocket>) -> Self {
        Self { bytes, addr, sock }
    }
}

type Sender = mpsc::Sender<ChannelData>;

const ADDR: &str = "0.0.0.0:53";
const LOCAL_ADDR: &str = "127.0.0.53:53";

struct DnsConfig {
    addr: std::net::IpAddr,
    name: String,
}

impl<S> From<(S, std::net::IpAddr)> for DnsConfig
where
    S: Into<String>,
{
    fn from(value: (S, std::net::IpAddr)) -> Self {
        let (name, addr) = value;
        Self {
            addr,
            name: name.into(),
        }
    }
}

#[derive(Default)]
struct Config {
    dns: Vec<DnsConfig>,
    domains: Vec<String>,
}

impl Config {
    fn has_addr(&self, value: &str) -> Option<std::net::IpAddr> {
        for dns in &self.dns {
            let local = dns.name.as_str();
            if value == local {
                return Some(dns.addr);
            }
            for domain in &self.domains {
                let mut local_domain: String = local.into();
                local_domain.push('.');
                local_domain.push_str(domain);

                if value == local_domain {
                    return Some(dns.addr);
                }
            }
        }
        None
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    std::panic::set_hook(Box::new(|p| {
        eprintln!("panic: {p:?}");
        std::process::exit(1);
    }));

    let config = parse_config("/code/dns/dns.toml")?;

    tokio::spawn(async {
        udp_server(config).expect("udp_server failed");
    });
    Box::pin(tcp_server()).await
}

fn parse_config(file: &str) -> Result<Config> {
    let file = std::fs::read_to_string(file)?;
    let toml: toml::Table = toml::from_str(&file)?;

    let mut config = Config::default();

    for (key, value) in toml {
        match key.to_lowercase().as_str() {
            "localnetwork" | "localnetworks" => {
                let ln = value.as_table().expect("LocalNetwork must be a table");
                for (name, addr) in ln {
                    if name == "domains" {
                        let domains = addr.as_array().expect("domains must be an array");
                        for domain in domains {
                            let domain = domain.as_str().expect("domain must be a string");
                            config.domains.push(domain.to_string());
                        }
                        continue;
                    }
                    let addr = addr.as_str().expect("dns addr must be a string");
                    let addr: std::net::IpAddr =
                        addr.parse().expect("dns addr must be a valid IP address");
                    let dns_cfg = (name, addr).into();
                    config.dns.push(dns_cfg);
                }
            }
            val => {
                bail!("Unknown toml entry key: {val}");
            }
        }
    }

    Ok(config)
}

fn udp_sock(addr: &str) -> Result<net::UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    let addr: std::net::SocketAddr = addr.parse()?;
    sock.set_reuse_port(true)?;
    sock.bind(&addr.into())?;
    sock.set_nonblocking(true)?;

    let sock: std::net::UdpSocket = sock.into();
    let sock = net::UdpSocket::from_std(sock)?;
    println!("Listening on {}", sock.local_addr()?);

    Ok(sock)
}

trait MakeDnsAnswers {
    fn make_dns_answers(&self, config: &Config) -> Vec<dns::ResourceRecord>;
}

impl MakeDnsAnswers for dns::Question<'_> {
    fn make_dns_answers(&self, config: &Config) -> Vec<dns::ResourceRecord<'_>> {
        let labels = self.qname.get_labels();

        labels
            .iter()
            .filter_map(|label| {
                let name = std::str::from_utf8(label.data()).ok()?;
                let addr = config.has_addr(name)?;
                let class = match self.qclass {
                    dns::QCLASS::CLASS(class) => class,
                    dns::QCLASS::ANY => dns::CLASS::NONE,
                };

                let rdata = match addr {
                    std::net::IpAddr::V4(addr) => dns::rdata::RData::A(dns::rdata::A::from(addr)),
                    std::net::IpAddr::V6(addr) => {
                        dns::rdata::RData::AAAA(dns::rdata::AAAA::from(addr))
                    }
                };

                Some(dns::ResourceRecord::new(
                    self.qname.clone(),
                    class,
                    300,
                    rdata,
                ))
            })
            .collect()
    }
}

fn udp_server(config: Config) -> Result<()> {
    let remote_sock = Arc::new(udp_sock(ADDR)?);
    let local_sock = Arc::new(udp_sock(LOCAL_ADDR)?);

    let (tx, mut rx) = mpsc::channel::<ChannelData>(1000);

    tokio::spawn(async move {
        let mut rec_buf = [0u8; 65535];
        while let Some(channel_data) = rx.recv().await {
            let bytes = channel_data.bytes.as_slice();
            let addr = &channel_data.addr;
            let sock = &channel_data.sock;

            let Ok(pkt) = dns::Packet::parse(bytes) else {
                eprintln!("Failed to parse DNS packet");
                continue;
            };

            let mut answers = Vec::new();

            for question in &pkt.questions {
                let mut ans = question.make_dns_answers(&config);
                answers.append(&mut ans);
            }

            if !answers.is_empty() {
                let mut reply = pkt.clone().into_reply();
                reply.set_flags(
                    dns::PacketFlag::RESPONSE
                        | dns::PacketFlag::RECURSION_DESIRED
                        | dns::PacketFlag::RECURSION_AVAILABLE,
                );
                reply.answers = answers;
                let reply_data = reply.build_bytes_vec().unwrap();

                _ = sock.send_to(&reply_data, addr).await.inspect_err(|e| {
                    eprintln!("Failed to send custom DNS packet to {addr}: {e}");
                });

                continue;
            }

            let Ok(dns_sock) = net::UdpSocket::bind("0.0.0.0:0")
                .await
                .inspect_err(|e| eprintln!("Failed to bind UDP socket: {e}"))
            else {
                continue;
            };
            if let Err(e) = dns_sock.connect("1.1.1.1:53").await {
                eprintln!("Failed to connect to DNS server: {e}");
                continue;
            };
            if let Err(e) = dns_sock.send(bytes).await {
                eprintln!("Failed to send DNS packet: {e}");
                continue;
            };
            let Ok(sz) = dns_sock.recv(&mut rec_buf).await.inspect_err(|e| {
                eprintln!("Failed to receive DNS packet: {e}");
            }) else {
                continue;
            };
            let data = &rec_buf[..sz];

            if dns::Packet::parse(data).is_err() {
                eprintln!("Failed to parse DNS packet");
                continue;
            };

            _ = sock.send_to(data, addr).await.inspect_err(|e| {
                eprintln!("Failed to send DNS packet to {addr}: {e}");
            });
        }
    });

    let recv_loop = |sock: Arc<net::UdpSocket>, tx: Sender| async move {
        let mut buf = [0u8; 65535];
        loop {
            let Ok((sz, addr)) = sock.recv_from(&mut buf).await.inspect_err(|e| {
                eprintln!("Failed to receive DNS packet: {e}");
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

async fn tcp_server() -> anyhow::Result<()> {
    let timeout = std::time::Duration::from_millis(250);
    let sock = net::TcpListener::bind("0.0.0.0:53")
        .await
        .inspect_err(|e| eprintln!("Failed to bind UDP socket: {e}"))?;
    let sock = Arc::new(sock);
    let r_sock = sock.clone();

    println!("Listening on {}", sock.local_addr()?);

    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, net::TcpStream)>(1000);

    tokio::spawn(async move {
        while let Some((bytes, mut sock)) = rx.recv().await {
            let Ok(mut dns_sock) = net::TcpStream::connect("1.1.1.1:53")
                .await
                .inspect_err(|e| {
                    eprintln!("Failed to connect to DNS server: {e}");
                })
            else {
                continue;
            };
            if let Err(e) = dns_sock.write_all(&bytes).await {
                eprintln!("Failed to send DNS packet: {e}");
                continue;
            }
            let Ok(data) = tokio::time::timeout(timeout, Box::pin(dns_sock.read_eof())).await
            else {
                continue;
            };

            if let Err(e) = sock.write_all(&data).await {
                eprintln!("Failed to send DNS packet to {sock:?}: {e}");
                continue;
            }
        }
    });

    loop {
        let Ok((mut sock, _)) = r_sock.accept().await.inspect_err(|e| {
            eprintln!("Failed to accept TCP connection: {e}");
        }) else {
            continue;
        };
        let Ok(buf) = tokio::time::timeout(timeout, Box::pin(sock.read_eof()))
            .await
            .inspect_err(|e| {
                eprintln!("Failed to receive DNS packet from {sock:?}: {e}");
            })
        else {
            continue;
        };
        tx.send((buf, sock)).await.expect("channel send failed");
    }
}

trait Eof {
    async fn read_eof(&mut self) -> Vec<u8>;
}

impl Eof for net::TcpStream {
    async fn read_eof(&mut self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 65535];
        loop {
            let sz = self.read(&mut tmp).await.unwrap();
            let data = &tmp[..sz];
            if sz == 0 {
                break;
            }

            buf.extend_from_slice(data);
            if dns::Packet::parse(&buf[2..]).is_ok() {
                break;
            }
        }
        buf
    }
}
