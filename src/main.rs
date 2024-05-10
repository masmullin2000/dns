use std::sync::Arc;

use anyhow::{bail, Result};
use simple_dns as dns;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net,
    sync::mpsc,
    time::timeout,
};

type Sender = mpsc::Sender<ChannelData>;

const ADDR: &str = "0.0.0.0:53";
const LOCAL_ADDR: &str = "127.0.0.53:53";

#[tokio::main]
async fn main() -> Result<()> {
    std::panic::set_hook(Box::new(|p| {
        eprintln!("panic: {p:?}");
        std::process::exit(1);
    }));

    let config: Arc<Config> = Arc::new("/code/dns/dns.toml".parse()?);

    tokio::spawn(async {
        udp_server(config).expect("udp_server failed");
    });
    Box::pin(tcp_server()).await
}

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

#[derive(Clone)]
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

#[derive(Default, Clone)]
struct Config {
    dns: Vec<DnsConfig>,
    domains: Vec<String>,
    nameservers: Vec<std::net::SocketAddr>,
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

impl std::str::FromStr for Config {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let file = std::fs::read_to_string(s)?;
        let toml: toml::Table = toml::from_str(&file)?;

        let mut config = Self::default();

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
                "nameservers" => {
                    println!("{value:?}");
                    let nameservers = value.as_table().expect("nameservers must be an array");
                    config.nameservers = nameservers
                        .iter()
                        .filter_map(|(ip, val)| {
                            if !val.as_bool()? {
                               return None;
                            };
                            let ns: std::net::IpAddr = ip
                                .parse()
                                .inspect_err(|e| {
                                    eprintln!("nameserver must be a valid IP address: skipping {ip}: error: {e}");
                                })
                                .ok()?;
                            println!("found nameserver: {ns}");
                            Some(std::net::SocketAddr::new(ns, 53))
                        })
                        .collect();
                }
                val => {
                    bail!("Unknown toml entry key: {val}");
                }
            }
        }

        if config.nameservers.is_empty() {
            bail!("No nameservers specified");
        }

        Ok(config)
    }
}

fn udp_sock(addr: impl AsRef<str>) -> Result<net::UdpSocket> {
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

fn udp_server(config: Arc<Config>) -> Result<()> {
    let remote_sock = Arc::new(udp_sock(ADDR)?);
    let local_sock = Arc::new(udp_sock(LOCAL_ADDR)?);

    let (tx, mut rx) = mpsc::channel::<ChannelData>(1000);

    tokio::spawn(async move {
        let mut rec_buf = [0u8; 65535];
        while let Some(channel_data) = rx.recv().await {
            let config = config.clone();
            tokio::spawn(async move {
                let bytes = channel_data.bytes.as_slice();
                let addr = &channel_data.addr;
                let sock = &channel_data.sock;

                let Ok(pkt) = dns::Packet::parse(bytes) else {
                    eprintln!("Failed to parse DNS packet");
                    return;
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

                    return;
                }

                let Ok(dns_sock) = net::UdpSocket::bind("0.0.0.0:0")
                    .await
                    .inspect_err(|e| eprintln!("Failed to bind UDP socket: {e}"))
                else {
                    return;
                };

                for ns in &config.nameservers {
                    if let Err(e) = dns_sock.connect(ns).await {
                        eprintln!("Failed to connect to DNS server: {e}");
                        continue;
                    };
                    if let Err(e) = dns_sock.send(bytes).await {
                        eprintln!("Failed to send DNS packet: {e}");
                        continue;
                    };
                    let dur = std::time::Duration::from_millis(250);
                    let sz = match timeout(dur, dns_sock.recv(&mut rec_buf)).await {
                        Ok(Ok(sz)) => sz,
                        Err(_) => {
                            eprintln!("Timeout when connecting to {ns}");
                            continue;
                        }
                        Ok(Err(e)) => {
                            eprintln!("Failed to receive DNS packet: {e}");
                            continue;
                        }
                    };
                    let data = &rec_buf[..sz];

                    if dns::Packet::parse(data).is_err() {
                        eprintln!("Failed to parse DNS packet");
                        continue;
                    };

                    let Err(e) = sock.send_to(data, addr).await else {
                        return;
                    };
                    eprintln!("Failed to send DNS packet to {addr}: {e}");
                }
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
    let dur = std::time::Duration::from_millis(250);
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
            let Ok(data) = timeout(dur, Box::pin(dns_sock.read_eof())).await else {
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
        let Ok(buf) = timeout(dur, Box::pin(sock.read_eof()))
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
