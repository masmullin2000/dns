use std::sync::Arc;

use simple_dns as dns;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio::spawn(async { udp_server(); });
    Box::pin(tcp_server()).await
}

const ADDR: &str = "0.0.0.0:53";
const LOCAL_ADDR: &str = "127.0.0.53:53";

fn udp_sock(addr: &str) -> net::UdpSocket {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    let addr: std::net::SocketAddr = addr.parse().unwrap();
    sock.set_reuse_port(true).unwrap();
    sock.bind(&addr.into()).unwrap();
    sock.set_nonblocking(true).unwrap();

    let sock: std::net::UdpSocket = sock.into();
    let sock = net::UdpSocket::from_std(sock).unwrap();
    println!("Listening on {}", sock.local_addr().unwrap());

    sock
}

fn udp_server() {
    let remote_sock = Arc::new(udp_sock(ADDR));
    let local_sock = Arc::new(udp_sock(LOCAL_ADDR));

    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, std::net::SocketAddr, Arc<net::UdpSocket>)>(1000);

    tokio::spawn(async move {
        let mut rec_buf = [0u8; 65535];
        'recv: while let Some((bytes, addr, sock)) = rx.recv().await {
            let Ok(pkt) = dns::Packet::parse(&bytes) else {
                eprintln!("Failed to parse DNS packet");
                continue;
            };

            for question in &pkt.questions {
                let labels = question.qname.get_labels();

                let mut answers: Vec<_> = labels
                    .iter()
                    .filter_map(|label| {
                        let Ok(name) = std::str::from_utf8(label.data()) else {
                            return None;
                        };
                        if "dns" == name {
                            let class = match question.qclass {
                                dns::QCLASS::CLASS(class) => class,
                                dns::QCLASS::ANY => dns::CLASS::NONE,
                            };
                            Some(dns::ResourceRecord::new(
                                question.qname.clone(),
                                class,
                                300,
                                dns::rdata::RData::A(dns::rdata::A::from(
                                    std::net::Ipv4Addr::from([192, 168, 0, 2]),
                                )),
                            ))
                        } else {
                            None
                        }
                    })
                    .collect();

                if !answers.is_empty() {
                    let mut reply = pkt.into_reply();
                    reply.set_flags(
                        dns::PacketFlag::RESPONSE
                            | dns::PacketFlag::RECURSION_DESIRED
                            | dns::PacketFlag::RECURSION_AVAILABLE,
                    );
                    reply.answers.append(&mut answers);
                    let reply_data = reply.build_bytes_vec().unwrap();

                    sock.send_to(&reply_data, addr).await.unwrap();

                    continue 'recv;
                }
            }

            let dns_sock = net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
            dns_sock.connect("1.1.1.1:53").await.unwrap();
            dns_sock.send(&bytes).await.unwrap();
            let sz = dns_sock.recv(&mut rec_buf).await.unwrap();
            let data = &rec_buf[..sz];

            let Ok(_pkt) = dns::Packet::parse(data) else {
                eprintln!("Failed to parse DNS packet");
                continue;
            };

            sock.send_to(data, addr).await.unwrap();
        }
    });

    let rtx = tx.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let (sz, addr) = remote_sock.recv_from(&mut buf).await.unwrap();
            let buf = buf[..sz].to_vec();
            rtx.send((buf, addr, remote_sock.clone())).await.unwrap();
        }
    });

    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let (sz, addr) = local_sock.recv_from(&mut buf).await.unwrap();
            let buf = buf[..sz].to_vec();
            tx.send((buf, addr, local_sock.clone())).await.unwrap();
        }
    });
}

async fn tcp_server() -> anyhow::Result<()> {
    let sock = net::TcpListener::bind("0.0.0.0:53")
        .await
        .inspect_err(|e| eprintln!("Failed to bind UDP socket: {e}"))?;
    let sock = Arc::new(sock);
    let r_sock = sock.clone();

    println!("Listening on {}", sock.local_addr()?);

    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, net::TcpStream)>(1000);

    tokio::spawn(async move {
        while let Some((bytes, mut sock)) = rx.recv().await {
            let mut dns_sock = net::TcpStream::connect("1.1.1.1:53").await.unwrap();
            dns_sock.write_all(&bytes).await.unwrap();
            let data = Box::pin(dns_sock.read_eof()).await;

            sock.write_all(&data).await.unwrap();
        }
    });

    loop {
        let (mut sock, _) = r_sock.accept().await?;
        let buf = Box::pin(sock.read_eof()).await;
        tx.send((buf, sock)).await?;
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
