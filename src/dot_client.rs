use std::{collections::VecDeque, sync::Arc, time::Duration};

use anyhow::Result;
use rustls::pki_types::{DnsName, ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{debug, trace};

use crate::config;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
pub struct DotPool {
    servers: std::collections::HashMap<String, VecDeque<DotConnection>>,
}

impl DotPool {
    pub fn get_connection(&mut self, server: &config::DotServer) -> Option<DotConnection> {
        let connections = self.servers.get_mut(&server.hostname)?;
        while let Some(res) = connections.pop_back() {
            if res.ts.elapsed() > Duration::from_millis(10_000) {
                trace!("Dropping stale DoT connection to {}", server.hostname);
                continue;
            }
            return Some(res);
        }
        None
    }

    pub fn return_connection(&mut self, server: &config::DotServer, conn: DotConnection) {
        let connections = self.servers.entry(server.hostname.clone()).or_default();
        connections.push_front(conn);
    }
}

pub struct DotConnection {
    stream: TlsStream<TcpStream>,
    ts: std::time::Instant,
}

impl DotConnection {
    pub async fn try_new(
        server: &config::DotServer,
        tls_config: &Arc<rustls::ClientConfig>,
    ) -> Result<Self> {
        let addr = std::net::SocketAddr::new(server.ip, server.port);
        let sock = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            None, //Some(socket2::Protocol::TCP),
        )?;
        sock.connect(&addr.into()).or_else(|e| {
            debug!("connect error: {e}");
            if e.kind() == std::io::ErrorKind::WouldBlock {
                Ok(())
            } else {
                Err(e)
            }
        })?;
        sock.set_nonblocking(true)
            .inspect_err(|e| debug!("set set_nonblocking failed: {e}"))?;
        // sock.set_keepalive(true).inspect_err(|e| debug!("set set_keepalive failed: {e}"))?;

        let keep_alive_duration = socket2::TcpKeepalive::new().with_time(Duration::from_secs(10));
        sock.set_tcp_keepalive(&keep_alive_duration)
            .inspect_err(|e| debug!("set set_tcp_keepalive failed: {e}"))?;

        let tcp_stream = sock.into();
        let tcp_stream = TcpStream::from_std(tcp_stream)
            .inspect_err(|e| debug!("convert to tokio::TcpStream failed: {e}"))?;

        tcp_stream
            .set_nodelay(true)
            .inspect_err(|e| debug!("set set_nodelay failed: {e}"))?;

        let server_name = ServerName::DnsName(
            DnsName::try_from(server.hostname.clone())
                .map_err(|_| anyhow::anyhow!("Invalid DNS name: {}", server.hostname))?,
        );

        let connector = TlsConnector::from(tls_config.clone());
        let tls_stream = tokio::time::timeout(
            CONNECTION_TIMEOUT,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .inspect_err(|e| debug!("Connection Timeout: {e}"))?
        .inspect_err(|e| debug!("TlsStream error: {e}"))?;

        debug!(
            "Established DoT connection to {}:{}",
            server.hostname, server.port
        );

        Ok(Self {
            stream: tls_stream,
            ts: std::time::Instant::now(),
        })
    }

    pub async fn send_query(&mut self, query: &[u8]) -> Result<Vec<u8>> {
        let now = std::time::Instant::now();
        // DNS over TLS uses TCP framing: 2-byte length prefix (big-endian)
        let len = u16::try_from(query.len()).map_err(|_| anyhow::anyhow!("DNS query too large"))?;
        let len_bytes = len.to_be_bytes();

        self.stream
            .write_all(&len_bytes)
            .await
            .inspect_err(|e| debug!("write all len failed: {e}"))?;
        self.stream
            .write_all(query)
            .await
            .inspect_err(|e| debug!("write all query failed: {e}"))?;
        self.stream
            .flush()
            .await
            .inspect_err(|e| debug!("write all flush failed: {e}"))?;

        // Read response length
        let mut len_buf = [0u8; 2];
        self.stream
            .read_exact(&mut len_buf)
            .await
            .inspect_err(|e| debug!("read len failed: {e}"))?;
        let response_len = u16::from_be_bytes(len_buf) as usize;

        // Read response
        let mut response = vec![0u8; response_len];
        self.stream
            .read_exact(&mut response)
            .await
            .inspect_err(|e| debug!("read response failed: {e}"))?;

        tracing::trace!(
            "DoT query completed, response size: {response_len} bytes: {}ms",
            now.elapsed().as_millis()
        );
        Ok(response)
    }
}
