use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use rustls::pki_types::{DnsName, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{debug, trace, warn};

use crate::config::DotServer;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CONNECTION_AGE: Duration = Duration::from_secs(600);

pub struct DotConnection {
    stream: TlsStream<TcpStream>,
    created_at: Instant,
    last_used: Instant,
}

impl DotConnection {
    async fn new(server: &DotServer, tls_config: Arc<rustls::ClientConfig>) -> Result<Self> {
        let addr = std::net::SocketAddr::new(server.ip, server.port);

        let tcp_stream =
            tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await??;

        tcp_stream.set_nodelay(true)?;

        let server_name = ServerName::DnsName(
            DnsName::try_from(server.hostname.clone())
                .map_err(|_| anyhow::anyhow!("Invalid DNS name: {}", server.hostname))?,
        );

        let connector = TlsConnector::from(tls_config);
        let tls_stream = tokio::time::timeout(
            CONNECTION_TIMEOUT,
            connector.connect(server_name, tcp_stream),
        )
        .await??;

        debug!(
            "Established DoT connection to {}:{}",
            server.hostname, server.port
        );

        Ok(Self {
            stream: tls_stream,
            created_at: Instant::now(),
            last_used: Instant::now(),
        })
    }

    pub async fn send_query(&mut self, query: &[u8]) -> Result<Vec<u8>> {
        self.last_used = Instant::now();

        // DNS over TLS uses TCP framing: 2-byte length prefix (big-endian)
        let len = u16::try_from(query.len()).map_err(|_| anyhow::anyhow!("DNS query too large"))?;
        let len_bytes = len.to_be_bytes();

        self.stream.write_all(&len_bytes).await?;
        self.stream.write_all(query).await?;
        self.stream.flush().await?;

        // Read response length
        let mut len_buf = [0u8; 2];
        self.stream.read_exact(&mut len_buf).await?;
        let response_len = u16::from_be_bytes(len_buf) as usize;

        // Read response
        let mut response = vec![0u8; response_len];
        self.stream.read_exact(&mut response).await?;

        trace!("DoT query completed, response size: {} bytes", response_len);
        Ok(response)
    }

    fn is_expired(&self) -> bool {
        let now = Instant::now();
        now.duration_since(self.created_at) > MAX_CONNECTION_AGE
            || now.duration_since(self.last_used) > IDLE_TIMEOUT
    }
}

pub struct DotConnectionPool {
    connections: Arc<Mutex<HashMap<String, Vec<DotConnection>>>>,
    tls_config: Arc<rustls::ClientConfig>,
}

impl DotConnectionPool {
    pub fn new() -> Self {
        // Install the default crypto provider (ring)
        let _ = rustls::crypto::ring::default_provider().install_default();
        
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            tls_config: Arc::new(tls_config),
        }
    }

    pub async fn get_connection(&self, server: &DotServer) -> Result<DotConnection> {
        let key = format!("{}:{}", server.hostname, server.port);
        let mut pool = self.connections.lock().await;

        // Try to reuse an existing connection
        if let Some(connections) = pool.get_mut(&key) {
            // Remove expired connections
            connections.retain(|conn| !conn.is_expired());

            if let Some(conn) = connections.pop() {
                debug!("Reusing existing DoT connection to {}", key);
                return Ok(conn);
            }
        }

        // Create a new connection
        drop(pool); // Release lock before creating connection
        DotConnection::new(server, self.tls_config.clone()).await
    }

    pub async fn return_connection(&self, server: &DotServer, connection: DotConnection) {
        if connection.is_expired() {
            debug!("Dropping expired DoT connection");
            return;
        }

        let key = format!("{}:{}", server.hostname, server.port);
        self.connections
            .lock()
            .await
            .entry(key.clone())
            .or_insert_with(Vec::new)
            .push(connection);

        debug!("Returned DoT connection to pool for {}", key);
    }

    pub async fn cleanup_expired(&self) {
        let mut pool = self.connections.lock().await;
        for (key, connections) in pool.iter_mut() {
            let before = connections.len();
            connections.retain(|conn| !conn.is_expired());
            let removed = before - connections.len();
            if removed > 0 {
                debug!("Removed {} expired connections for {}", removed, key);
            }
        }
    }
}

pub async fn query_dot_server(
    server: &DotServer,
    query: &[u8],
    pool: &DotConnectionPool,
) -> Result<Vec<u8>> {
    let mut connection = pool.get_connection(server).await?;

    match connection.send_query(query).await {
        Ok(response) => {
            pool.return_connection(server, connection).await;
            Ok(response)
        }
        Err(e) => {
            warn!(
                "DoT query failed for {}:{} - {}",
                server.hostname, server.port, e
            );
            Err(e)
        }
    }
}
