use anyhow::Result;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::block_filter::{BlockFilter, BlockFilterBuilder};

const DEFAULT_DOT_PORT: u16 = 853;

#[derive(Deserialize, serde::Serialize, Default, Debug)]
pub struct StartupConfig {
    pub local_network: LocalNetwork,
    #[serde(default = "Nameservers::default")]
    pub nameservers: Nameservers,
    #[serde(default = "Domains::default")]
    pub local_domains: Domains,
    #[serde(default = "Options::default")]
    pub options: Options,
}

#[derive(Deserialize, serde::Serialize, Debug)]
pub struct Options {
    #[serde(default = "default_dot")]
    pub dot: String,
    pub blocklist_dir: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            dot: default_dot(),
            blocklist_dir: None,
        }
    }
}

fn default_dot() -> String {
    "off".to_string()
}

#[derive(Debug, PartialEq, Eq)]
pub enum DotEnabled {
    Off,
    On,
    Force,
}

impl From<&str> for DotEnabled {
    fn from(value: &str) -> Self {
        match value {
            "off" => Self::Off,
            "on" => Self::On,
            "force" => Self::Force,
            _ => {
                warn!("Invalid DoT option: {value}, defaulting to 'off'");
                Self::Off
            }
        }
    }
}

// #[derive(Debug)]
pub struct RuntimeConfig {
    pub local_network: LocalNetwork,
    pub local_domains: Domains,
    pub block_filter: BlockFilter,
    pub nameservers: Vec<std::net::SocketAddr>,
    pub dot_servers: Vec<DotServer>,
    pub dot: DotEnabled,
    pub tls_config: Arc<rustls::ClientConfig>,
}

#[derive(Deserialize, serde::Serialize, Default, Debug)]
pub struct Domains {
    pub domains: Option<Vec<String>>,
}

#[derive(Deserialize, serde::Serialize, Default, Debug)]
pub struct BlockFilters {
    pub files: Option<Vec<String>>,
}

#[derive(Deserialize, serde::Serialize, Default, Debug)]
pub struct Nameservers {
    pub ip4: HashSet<String>,
    pub dot: Option<Vec<DotServer>>,
}

#[derive(Deserialize, serde::Serialize, Clone, Debug)]
pub struct DotServer {
    pub hostname: String,
    #[serde(default = "default_dot_port")]
    pub port: u16,
    pub ip: std::net::IpAddr,
}

const fn default_dot_port() -> u16 {
    DEFAULT_DOT_PORT
}

#[derive(Deserialize, serde::Serialize, Default, Clone, Debug)]
pub struct LocalNetwork {
    #[serde(flatten)]
    pub hosts: std::collections::BTreeMap<String, std::net::IpAddr>,
}

impl std::str::FromStr for StartupConfig {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let me = toml::from_str(s).map_err(|e| {
            error!("error: {e}");
            anyhow::anyhow!("Failed to parse configuration: {e}")
        });

        info!("StartupConfig: {me:#?}");
        me
    }
}

impl RuntimeConfig {
    #[must_use]
    pub fn has_addr(&self, value: &str) -> Option<std::net::IpAddr> {
        if let Some(addr) = self.local_network.hosts.get(value) {
            return Some(*addr);
        }

        let Some(domains) = &self.local_domains.domains else {
            return None;
        };

        // Having the domains be a hashset would be more performant,
        // if there are lots of domains.  But the amount of domains
        // will usually be small, so a Vec is preferred.
        for domain in domains {
            if value.ends_with(domain) {
                let host_len = value.len() - domain.len() - 1;
                let host_str = &value[0..host_len];
                if let Some(addr) = self.local_network.hosts.get(host_str) {
                    return Some(*addr);
                }
            }
        }

        None
    }

    #[must_use]
    pub fn has_block(&self, value: &str) -> bool {
        // a reverse check would be faster for the case where
        // we should return true, however that's the minority case.
        let mut name = value;
        while !name.is_empty() {
            if self.block_filter.contains(name) {
                return true;
            }
            if let Some((_, value)) = name.split_once('.') {
                name = value;
            } else {
                break;
            }
        }

        false
    }

    #[must_use]
    pub fn get_nameservers(&self) -> &[std::net::SocketAddr] {
        &self.nameservers
    }

    #[must_use]
    pub fn get_dot_servers(&self) -> &[DotServer] {
        &self.dot_servers
    }
}

impl From<StartupConfig> for RuntimeConfig {
    fn from(startup: StartupConfig) -> Self {
        // Load blocklists
        let blocklist_builder = BlockFilterBuilder::from(startup.options.blocklist_dir.as_deref());

        // Build filter
        let block_filter = blocklist_builder.build();

        // Cache nameservers
        let nameservers: Vec<_> = startup
            .nameservers
            .ip4
            .into_iter()
            .filter_map(|ip| {
                let ns = ip
                    .parse()
                    .inspect_err(|e| {
                        error!("nameserver must be a valid IP address: skipping {ip}: error: {e}");
                    })
                    .ok()?;
                Some(std::net::SocketAddr::new(ns, 53))
            })
            .collect();

        debug!("Cached {} nameservers", nameservers.len());

        let dot_servers = startup.nameservers.dot.unwrap_or_default();
        // Install the default crypto provider (ring)
        _ = rustls::crypto::ring::default_provider().install_default();

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self {
            local_network: startup.local_network,
            local_domains: startup.local_domains,
            block_filter,
            nameservers,
            dot_servers,
            dot: startup.options.dot.as_str().into(),
            tls_config: Arc::new(tls_config),
        }
    }
}
