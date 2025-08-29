use anyhow::Result;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use tracing::{debug, error};

use crate::block_filter::{BlockFilter, BlockFilterBuilder};

#[derive(Deserialize, Default, Debug)]
pub struct StartupConfig {
    pub local_network: LocalNetwork,
    #[serde(default = "Nameservers::default")]
    pub nameservers: Nameservers,
    #[serde(default = "Domains::default")]
    pub local_domains: Domains,
    #[serde(default = "BlockFilters::default")]
    pub blocklists: BlockFilters,
}

#[derive(Debug)]
pub struct RuntimeConfig {
    pub local_network: LocalNetwork,
    pub local_domains: Domains,
    pub block_filter: BlockFilter,
    pub nameservers: Vec<std::net::SocketAddr>,
}

#[derive(Deserialize, Default, Debug)]
pub struct Domains {
    pub domains: Option<Vec<String>>,
}

#[derive(Deserialize, Default, Debug)]
pub struct BlockFilters {
    pub files: Option<Vec<String>>,
}

#[derive(Deserialize, Default, Debug)]
pub struct Nameservers {
    pub ip4: HashSet<String>,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct LocalNetwork {
    #[serde(flatten)]
    pub hosts: HashMap<String, std::net::IpAddr>,
}

impl std::str::FromStr for StartupConfig {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        toml::from_str(s).map_err(|e| {
            error!("error: {e}");
            anyhow::anyhow!("Failed to parse configuration: {e}")
        })
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
}

impl From<StartupConfig> for RuntimeConfig {
    fn from(startup: StartupConfig) -> Self {
        // Load blocklists
        let blocklist_builder = BlockFilterBuilder::from(startup.blocklists.files);

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

        Self {
            local_network: startup.local_network,
            local_domains: startup.local_domains,
            block_filter,
            nameservers,
        }
    }
}
