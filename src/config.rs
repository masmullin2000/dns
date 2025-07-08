use anyhow::Result;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use tracing::{debug, error, warn};

#[derive(Deserialize, Default, Debug)]
pub struct StartupConfig {
    pub local_network: LocalNetwork,
    #[serde(default = "Nameservers::default")]
    pub nameservers: Nameservers,
    #[serde(default = "Domains::default")]
    pub local_domains: Domains,
    #[serde(default = "Blocklists::default")]
    pub blocklists: Blocklists,
}

#[derive(Debug)]
pub struct RuntimeConfig {
    pub local_network: LocalNetwork,
    pub local_domains: Domains,
    pub block_filter: Option<bloomfilter::Bloom<str>>,
    pub nameservers: Vec<std::net::SocketAddr>,
}

#[derive(Deserialize, Default, Debug)]
pub struct Domains {
    pub domains: Option<Vec<String>>,
}

#[derive(Deserialize, Default, Debug)]
pub struct Blocklists {
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
        let Some(ref blocklist) = self.block_filter else {
            return false;
        };

        // a reverse check would be faster for the case where
        // we should return true, however that's the minority case.
        let mut name = value;
        while !name.is_empty() {
            if blocklist.check(name) {
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
        let blocklist_builder = BlocklistBuilder::from(startup.blocklists.files);

        // Build bloom filter
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

#[derive(Default, Debug)]
pub struct BlocklistBuilder(HashSet<String>);

impl BlocklistBuilder {
    pub fn set_file(&mut self, block_file: &str) -> Result<()> {
        let file = std::fs::read_to_string(block_file)?;
        for line in file.lines() {
            self.set_item(line);
        }
        Ok(())
    }

    pub fn set_item(&mut self, item: &str) {
        let item = item.trim();
        if item.is_empty() {
        } else if let Some(name) = item.strip_prefix("*.") {
            self.0.insert(name.into());
        } else {
            self.0.insert(item.into());
        }
    }

    pub fn build(self) -> Option<bloomfilter::Bloom<str>> {
        if self.0.is_empty() {
            warn!("Blocklist Size 0");
            None
        } else {
            bloomfilter::Bloom::new_for_fp_rate(self.0.len(), 0.00001).map_or_else(
                |e| {
                    error!(
                        "Failed to create bloom filter for blocklist - {e}: blocklist inoperable"
                    );
                    None
                },
                |mut filter| {
                    for item in &self.0 {
                        filter.set(item.as_str());
                    }
                    debug!("Blocklist Size {}", self.0.len());
                    Some(filter)
                },
            )
        }
    }

    #[must_use]
    pub fn contains(&self, domain: &str) -> bool {
        self.0.contains(domain)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<String>> for BlocklistBuilder {
    fn from(block_files: Vec<String>) -> Self {
        let mut builder = Self::default();
        for block_file in &block_files {
            if let Err(e) = builder.set_file(block_file) {
                error!("Failed to load blocklist file {block_file}: {e}");
            }
        }
        builder
    }
}

impl From<Option<Vec<String>>> for BlocklistBuilder {
    fn from(block_files: Option<Vec<String>>) -> Self {
        let Some(blocklists) = block_files else {
            warn!("No blocklists defined in config");
            return Self::default();
        };
        Self::from(blocklists)
    }
}
