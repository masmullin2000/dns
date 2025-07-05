use anyhow::Result;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use tracing::{debug, error, warn};

#[derive(Deserialize, Default, Debug)]
pub struct StartupConfig {
    pub local_network: LocalNetwork,
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
    pub cached_nameservers: Vec<std::net::SocketAddr>,
}

// Keep the original Config struct for backward compatibility during transition
#[derive(Deserialize, Default, Debug)]
pub struct Config {
    pub local_network: LocalNetwork,
    pub nameservers: Nameservers,
    #[serde(default = "Domains::default")]
    pub local_domains: Domains,
    #[serde(default = "Blocklists::default")]
    pub blocklists: Blocklists,

    #[serde(skip)]
    pub blocklist_builder: HashSet<String>,
    #[serde(skip)]
    pub block_filter: Option<bloomfilter::Bloom<str>>,
    #[serde(skip)]
    pub cached_nameservers: Vec<std::net::SocketAddr>,
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
        &self.cached_nameservers
    }
}

impl StartupConfig {
    pub fn into_runtime(self) -> Result<RuntimeConfig> {
        let mut blocklist_builder = HashSet::new();

        // Load blocklists
        if let Some(blocklists) = &self.blocklists.files {
            for blocklist in blocklists {
                if let Err(e) = Self::load_blocklist_file(&mut blocklist_builder, blocklist) {
                    error!("Failed to load blocklist {blocklist}: {e}");
                }
            }
        } else {
            warn!("No blocklists defined in config");
        }

        // Build bloom filter
        let block_filter = if blocklist_builder.is_empty() {
            warn!("Blocklist Size 0");
            None
        } else {
            let Ok(mut filter) =
                bloomfilter::Bloom::new_for_fp_rate(blocklist_builder.len(), 0.00001)
            else {
                error!("Failed to create bloom filter for blocklist: blocklist inoperable");
                return Err(anyhow::anyhow!("Failed to create bloom filter"));
            };
            for item in &blocklist_builder {
                filter.set(item.as_str());
            }
            debug!("Blocklist Size {}", blocklist_builder.len());
            Some(filter)
        };

        // Cache nameservers
        let cached_nameservers: Vec<std::net::SocketAddr> = self
            .nameservers
            .ip4
            .iter()
            .filter_map(|ip| {
                let ns: std::net::IpAddr = ip
                    .parse()
                    .inspect_err(|e| {
                        error!("nameserver must be a valid IP address: skipping {ip}: error: {e}");
                    })
                    .ok()?;
                Some(std::net::SocketAddr::new(ns, 53))
            })
            .collect();

        debug!("Cached {} nameservers", cached_nameservers.len());

        Ok(RuntimeConfig {
            local_network: self.local_network,
            local_domains: self.local_domains,
            block_filter,
            cached_nameservers,
        })
    }

    fn load_blocklist_file(
        blocklist_builder: &mut HashSet<String>,
        block_file: &str,
    ) -> Result<()> {
        let file = std::fs::read_to_string(block_file)?;
        for line in file.lines() {
            Self::insert_blocklist_item(blocklist_builder, line);
        }
        Ok(())
    }

    fn insert_blocklist_item(blocklist_builder: &mut HashSet<String>, item: &str) {
        if item.is_empty() {
        } else if let Some(name) = item.strip_prefix("*.") {
            blocklist_builder.insert(name.into());
        } else {
            blocklist_builder.insert(item.into());
        }
    }
}

impl Config {
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

    fn load_blocklist_file(&mut self, block_file: &str) -> Result<()> {
        let file = std::fs::read_to_string(block_file)?;
        for line in file.lines() {
            self.insert_blocklist_item(line);
        }
        Ok(())
    }

    pub fn insert_blocklist_item(&mut self, item: &str) {
        if item.is_empty() {
        } else if let Some(name) = item.strip_prefix("*.") {
            self.blocklist_builder.insert(name.into());
        } else {
            self.blocklist_builder.insert(item.into());
        }
    }

    pub fn read_blocklists(&mut self) {
        let Some(blocklists) = self.blocklists.files.clone() else {
            warn!("No blocklists defined in config");
            return;
        };
        for blocklist in blocklists {
            _ = self.load_blocklist_file(&blocklist).inspect_err(|e| {
                error!("Failed to load blocklist {blocklist}: {e}");
            });
        }
    }

    pub fn build_blocklist(&mut self) {
        if self.blocklist_builder.is_empty() {
            warn!("Blocklist Size 0");
            return;
        }
        let Ok(mut filter) =
            bloomfilter::Bloom::new_for_fp_rate(self.blocklist_builder.len(), 0.00001)
        else {
            error!("Failed to create bloom filter for blocklist: blocklist inoperable");
            return;
        };
        for item in &self.blocklist_builder {
            filter.set(item.as_str());
        }
        self.block_filter = Some(filter);
        debug!("Blocklist Size {}", self.blocklist_builder.len());
        self.blocklist_builder.clear();
        self.blocklist_builder.shrink_to_fit();
    }

    pub fn cache_nameservers(&mut self) {
        self.cached_nameservers = self
            .nameservers
            .ip4
            .iter()
            .filter_map(|ip| {
                let ns: std::net::IpAddr = ip
                    .parse()
                    .inspect_err(|e| {
                        error!("nameserver must be a valid IP address: skipping {ip}: error: {e}");
                    })
                    .ok()?;
                Some(std::net::SocketAddr::new(ns, 53))
            })
            .collect();

        self.nameservers.ip4.clear();
        self.nameservers.ip4.shrink_to_fit();
        debug!("Cached {} nameservers", self.cached_nameservers.len());
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
        &self.cached_nameservers
    }
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

impl std::str::FromStr for RuntimeConfig {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let startup_config: StartupConfig = s.parse()?;
        startup_config.into_runtime()
    }
}

impl std::str::FromStr for Config {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut config: Self = toml::from_str(s).inspect_err(|e| error!("error: {e}"))?;

        config.read_blocklists();
        config.build_blocklist();
        config.cache_nameservers();
        Ok(config)
    }
}
