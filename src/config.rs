use anyhow::Result;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use tracing::{debug, error, warn};

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
    pub blocklist: Option<bloomfilter::Bloom<str>>,
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
        let Ok(mut blocklist) =
            bloomfilter::Bloom::new_for_fp_rate(self.blocklist_builder.len(), 0.0001)
        else {
            error!("Failed to create bloom filter for blocklist: blocklist inoperable");
            return;
        };
        for item in &self.blocklist_builder {
            blocklist.set(item.as_str());
        }
        self.blocklist = Some(blocklist);
        debug!("Blocklist Size {}", self.blocklist_builder.len());
        self.blocklist_builder.clear();
        self.blocklist_builder.shrink_to_fit();
    }

    #[must_use]
    pub fn has_block(&self, value: &str) -> bool {
        let Some(ref blocklist) = self.blocklist else {
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
    pub fn get_nameservers(&self) -> Vec<std::net::SocketAddr> {
        self.nameservers
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
            .collect()
    }
}

impl std::str::FromStr for Config {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut config: Self = toml::from_str(s).inspect_err(|e| error!("error: {e}"))?;

        config.read_blocklists();
        config.build_blocklist();
        Ok(config)
    }
}
