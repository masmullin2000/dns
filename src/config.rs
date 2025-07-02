use anyhow::Result;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

#[derive(Deserialize, Default, Clone, Debug)]
pub struct Config {
    #[serde(rename = "LocalNetwork")]
    pub local_network: LocalNetwork,
    #[serde(rename = "nameservers")]
    pub nameservers: HashMap<String, bool>,
    #[serde(skip)]
    pub blocklist: Option<bloomfilter::Bloom<Box<str>>>,
    #[serde(skip)]
    pub blocklist_builder: HashSet<Box<str>>,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct LocalNetwork {
    #[serde(flatten)]
    pub hosts: HashMap<String, std::net::IpAddr>,
    pub domains: Option<Vec<String>>,
    pub blocklists: Option<Vec<String>>,
}

impl Config {
    pub fn has_addr(&self, value: &str) -> Option<std::net::IpAddr> {
        if let Some(addr) = self.local_network.hosts.get(value) {
            return Some(*addr);
        }

        let Some(domains) = &self.local_network.domains else {
            return None;
        };

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
        let Some(blocklists) = self.local_network.blocklists.clone() else {
            println!("Blocklist Size 0");
            return;
        };
        for blocklist in blocklists {
            _ = self.load_blocklist_file(&blocklist).inspect_err(|e| {
                eprintln!("Failed to load blocklist {blocklist}: {e}");
            });
        }
    }

    pub fn build_blocklist(&mut self) {
        if self.blocklist_builder.is_empty() {
            println!("Blocklist Size 0");
            return;
        }
        let mut blocklist =
            bloomfilter::Bloom::new_for_fp_rate(self.blocklist_builder.len(), 0.001);
        for item in &self.blocklist_builder {
            blocklist.set(item);
        }
        self.blocklist = Some(blocklist);
        println!("Blocklist Size {}", self.blocklist_builder.len());
        self.blocklist_builder.clear();
        self.blocklist_builder.shrink_to_fit();
    }

    pub fn has_block(&self, value: &str) -> bool {
        let Some(ref blocklist) = self.blocklist else {
            return false;
        };
        let mut name = value;
        while !name.is_empty() {
            if blocklist.check(&name.into()) {
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

    pub fn get_nameservers(&self) -> Vec<std::net::SocketAddr> {
        self.nameservers
            .iter()
            .filter_map(|(ip, enabled)| {
                if !enabled {
                    return None;
                }
                let ns: std::net::IpAddr = ip
                    .parse()
                    .inspect_err(|e| {
                        eprintln!(
                            "nameserver must be a valid IP address: skipping {ip}: error: {e}"
                        );
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
        let mut config: Self = toml::from_str(s).inspect_err(|e| println!("error: {e}"))?;

        config.read_blocklists();
        config.build_blocklist();
        Ok(config)
    }
}

#[cfg(test)]
#[path = "../tests/unit_tests/config.rs"]
mod test;
