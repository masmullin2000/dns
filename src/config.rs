use anyhow::{bail, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

#[derive(Deserialize, Default, Clone)]
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

#[derive(Deserialize, Default, Clone)]
pub struct LocalNetwork {
    #[serde(flatten)]
    pub hosts: HashMap<String, std::net::IpAddr>,
    pub domains: Vec<String>,
    pub blocklists: Vec<String>,
}

impl Config {
    pub fn has_addr(&self, value: &str) -> Option<std::net::IpAddr> {
        if let Some(addr) = self.local_network.hosts.get(value) {
            return Some(*addr);
        }

        for domain in &self.local_network.domains {
            let mut local_domain: String = value.into();
            local_domain.push('.');
            local_domain.push_str(domain);
            if let Some(addr) = self.local_network.hosts.get(&local_domain) {
                return Some(*addr);
            }
        }

        None
    }

    fn load_blocklist(&mut self, block_file: &str) -> Result<()> {
        let file = std::fs::read_to_string(block_file)?;
        for line in file.lines() {
            if !line.is_empty() && line.starts_with("*.") {
                let name = &line[2..];
                self.blocklist_builder.insert(name.into());
            }
        }
        Ok(())
    }

    pub fn build_blocklist(&mut self) {
        for blocklist in self.local_network.blocklists.clone() {
            if let Err(e) = self.load_blocklist(&blocklist) {
                eprintln!("Failed to load blocklist {blocklist}: {e}");
            }
        }

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
        let file = std::fs::read_to_string(s)?;
        let mut config: Self = toml::from_str(&file)?;

        if config.nameservers.is_empty() {
            bail!("No nameservers specified");
        }

        config.build_blocklist();
        Ok(config)
    }
}
