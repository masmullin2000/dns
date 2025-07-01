use anyhow::{bail, Result};
use std::collections::HashSet;

#[derive(Clone)]
pub struct DnsConfig {
    pub addr: std::net::IpAddr,
    pub name: String,
}

impl<S> From<(S, std::net::IpAddr)> for DnsConfig
where
    S: Into<String>,
{
    fn from(value: (S, std::net::IpAddr)) -> Self {
        let (name, addr) = value;
        Self {
            addr,
            name: name.into(),
        }
    }
}

#[derive(Default, Clone)]
pub struct Config {
    pub dns: Vec<DnsConfig>,
    pub domains: Vec<String>,
    pub nameservers: Vec<std::net::SocketAddr>,
    pub blocklist: Option<bloomfilter::Bloom<Box<str>>>,
    pub blocklist_builder: HashSet<Box<str>>,
}

impl Config {
    pub fn has_addr(&self, value: &str) -> Option<std::net::IpAddr> {
        for dns in &self.dns {
            let local = dns.name.as_str();
            if value == local {
                return Some(dns.addr);
            }
            for domain in &self.domains {
                let mut local_domain: String = local.into();
                local_domain.push('.');
                local_domain.push_str(domain);

                if value == local_domain {
                    return Some(dns.addr);
                }
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
}

impl std::str::FromStr for Config {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let file = std::fs::read_to_string(s)?;
        let toml: toml::Table = toml::from_str(&file)?;

        let mut config = Self::default();

        for (key, value) in toml {
            match key.to_lowercase().as_str() {
                "localnetwork" | "localnetworks" => {
                    let ln = value.as_table().expect("LocalNetwork must be a table");
                    for (name, addr) in ln {
                        if name == "domains" {
                            let domains = addr.as_array().expect("domains must be an array");
                            for domain in domains {
                                let domain = domain.as_str().expect("domain must be a string");
                                config.domains.push(domain.to_string());
                            }
                            continue;
                        }
                        if name == "blocklists" {
                            let blocklists = addr.as_array().expect("blocklists must be an array");
                            for blocklist in blocklists {
                                let blocklist =
                                    blocklist.as_str().expect("blocklist must be a string");
                                _ = config.load_blocklist(blocklist).inspect_err(|e| {
                                    eprintln!("Failed to load blocklist {blocklist}: {e}");
                                });
                            }
                            continue;
                        }
                        let addr = addr.as_str().expect("dns addr must be a string");
                        let addr: std::net::IpAddr =
                            addr.parse().expect("dns addr must be a valid IP address");
                        let dns_cfg = (name, addr).into();
                        config.dns.push(dns_cfg);
                    }
                }
                "nameservers" => {
                    println!("{value:?}");
                    let nameservers = value.as_table().expect("nameservers must be an array");
                    config.nameservers = nameservers
                        .iter()
                        .filter_map(|(ip, val)| {
                            if !val.as_bool()? {
                                return None;
                            };
                            let ns: std::net::IpAddr = ip
                                .parse()
                                .inspect_err(|e| {
                                    eprintln!("nameserver must be a valid IP address: skipping {ip}: error: {e}");
                                })
                                .ok()?;
                            println!("found nameserver: {ns}");
                            Some(std::net::SocketAddr::new(ns, 53))
                        })
                        .collect();
                }
                val => {
                    bail!("Unknown toml entry key: {val}");
                }
            }
        }

        if config.nameservers.is_empty() {
            bail!("No nameservers specified");
        }

        Ok(config)
    }
}
