use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct IpAddr {
    ip: std::net::IpAddr,
    ttl: std::time::SystemTime,
}

impl IpAddr {
    pub fn new(ip: std::net::IpAddr, ttl: u32) -> Self {
        #[allow(clippy::cast_lossless)] // SAFETY: ttl is u32 so casting to u64 is safe
        let ttl = std::time::SystemTime::now() + std::time::Duration::from_secs(ttl as u64);
        Self { ip, ttl }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Cache(HashMap<String, Vec<IpAddr>>);

impl Cache {
    pub fn get(&self, key: &str) -> Option<Vec<std::net::IpAddr>> {
        let addrs: Vec<_> = self
            .0
            .get(key)?
            .iter()
            .filter_map(|value| {
                if value.ttl > std::time::SystemTime::now() {
                    Some(value.ip)
                } else {
                    None
                }
            })
            .collect();

        if addrs.is_empty() {
            return None;
        }

        Some(addrs)
    }

    pub fn insert(&mut self, key: String, value: IpAddr) {
        self.0
            .entry(key)
            .and_modify(|e| {
                e.push(value.clone());
            })
            .or_insert_with(|| vec![value]);
    }

    pub fn prune(&mut self) {
        let now = std::time::SystemTime::now();
        self.0.retain(|_, ips| {
            ips.retain(|ip| ip.ttl > now);
            !ips.is_empty()
        });
    }
}
