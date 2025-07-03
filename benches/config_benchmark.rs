use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use criterion::{criterion_group, criterion_main, Criterion};

use lib::config;

fn setup_config(num_domains: usize) -> config::Config {
    let mut hosts = HashMap::new();
    hosts.insert("test".to_string(), "192.168.1.1".parse::<IpAddr>().unwrap());

    let mut domains = Vec::new();
    for i in 0..num_domains {
        domains.push(format!("domain{}.com", i));
    }

    let domains = domains
        .into_iter()
        .map(|d| d.to_string())
        .collect();

    config::Config {
        local_network: config::LocalNetwork {
            hosts,
            domains: Some(domains),
            blocklists: None,
        },
        nameservers: HashMap::new(),
        blocklist: None,
        blocklist_builder: HashSet::new(),
    }
}

fn benchmark_has_addr(c: &mut Criterion) {
    let config = setup_config(1000);
    let mut group = c.benchmark_group("has_addr");

    group.bench_function("existing host", |b| {
        b.iter(|| config.has_addr("test.domain500.com"))
    });

    group.bench_function("non-existing host", |b| {
        b.iter(|| config.has_addr("unknown.domain500.com"))
    });

    group.bench_function("non-existing domain", |b| {
        b.iter(|| config.has_addr("test.unknown.com"))
    });

    group.finish();
}

fn benchmark_has_addr_short(c: &mut Criterion) {
    let config = setup_config(3);
    let mut group = c.benchmark_group("has_addr");

    group.bench_function("existing host", |b| {
        b.iter(|| config.has_addr("test.domain2.com"))
    });

    group.bench_function("non-existing host", |b| {
        b.iter(|| config.has_addr("unknown.domain2.com"))
    });

    group.bench_function("non-existing domain", |b| {
        b.iter(|| config.has_addr("test.unknown.com"))
    });

    group.finish();
}

criterion_group!(benches, benchmark_has_addr, benchmark_has_addr_short);
criterion_main!(benches);
