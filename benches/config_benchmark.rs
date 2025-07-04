use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use criterion::{Criterion, criterion_group, criterion_main};

use lib::config;

fn setup_config(num_domains: usize) -> config::Config {
    let mut hosts = HashMap::new();
    hosts.insert("test".to_string(), "192.168.1.1".parse::<IpAddr>().unwrap());

    let mut domains = Vec::new();
    for i in 0..num_domains {
        domains.push(format!("domain{i}.com"));
    }

    // do this so we can easily switch to a different collection
    let domains = domains.into_iter().collect();

    config::Config {
        local_network: config::LocalNetwork { hosts },
        local_domains: config::Domains {
            domains: Some(domains),
        },
        ..Default::default()
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

// this benchmark is more realistic
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

fn setup_config_with_blocklist(num_block_items: usize) -> config::Config {
    let mut config = config::Config::default();
    for i in 0..num_block_items {
        config.insert_blocklist_item(&format!("blockeddomain{i}.com"));
    }
    config.insert_blocklist_item("anotherblockeddomain.com");
    config.build_blocklist();
    config
}

fn benchmark_has_block(c: &mut Criterion) {
    let config = setup_config_with_blocklist(1000);
    let mut group = c.benchmark_group("has_block");

    group.bench_function("blocked domain", |b| {
        b.iter(|| config.has_block("anotherblockeddomain.com"))
    });

    group.bench_function("subdomain of blocked domain", |b| {
        b.iter(|| config.has_block("sub.anotherblockeddomain.com"))
    });

    group.bench_function("sub-subdomain of blocked domain", |b| {
        b.iter(|| config.has_block("1234.sub.anotherblockeddomain.com"))
    });

    group.bench_function("not blocked domain", |b| {
        b.iter(|| config.has_block("example.com"))
    });

    group.bench_function("not blocked domain w/www", |b| {
        b.iter(|| config.has_block("www.example.com"))
    });

    group.bench_function("long not blocked domain", |b| {
        b.iter(|| {
            config.has_block("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.com")
        })
    });

    group.finish();
}

fn benchmark_get_nameservers(c: &mut Criterion) {
    let config = setup_config_with_nameservers();
    let mut group = c.benchmark_group("get_nameservers");

    group.bench_function("cached nameservers", |b| {
        b.iter(|| config.get_nameservers())
    });

    group.finish();
}

fn setup_config_with_nameservers() -> config::Config {
    let toml_content = r#"
[local_network]

[nameservers]
ip4 = ["1.1.1.1", "8.8.8.8", "208.67.222.222", "208.67.220.220"]
"#;

    config::Config::from_str(toml_content).expect("Failed to parse config")
}

criterion_group!(
    benches,
    benchmark_has_addr,
    benchmark_has_addr_short,
    benchmark_has_block,
    benchmark_get_nameservers
);
criterion_main!(benches);
