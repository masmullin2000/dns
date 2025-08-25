use std::net::IpAddr;
use std::time::Duration;

use simple_dns as dns;

use crate::dns_cache::{Cache, IpAddr as CacheIpAddr};

#[test]
fn test_cache_insert_and_get() {
    let mut cache = Cache::default();
    let ip = "192.168.1.1".parse().unwrap();
    let cache_ip = CacheIpAddr::new(ip, 300);

    cache.insert("example.com", cache_ip);

    let result = cache.get("example.com", dns::TYPE::A);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), vec![ip]);

    let result = cache.get("example.com", dns::TYPE::AAAA);
    assert!(result.is_none());
}

#[test]
fn test_cache_get_nonexistent() {
    let cache = Cache::default();
    let result = cache.get("nonexistent.com", dns::TYPE::A);
    assert!(result.is_none());
}

#[test]
fn test_cache_multiple_ips() {
    let mut cache = Cache::default();
    let ip1 = "192.168.1.1".parse().unwrap();
    let ip2 = "192.168.1.2".parse().unwrap();

    cache.insert("example.com", CacheIpAddr::new(ip1, 300));
    cache.insert("example.com", CacheIpAddr::new(ip2, 300));

    let result = cache.get("example.com", dns::TYPE::A).unwrap();
    assert_eq!(result.len(), 2);
    assert!(result.contains(&ip1));
    assert!(result.contains(&ip2));
}

#[test]
fn test_cache_ttl_expiry() {
    let mut cache = Cache::default();
    let ip = "192.168.1.1".parse().unwrap();

    // Insert with 0 TTL (should expire immediately)
    cache.insert("example.com", CacheIpAddr::new(ip, 0));

    // Sleep a bit to ensure expiry
    std::thread::sleep(Duration::from_millis(10));

    let result = cache.get("example.com", dns::TYPE::A);
    assert!(result.is_none());
}

#[test]
fn test_cache_prune_expired() {
    let mut cache = Cache::default();
    let ip1 = "192.168.1.1".parse().unwrap();
    let ip2 = "192.168.1.2".parse().unwrap();

    // Insert one expired and one valid entry
    cache.insert("expired.com", CacheIpAddr::new(ip1, 0));
    cache.insert("valid.com", CacheIpAddr::new(ip2, 300));

    std::thread::sleep(Duration::from_millis(10));

    cache.prune();

    assert!(cache.get("expired.com", dns::TYPE::A).is_none());
    assert!(cache.get("valid.com", dns::TYPE::A).is_some());
}

#[test]
fn test_cache_prune_partial_expiry() {
    let mut cache = Cache::default();
    let ip1 = "192.168.1.1".parse().unwrap();
    let ip2 = "192.168.1.2".parse().unwrap();

    // Insert multiple IPs for same domain with different TTLs
    cache.insert("example.com", CacheIpAddr::new(ip1, 0));
    cache.insert("example.com", CacheIpAddr::new(ip2, 300));

    std::thread::sleep(Duration::from_millis(10));

    cache.prune();

    let result = cache.get("example.com", dns::TYPE::A).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], ip2);
}

#[test]
fn test_cache_ipaddr_creation() {
    let ip = "192.168.1.1".parse().unwrap();
    let cache_ip = CacheIpAddr::new(ip, 300);

    // Test that the IP is stored correctly
    // Note: We can't directly access the fields as they're private,
    // but we can test through cache operations
    let mut cache = Cache::default();
    cache.insert("test.com", cache_ip);

    let result = cache.get("test.com", dns::TYPE::A).unwrap();
    assert_eq!(result[0], ip);
}

#[test]
fn test_cache_empty_after_full_prune() {
    let mut cache = Cache::default();
    let ip = "192.168.1.1".parse().unwrap();

    // Insert multiple entries all with 0 TTL
    cache.insert("example1.com", CacheIpAddr::new(ip, 0));
    cache.insert("example2.com", CacheIpAddr::new(ip, 0));
    cache.insert("example3.com", CacheIpAddr::new(ip, 0));

    std::thread::sleep(Duration::from_millis(10));

    cache.prune();

    assert!(cache.get("example1.com", dns::TYPE::A).is_none());
    assert!(cache.get("example2.com", dns::TYPE::A).is_none());
    assert!(cache.get("example3.com", dns::TYPE::A).is_none());
}

#[test]
fn test_cache_ipv6_support() {
    let mut cache = Cache::default();
    let ipv6: IpAddr = "2001:db8::1".parse().unwrap();
    let cache_ip = CacheIpAddr::new(ipv6, 300);

    cache.insert("ipv6.example.com", cache_ip);

    let result = cache.get("ipv6.example.com", dns::TYPE::AAAA);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), vec![ipv6]);

    let result = cache.get("ipv6.example.com", dns::TYPE::A);
    assert!(result.is_none());
}
