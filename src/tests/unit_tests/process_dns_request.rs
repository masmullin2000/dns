use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, ResourceRecord, TYPE, rdata};

use crate::config::{RuntimeConfig, StartupConfig};
use crate::dns_cache;
use crate::server::process_dns_request_test;

// Test utilities for creating DNS packets

fn create_dns_query(domain: &str, record_type: TYPE) -> Vec<u8> {
    let mut packet = Packet::new_query(1234);
    let question = Question::new(
        Name::new_unchecked(domain),
        QTYPE::TYPE(record_type),
        QCLASS::CLASS(CLASS::IN),
        false,
    );
    packet.questions.push(question);
    packet.build_bytes_vec().unwrap()
}

fn create_dns_response(domain: &str, ip: &str, record_type: TYPE) -> Vec<u8> {
    let mut packet = Packet::new_reply(1234);
    packet.questions.push(Question::new(
        Name::new_unchecked(domain),
        QTYPE::TYPE(record_type),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));

    let rdata = match record_type {
        TYPE::A => rdata::RData::A(rdata::A {
            address: ip.parse::<std::net::Ipv4Addr>().unwrap().into(),
        }),
        TYPE::AAAA => rdata::RData::AAAA(rdata::AAAA {
            address: ip.parse::<std::net::Ipv6Addr>().unwrap().into(),
        }),
        _ => panic!("Unsupported record type for test"),
    };

    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked(domain),
        CLASS::IN,
        300, // TTL
        rdata,
    ));

    packet.build_bytes_vec().unwrap()
}

fn create_test_config_with_local_host(hostname: &str, ip: &str) -> RuntimeConfig {
    let mut startup_config = StartupConfig::default();
    startup_config
        .local_network
        .hosts
        .insert(hostname.to_string(), ip.parse().unwrap());
    startup_config.into()
}

fn create_test_config_with_nameservers(nameservers: Vec<&str>) -> RuntimeConfig {
    let mut startup_config = StartupConfig::default();
    startup_config.nameservers.ip4 = nameservers.into_iter().map(String::from).collect();
    startup_config.into()
}

// Tests for local network resolution

#[tokio::test]
async fn test_process_dns_request_local_host_resolution() {
    // Setup
    let config = create_test_config_with_local_host("myhost", "192.168.1.100");
    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));
    let query_bytes = create_dns_query("myhost", TYPE::A);
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    // Mock function should not be called for local resolution
    let mock_get_data = |_ns: &SocketAddr, _bytes: &Arc<Vec<u8>>| async move {
        panic!("get_data should not be called for local resolution")
    };

    // Execute
    let result = process_dns_request_test(
        &client_addr,
        &config,
        &cache,
        query_bytes,
        0, // UDP
        mock_get_data,
    )
    .await;

    // Assert
    assert!(result.is_ok());
    let response_bytes = result.unwrap();

    // Parse and validate response
    let response_packet = Packet::parse(&response_bytes).unwrap();
    assert!(!response_packet.answers.is_empty());

    // Verify the response contains the correct IP
    if let rdata::RData::A(a_record) = &response_packet.answers[0].rdata {
        let ip = std::net::Ipv4Addr::from(a_record.address);
        assert_eq!(ip.to_string(), "192.168.1.100");
    } else {
        panic!("Expected A record in response");
    }
}

#[tokio::test]
async fn test_process_dns_request_local_host_with_domain_suffix() {
    // Setup config with domain suffix
    let mut startup_config = StartupConfig::default();
    startup_config
        .local_network
        .hosts
        .insert("myhost".to_string(), "192.168.1.100".parse().unwrap());
    startup_config.local_domains.domains = Some(vec!["local".to_string()]);
    let config: RuntimeConfig = startup_config.into();

    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));
    let query_bytes = create_dns_query("myhost.local", TYPE::A);
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let mock_get_data = |_ns: &SocketAddr, _bytes: &Arc<Vec<u8>>| async move {
        panic!("get_data should not be called for local resolution with domain suffix")
    };

    // Execute
    let result =
        process_dns_request_test(&client_addr, &config, &cache, query_bytes, 0, mock_get_data)
            .await;

    // Assert
    assert!(result.is_ok());
    let response_bytes = result.unwrap();
    let response_packet = Packet::parse(&response_bytes).unwrap();
    assert!(!response_packet.answers.is_empty());

    // Verify correct IP
    if let rdata::RData::A(a_record) = &response_packet.answers[0].rdata {
        let ip = std::net::Ipv4Addr::from(a_record.address);
        assert_eq!(ip.to_string(), "192.168.1.100");
    }
}

#[tokio::test]
async fn test_process_dns_request_tcp_local_resolution() {
    // Test TCP DNS request (with length prefix)
    let config = create_test_config_with_local_host("myhost", "192.168.1.100");
    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));

    // Create TCP DNS packet (length prefix + DNS packet)
    let dns_packet = create_dns_query("myhost", TYPE::A);
    let length = (dns_packet.len() as u16).to_be_bytes();
    let mut tcp_bytes = Vec::new();
    tcp_bytes.extend_from_slice(&length);
    tcp_bytes.extend_from_slice(&dns_packet);

    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let mock_get_data = |_ns: &SocketAddr, _bytes: &Arc<Vec<u8>>| async move {
        panic!("get_data should not be called for TCP local resolution")
    };

    // Execute
    let result = process_dns_request_test(
        &client_addr,
        &config,
        &cache,
        tcp_bytes,
        2, // TCP starts after 2-byte length prefix
        mock_get_data,
    )
    .await;

    // Assert
    assert!(result.is_ok());
    let response_bytes = result.unwrap();

    // TCP response should include length prefix
    assert!(response_bytes.len() > 2);
    let response_length = u16::from_be_bytes([response_bytes[0], response_bytes[1]]);
    assert_eq!(response_length as usize, response_bytes.len() - 2);

    // Parse DNS packet (skip length prefix)
    let response_packet = Packet::parse(&response_bytes[2..]).unwrap();
    assert!(!response_packet.answers.is_empty());
}

// Tests for blocked domain resolution

#[tokio::test]
async fn test_process_dns_request_blocked_domain() {
    // Setup config with blocked domain and nameservers to avoid empty select_all panic
    let mut startup_config = StartupConfig::default();

    // Create a temporary blocklist directory with unique name to avoid conflicts
    let blocklist_dir = format!("./test_blocked_domain_{}", std::process::id());
    std::fs::create_dir_all(&blocklist_dir).unwrap();
    std::fs::write(format!("{}/test.list", blocklist_dir), "blocked.com").unwrap();

    startup_config.options.blocklist_dir = Some(blocklist_dir.clone());
    startup_config.nameservers.ip4.insert("8.8.8.8".to_string()); // Add nameserver to avoid panic
    let config: RuntimeConfig = startup_config.into();

    // Clean up the temporary directory
    std::fs::remove_dir_all(&blocklist_dir).ok();

    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));
    let query_bytes = create_dns_query("blocked.com", TYPE::A);
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let mock_get_data = |_ns: &SocketAddr, _bytes: &Arc<Vec<u8>>| async move {
        panic!("get_data should not be called for blocked domains")
    };

    // Execute
    let result =
        process_dns_request_test(&client_addr, &config, &cache, query_bytes, 0, mock_get_data)
            .await;

    // Assert
    assert!(result.is_ok());
    let response_bytes = result.unwrap();
    let response_packet = Packet::parse(&response_bytes).unwrap();
    assert!(!response_packet.answers.is_empty());

    // Verify blocked domain returns localhost
    if let rdata::RData::A(a_record) = &response_packet.answers[0].rdata {
        let ip = std::net::Ipv4Addr::from(a_record.address);
        assert_eq!(ip, std::net::Ipv4Addr::LOCALHOST);
    } else {
        panic!("Expected A record pointing to localhost for blocked domain");
    }
}

#[tokio::test]
async fn test_process_dns_request_blocked_subdomain() {
    // Setup config with wildcard blocked domain and nameservers
    let mut startup_config = StartupConfig::default();

    // Create a temporary blocklist directory with unique name to avoid conflicts
    let blocklist_dir = format!("./test_blocked_subdomain_{}", std::process::id());
    std::fs::create_dir_all(&blocklist_dir).unwrap();
    std::fs::write(format!("{}/test.list", blocklist_dir), "*.blocked.com").unwrap();

    startup_config.options.blocklist_dir = Some(blocklist_dir.clone());
    startup_config.nameservers.ip4.insert("8.8.8.8".to_string()); // Add nameserver to avoid panic
    let config: RuntimeConfig = startup_config.into();

    // Clean up the temporary directory
    std::fs::remove_dir_all(&blocklist_dir).ok();

    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));
    let query_bytes = create_dns_query("sub.blocked.com", TYPE::A);
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let mock_get_data = |_ns: &SocketAddr, _bytes: &Arc<Vec<u8>>| async move {
        panic!("get_data should not be called for blocked subdomains")
    };

    // Execute
    let result =
        process_dns_request_test(&client_addr, &config, &cache, query_bytes, 0, mock_get_data)
            .await;

    // Assert
    assert!(result.is_ok());
    let response_bytes = result.unwrap();
    let response_packet = Packet::parse(&response_bytes).unwrap();
    assert!(!response_packet.answers.is_empty());

    // Verify subdomain is also blocked
    if let rdata::RData::A(a_record) = &response_packet.answers[0].rdata {
        let ip = std::net::Ipv4Addr::from(a_record.address);
        assert_eq!(ip, std::net::Ipv4Addr::LOCALHOST);
    }
}

// Tests for cache hit scenarios

#[tokio::test]
async fn test_process_dns_request_cache_hit() {
    // Setup config and pre-populate cache
    let config: RuntimeConfig = StartupConfig::default().into();
    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));

    // Pre-populate cache
    {
        #[allow(clippy::unwrap_used)]
        let mut cache_write = cache.write().unwrap();
        cache_write.insert(
            "cached.com",
            dns_cache::IpAddr::new("1.2.3.4".parse().unwrap(), 300),
        );
    }

    let query_bytes = create_dns_query("cached.com", TYPE::A);
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    // Mock should not be called since we have cache hit
    let mock_get_data = |_ns: &SocketAddr, _bytes: &Arc<Vec<u8>>| async move {
        panic!("get_data should not be called for cache hits")
    };

    // Execute
    let result =
        process_dns_request_test(&client_addr, &config, &cache, query_bytes, 0, mock_get_data)
            .await;

    // Assert
    assert!(result.is_ok());
    let response_bytes = result.unwrap();
    let response_packet = Packet::parse(&response_bytes).unwrap();
    assert!(!response_packet.answers.is_empty());

    // Verify response comes from cache
    if let rdata::RData::A(a_record) = &response_packet.answers[0].rdata {
        let ip = std::net::Ipv4Addr::from(a_record.address);
        assert_eq!(ip.to_string(), "1.2.3.4");
    }
}

// Tests for upstream DNS forwarding

#[tokio::test]
async fn test_process_dns_request_upstream_forwarding_success() {
    // Setup config with nameservers
    let config = create_test_config_with_nameservers(vec!["8.8.8.8", "1.1.1.1"]);
    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));
    let query_bytes = create_dns_query("google.com", TYPE::A);
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    // Mock successful upstream response
    let mock_response = create_dns_response("google.com", "8.8.8.8", TYPE::A);
    let mock_get_data = move |_ns: &SocketAddr, _bytes: &Arc<Vec<u8>>| {
        let response = mock_response.clone();
        async move { Ok(response) }
    };

    // Execute
    let result =
        process_dns_request_test(&client_addr, &config, &cache, query_bytes, 0, mock_get_data)
            .await;

    // Assert
    assert!(result.is_ok());
    let response_bytes = result.unwrap();
    let response_packet = Packet::parse(&response_bytes).unwrap();

    // Verify response contains upstream data
    assert!(!response_packet.answers.is_empty());

    // Verify cache was populated
    {
        #[allow(clippy::unwrap_used)]
        let cache_read = cache.read().unwrap();
        let cached_addrs = cache_read.get("google.com", TYPE::A);
        assert!(cached_addrs.is_some());
        let addrs = cached_addrs.unwrap();
        assert!(!addrs.is_empty());
        assert_eq!(addrs[0].to_string(), "8.8.8.8");
    }
}

#[tokio::test]
async fn test_process_dns_request_upstream_forwarding_with_ipv6() {
    // Test IPv6 response handling
    let config = create_test_config_with_nameservers(vec!["8.8.8.8"]);
    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));
    let query_bytes = create_dns_query("ipv6.google.com", TYPE::AAAA);
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    // Create IPv6 response
    let ipv6_response = create_dns_response("ipv6.google.com", "2001:4860:4860::8888", TYPE::AAAA);
    let mock_get_data = move |_ns: &SocketAddr, _bytes: &Arc<Vec<u8>>| {
        let response = ipv6_response.clone();
        async move { Ok(response) }
    };

    // Execute
    let result =
        process_dns_request_test(&client_addr, &config, &cache, query_bytes, 0, mock_get_data)
            .await;

    // Assert
    assert!(result.is_ok());

    // Verify IPv6 cache was populated
    {
        #[allow(clippy::unwrap_used)]
        let cache_read = cache.read().unwrap();
        let cached_addrs = cache_read.get("ipv6.google.com", TYPE::AAAA);
        assert!(cached_addrs.is_some());
        let addrs = cached_addrs.unwrap();
        assert!(!addrs.is_empty());
        assert_eq!(addrs[0].to_string(), "2001:4860:4860::8888");
    }
}

#[tokio::test]
async fn test_process_dns_request_upstream_forwarding_failure() {
    // Setup config with nameservers
    let config = create_test_config_with_nameservers(vec!["8.8.8.8"]);
    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));
    let query_bytes = create_dns_query("nonexistent.com", TYPE::A);
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    // Mock upstream failure
    let mock_get_data = |_ns: &SocketAddr, _bytes: &Arc<Vec<u8>>| async move {
        Err(anyhow::anyhow!("Mock upstream server failure"))
    };

    // Execute
    let result =
        process_dns_request_test(&client_addr, &config, &cache, query_bytes, 0, mock_get_data)
            .await
            .unwrap();

    // Assert
    let pkt = simple_dns::Packet::parse(&result).unwrap();
    assert_eq!(pkt.rcode(), simple_dns::RCODE::ServerFailure);
}

#[tokio::test]
#[should_panic(expected = "assertion failed: !ret.inner.is_empty()")]
async fn test_process_dns_request_no_nameservers_configured() {
    // NOTE: This test reveals a bug in the original code - when no nameservers are configured
    // and no local resolution is possible, select_all() is called with an empty iterator which panics.
    // This should be fixed to return a proper error instead of panicking.

    // Setup config without nameservers
    let config: RuntimeConfig = StartupConfig::default().into();
    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));
    let query_bytes = create_dns_query("external.com", TYPE::A);
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let mock_get_data = |_ns: &SocketAddr, _bytes: &Arc<Vec<u8>>| async move {
        panic!("get_data should not be called when no nameservers configured")
    };

    // Execute - this currently panics due to empty select_all()
    let _result =
        process_dns_request_test(&client_addr, &config, &cache, query_bytes, 0, mock_get_data)
            .await;
}

// Tests for error conditions

#[tokio::test]
async fn test_process_dns_request_malformed_packet() {
    let config: RuntimeConfig = StartupConfig::default().into();
    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));
    let malformed_bytes = vec![5u8; 13]; // Invalid DNS packet
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let mock_get_data = |_ns: &SocketAddr, _bytes: &Arc<Vec<u8>>| async move {
        panic!("get_data should not be called for malformed packets")
    };

    // Execute
    let result = process_dns_request_test(
        &client_addr,
        &config,
        &cache,
        malformed_bytes,
        0,
        mock_get_data,
    )
    .await
    .unwrap();

    // Assert
    let response_packet = Packet::parse(&result).unwrap();
    assert_eq!(response_packet.rcode(), simple_dns::RCODE::FormatError);
}

#[tokio::test]
async fn test_process_dns_request_empty_packet() {
    let config: RuntimeConfig = StartupConfig::default().into();
    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));
    let empty_bytes = vec![];
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let mock_get_data = |_ns: &SocketAddr, _bytes: &Arc<Vec<u8>>| async move {
        panic!("get_data should not be called for empty packets")
    };

    // Execute
    let result =
        process_dns_request_test(&client_addr, &config, &cache, empty_bytes, 0, mock_get_data)
            .await;

    // Assert
    assert!(result.is_err());
}

#[tokio::test]
async fn test_process_dns_request_tcp_wrong_offset() {
    // Test TCP packet with wrong dns_start_location
    let config = create_test_config_with_local_host("myhost", "192.168.1.100");
    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));
    let query_bytes = create_dns_query("myhost", TYPE::A);
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let mock_get_data = |_ns: &SocketAddr, _bytes: &Arc<Vec<u8>>| async move {
        panic!("get_data should not be called with wrong offset")
    };

    // Execute with wrong offset (should be 0 for UDP packet)
    let result = process_dns_request_test(
        &client_addr,
        &config,
        &cache,
        query_bytes,
        10, // Wrong offset
        mock_get_data,
    )
    .await;

    // Assert
    assert!(result.is_err());
}

// Tests for DNS response flags and structure

#[tokio::test]
async fn test_process_dns_request_response_flags() {
    let config = create_test_config_with_local_host("myhost", "192.168.1.100");
    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));
    let query_bytes = create_dns_query("myhost", TYPE::A);
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let mock_get_data = |_ns: &SocketAddr, _bytes: &Arc<Vec<u8>>| async move {
        panic!("get_data should not be called for local resolution")
    };

    // Execute
    let result =
        process_dns_request_test(&client_addr, &config, &cache, query_bytes, 0, mock_get_data)
            .await;

    // Assert
    assert!(result.is_ok());
    let response_bytes = result.unwrap();
    let response_packet = Packet::parse(&response_bytes).unwrap();

    // Verify DNS response flags are set correctly
    assert!(response_packet.has_flags(simple_dns::PacketFlag::RESPONSE));
    assert!(response_packet.has_flags(simple_dns::PacketFlag::RECURSION_DESIRED));
    assert!(response_packet.has_flags(simple_dns::PacketFlag::RECURSION_AVAILABLE));
}
