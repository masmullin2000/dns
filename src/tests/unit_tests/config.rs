use std::str::FromStr;

use crate::config::{RuntimeConfig, StartupConfig};

#[test]
fn test_startup_config_parsing() {
    let toml_content = r#"
[local_network]
"tplinkwifi.net" = "192.168.1.1"
dns = "192.168.0.2"

[local_domains]
domains = ["local", "home"]

[nameservers]
ip4 = ["1.1.1.1", "8.8.8.8"]

[blocklists]
files = ["./test_blocklist.list"]
"#;

    let startup_config =
        StartupConfig::from_str(toml_content).expect("Failed to parse startup config");

    assert_eq!(
        startup_config
            .local_network
            .hosts
            .get("tplinkwifi.net")
            .unwrap()
            .to_string(),
        "192.168.1.1"
    );
    assert_eq!(
        startup_config
            .local_network
            .hosts
            .get("dns")
            .unwrap()
            .to_string(),
        "192.168.0.2"
    );
    let Some(domains) = &startup_config.local_domains.domains else {
        panic!("Expected domains to be defined");
    };
    assert!(domains.contains(&"local".to_string()));
    assert!(domains.contains(&"home".to_string()));
    assert!(
        startup_config
            .nameservers
            .ip4
            .contains(&"1.1.1.1".to_string())
    );
    assert!(
        startup_config
            .nameservers
            .ip4
            .contains(&"8.8.8.8".to_string())
    );
}

#[test]
fn test_runtime_config_conversion() {
    let toml_content = r#"
[local_network]
"tplinkwifi.net" = "192.168.1.1"
dns = "192.168.0.2"

[local_domains]
domains = ["local", "home"]

[nameservers]
ip4 = ["1.1.1.1", "8.8.8.8"]

[blocklists]
files = ["./test_blocklist_runtime.list"]
"#;

    // Create a dummy blocklist file for the test
    std::fs::write(
        "./test_blocklist_runtime.list",
        "*.blocked.com\n*.another.org",
    )
    .unwrap();

    let config = StartupConfig::from_str(toml_content).expect("Failed to parse runtime config");
    let runtime_config: RuntimeConfig = config.into();

    assert_eq!(
        runtime_config
            .local_network
            .hosts
            .get("tplinkwifi.net")
            .unwrap()
            .to_string(),
        "192.168.1.1"
    );
    assert_eq!(
        runtime_config
            .local_network
            .hosts
            .get("dns")
            .unwrap()
            .to_string(),
        "192.168.0.2"
    );
    let Some(domains) = &runtime_config.local_domains.domains else {
        panic!("Expected domains to be defined");
    };
    assert!(domains.contains(&"local".to_string()));
    assert!(domains.contains(&"home".to_string()));
    assert!(runtime_config.block_filter.is_some());
    assert!(
        runtime_config
            .get_nameservers()
            .contains(&"1.1.1.1:53".parse().unwrap())
    );
    assert!(
        runtime_config
            .get_nameservers()
            .contains(&"8.8.8.8:53".parse().unwrap())
    );

    // Clean up the dummy blocklist file
    std::fs::remove_file("./test_blocklist_runtime.list").unwrap();
}

#[test]
fn test_runtime_config_has_addr_direct_match() {
    let mut startup_config = StartupConfig::default();
    startup_config
        .local_network
        .hosts
        .insert("myhost".to_string(), "192.168.1.100".parse().unwrap());

    let runtime_config: RuntimeConfig = startup_config.into();
    let addr = runtime_config
        .has_addr("myhost")
        .expect("Should find address");
    assert_eq!(addr.to_string(), "192.168.1.100");
}

#[test]
fn test_runtime_config_has_addr_domain_match() {
    let mut startup_config = StartupConfig::default();
    startup_config
        .local_network
        .hosts
        .insert("myhost".to_string(), "192.168.1.100".parse().unwrap());

    let hs = ["local"].iter().map(|&i| String::from(i)).collect();
    startup_config.local_domains.domains = Some(hs);

    let runtime_config: RuntimeConfig = startup_config.into();
    let addr = runtime_config
        .has_addr("myhost.local")
        .expect("Should find address");
    assert_eq!(addr.to_string(), "192.168.1.100");
}

#[test]
fn test_runtime_config_has_addr_no_match() {
    let startup_config = StartupConfig::default();
    let runtime_config: RuntimeConfig = startup_config.into();
    let addr = runtime_config.has_addr("nonexistent");
    assert!(addr.is_none());
}

#[test]
fn test_runtime_config_has_block_empty_blocklist() {
    let startup_config = StartupConfig::default();
    let runtime_config: RuntimeConfig = startup_config.into();
    assert!(!runtime_config.has_block("any.domain.com"));
}

#[test]
fn test_runtime_config_has_block_with_blocklist() {
    // Create a test blocklist file
    std::fs::write(
        "./test_blocklist_blocking.list",
        "blocked.com\n*.another.org",
    )
    .unwrap();

    let mut startup_config = StartupConfig::default();
    startup_config.blocklists.files = Some(vec!["./test_blocklist_blocking.list".to_string()]);

    let runtime_config: RuntimeConfig = startup_config.into();

    // Test blocked domains
    assert!(runtime_config.has_block("blocked.com"));
    assert!(runtime_config.has_block("sub.blocked.com"));
    assert!(runtime_config.has_block("test.another.org"));

    // Test non-blocked domains
    assert!(!runtime_config.has_block("google.com"));

    // Clean up
    std::fs::remove_file("./test_blocklist_blocking.list").unwrap();
}

#[test]
fn test_startup_config_no_nameservers() {
    let toml_content = r#"
[local_network]
dns = "192.168.0.2"
"#;

    let startup_config =
        StartupConfig::from_str(toml_content).expect("Should parse config without nameservers");
    assert!(startup_config.nameservers.ip4.is_empty());

    let runtime_config: RuntimeConfig = startup_config.into();
    assert!(runtime_config.get_nameservers().is_empty());
}

#[test]
fn test_runtime_config_complex_domain_matching() {
    let mut startup_config = StartupConfig::default();
    startup_config
        .local_network
        .hosts
        .insert("myhost".to_string(), "192.168.1.100".parse().unwrap());

    let hs = ["local", "local.hometown"]
        .iter()
        .map(|&i| String::from(i))
        .collect();
    startup_config.local_domains.domains = Some(hs);

    let runtime_config: RuntimeConfig = startup_config.into();

    // Test domain matching
    let addr = runtime_config
        .has_addr("myhost.local")
        .expect("Should find address for .local");
    assert_eq!(addr.to_string(), "192.168.1.100");

    let addr = runtime_config
        .has_addr("myhost.local.hometown")
        .expect("Should find address for .local.hometown");
    assert_eq!(addr.to_string(), "192.168.1.100");

    // Test non-matching
    assert!(runtime_config.has_addr("nonexistent.local").is_none());
    assert!(runtime_config.has_addr("myhost.unknown").is_none());
}
