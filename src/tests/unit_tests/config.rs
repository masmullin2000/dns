use std::str::FromStr;

use crate::config::Config;

#[test]
fn test_config_from_str_valid() {
    let toml_content = r#"
[LocalNetwork]
"tplinkwifi.net" = "192.168.1.1"
dns = "192.168.0.2"
domains = ["local", "home"]
blocklists = ["./test_blocklist.list"]

[nameservers]
"1.1.1.1" = true
"8.8.8.8" = true
"192.168.0.2" = false
"#;

    // Create a dummy blocklist file for the test
    std::fs::write("./test_blocklist.list", "*.blocked.com\n*.another.org").unwrap();

    let config = Config::from_str(toml_content).expect("Failed to parse config");

    assert_eq!(
        config
            .local_network
            .hosts
            .get("tplinkwifi.net")
            .unwrap()
            .to_string(),
        "192.168.1.1"
    );
    assert_eq!(
        config.local_network.hosts.get("dns").unwrap().to_string(),
        "192.168.0.2"
    );
    let Some(domains) = &config.local_network.domains else {
        panic!("Expected domains to be defined");
    };
    assert!(domains.contains(&"local".to_string()));
    assert!(domains.contains(&"home".to_string()));
    assert!(config.blocklist.is_some());
    assert!(
        config
            .get_nameservers()
            .contains(&"1.1.1.1:53".parse().unwrap())
    );
    assert!(
        config
            .get_nameservers()
            .contains(&"8.8.8.8:53".parse().unwrap())
    );
    assert!(
        !config
            .get_nameservers()
            .contains(&"192.168.0.2:53".parse().unwrap())
    );

    // Clean up the dummy blocklist file
    std::fs::remove_file("./test_blocklist.list").unwrap();
}

#[test]
fn test_config_from_str_no_nameservers() {
    let toml_content = r#"
[LocalNetwork]
dns = "192.168.0.2"
"#;

    let err = Config::from_str(toml_content);
    assert!(
        err.is_err(),
        "Expected error when no nameservers are defined"
    );
}

#[test]
fn test_config_has_addr_direct_match() {
    let mut config = Config::default();
    config
        .local_network
        .hosts
        .insert("myhost".to_string(), "192.168.1.100".parse().unwrap());

    let addr = config.has_addr("myhost").expect("Should find address");
    assert_eq!(addr.to_string(), "192.168.1.100");
}

#[test]
fn test_config_has_addr_domain_match() {
    let mut config = Config::default();
    config
        .local_network
        .hosts
        .insert("myhost".to_string(), "192.168.1.100".parse().unwrap());

    let hs = ["local"].iter().map(|&i| String::from(i)).collect();

    config.local_network.domains = Some(hs);

    let addr = config
        .has_addr("myhost.local")
        .expect("Should find address");
    assert_eq!(addr.to_string(), "192.168.1.100");

    let Some(domains) = &mut config.local_network.domains else {
        panic!("Expected domains to be defined");
    };

    domains.push("local.hometown".to_string());
    let addr = config
        .has_addr("myhost.local.hometown")
        .expect("Should find address");
    assert_eq!(addr.to_string(), "192.168.1.100");
}

#[test]
fn test_config_has_addr_no_match() {
    let config = Config::default();
    let addr = config.has_addr("nonexistent");
    assert!(addr.is_none());
}

#[test]
fn test_config_has_block_blocked() {
    let mut config = Config::default();
    config.insert_blocklist_item("blocked.com");
    config.build_blocklist();

    assert!(config.has_block("b.a.test.blocked.com"));
    assert!(config.has_block("a.test.blocked.com"));
    assert!(config.has_block("test.blocked.com"));
    assert!(config.has_block("blocked.com"));
}

#[test]
fn test_config_has_block_not_blocked() {
    let mut config = Config::default();
    config.insert_blocklist_item("blocked.com");
    config.build_blocklist();

    assert!(!config.has_block("google.com"));
}

#[test]
fn test_config_has_block_empty_blocklist() {
    let config = Config::default();
    assert!(!config.has_block("any.domain.com"));
}

#[test]
fn test_config_get_nameservers() {
    let toml_content = r#"
[LocalNetwork]

[nameservers]
"1.1.1.1" = true
"8.8.8.8" = false
"192.168.0.1" = true
"#;

    let config = Config::from_str(toml_content).expect("Failed to parse config");
    let nameservers = config.get_nameservers();

    assert_eq!(nameservers.len(), 2);
    assert!(nameservers.contains(&"1.1.1.1:53".parse().unwrap()));
    assert!(nameservers.contains(&"192.168.0.1:53".parse().unwrap()));
    assert!(!nameservers.contains(&"8.8.8.8:53".parse().unwrap()));
}
