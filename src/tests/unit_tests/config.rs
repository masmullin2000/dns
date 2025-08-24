use std::str::FromStr;

use crate::block_filter::BlocklistBuilder;
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
    assert!(startup_config.nameservers.ip4.contains("1.1.1.1"));
    assert!(startup_config.nameservers.ip4.contains("8.8.8.8"));
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
    assert!(runtime_config.block_filter.contains("blocked.com"));
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

#[test]
fn test_blocklist_builder_set_item_regular_domain() {
    let mut builder = BlocklistBuilder::default();
    builder.set_item("example.com");
    builder.set_item("another.org");

    assert!(builder.contains("example.com"));
    assert!(builder.contains("another.org"));
}

#[test]
fn test_blocklist_builder_set_item_wildcard_domain() {
    let mut builder = BlocklistBuilder::default();
    builder.set_item("*.example.com");
    builder.set_item("*.another.org");

    assert!(builder.contains("example.com"));
    assert!(builder.contains("another.org"));
    assert!(!builder.contains("*.example.com"));
    assert!(!builder.contains("*.another.org"));
}

#[test]
fn test_blocklist_builder_set_item_empty_string() {
    let mut builder = BlocklistBuilder::default();
    builder.set_item("");

    assert!(builder.is_empty());
}

#[test]
fn test_blocklist_builder_set_item_whitespace() {
    let mut builder = BlocklistBuilder::default();
    builder.set_item("   ");

    assert!(!builder.contains("   "));
    assert!(builder.is_empty());
}

#[test]
fn test_blocklist_builder_set_item_mixed_domains() {
    let mut builder = BlocklistBuilder::default();
    builder.set_item("direct.com");
    builder.set_item("*.wildcard.com");
    builder.set_item("");
    builder.set_item("another.org");

    assert!(builder.contains("direct.com"));
    assert!(builder.contains("wildcard.com"));
    assert!(builder.contains("another.org"));
    assert!(!builder.contains("*.wildcard.com"));
    assert_eq!(builder.len(), 3);
}

#[test]
fn test_blocklist_builder_set_file_valid_file() {
    let test_content = "example.com\n*.blocked.org\nanothersite.net\n";
    std::fs::write("./test_blocklist_set_file.list", test_content).unwrap();

    let mut builder = BlocklistBuilder::default();
    let result = builder.set_file("./test_blocklist_set_file.list");

    assert!(result.is_ok());
    assert!(builder.contains("example.com"));
    assert!(builder.contains("blocked.org"));
    assert!(builder.contains("anothersite.net"));
    assert!(!builder.contains("*.blocked.org"));
    assert_eq!(builder.len(), 3);

    std::fs::remove_file("./test_blocklist_set_file.list").unwrap();
}

#[test]
fn test_blocklist_builder_set_file_empty_file() {
    std::fs::write("./test_blocklist_empty.list", "").unwrap();

    let mut builder = BlocklistBuilder::default();
    let result = builder.set_file("./test_blocklist_empty.list");

    assert!(result.is_ok());
    assert!(builder.is_empty());

    std::fs::remove_file("./test_blocklist_empty.list").unwrap();
}

#[test]
fn test_blocklist_builder_set_file_with_empty_lines() {
    let test_content = "example.com\n\n*.blocked.org\n\n\nanothersite.net\n";
    std::fs::write("./test_blocklist_empty_lines.list", test_content).unwrap();

    let mut builder = BlocklistBuilder::default();
    let result = builder.set_file("./test_blocklist_empty_lines.list");

    assert!(result.is_ok());
    assert!(builder.contains("example.com"));
    assert!(builder.contains("blocked.org"));
    assert!(builder.contains("anothersite.net"));
    assert_eq!(builder.len(), 3);

    std::fs::remove_file("./test_blocklist_empty_lines.list").unwrap();
}

#[test]
fn test_blocklist_builder_set_file_nonexistent_file() {
    let mut builder = BlocklistBuilder::default();
    let result = builder.set_file("./nonexistent_file.list");

    assert!(result.is_err());
    assert!(builder.is_empty());
}

#[test]
fn test_blocklist_builder_set_file_duplicate_domains() {
    let test_content = "example.com\nexample.com\n*.example.com\nanothersite.net\n";
    std::fs::write("./test_blocklist_duplicates.list", test_content).unwrap();

    let mut builder = BlocklistBuilder::default();
    let result = builder.set_file("./test_blocklist_duplicates.list");

    assert!(result.is_ok());
    assert!(builder.contains("example.com"));
    assert!(builder.contains("anothersite.net"));
    assert_eq!(builder.len(), 2);

    std::fs::remove_file("./test_blocklist_duplicates.list").unwrap();
}

#[test]
fn test_blocklist_builder_build_empty_set() {
    let builder = BlocklistBuilder::default();
    let filter = builder.build();
    assert!(filter.is_empty());
}

#[test]
fn test_blocklist_builder_build_with_domains() {
    let mut builder = BlocklistBuilder::default();
    builder.set_item("example.com");
    builder.set_item("*.blocked.org");
    builder.set_item("anothersite.net");

    let filter = builder.build();

    assert!(filter.contains("example.com"));
    assert!(filter.contains("blocked.org"));
    assert!(filter.contains("anothersite.net"));
}

#[test]
fn test_blocklist_builder_build_single_domain() {
    let mut builder = BlocklistBuilder::default();
    builder.set_item("single.com");

    let filter = builder.build();

    assert!(filter.contains("single.com"));
}

#[test]
fn test_blocklist_builder_build_large_set() {
    let mut builder = BlocklistBuilder::default();
    for i in 0..1000 {
        builder.set_item(&format!("domain{i}.com"));
    }

    let filter = builder.build();

    assert!(filter.contains("domain0.com"));
    assert!(filter.contains("domain500.com"));
    assert!(filter.contains("domain999.com"));
}

#[test]
fn test_blocklist_builder_from_vec_valid_files() {
    let test_content1 = "example.com\n*.blocked.org\n";
    let test_content2 = "anothersite.net\n*.wildcard.com\n";

    std::fs::write("./test_blocklist_from1.list", test_content1).unwrap();
    std::fs::write("./test_blocklist_from2.list", test_content2).unwrap();

    let files = vec![
        "./test_blocklist_from1.list".to_string(),
        "./test_blocklist_from2.list".to_string(),
    ];

    let builder = BlocklistBuilder::from(files);

    assert!(builder.contains("example.com"));
    assert!(builder.contains("blocked.org"));
    assert!(builder.contains("anothersite.net"));
    assert!(builder.contains("wildcard.com"));
    assert_eq!(builder.len(), 4);

    std::fs::remove_file("./test_blocklist_from1.list").unwrap();
    std::fs::remove_file("./test_blocklist_from2.list").unwrap();
}

#[test]
fn test_blocklist_builder_from_vec_empty_vec() {
    let files: Vec<String> = vec![];
    let builder = BlocklistBuilder::from(files);

    assert!(builder.is_empty());
}

#[test]
fn test_blocklist_builder_from_vec_nonexistent_file() {
    let files = vec!["./nonexistent_file.list".to_string()];
    let builder = BlocklistBuilder::from(files);

    assert!(builder.is_empty());
}

#[test]
fn test_blocklist_builder_from_vec_mixed_files() {
    let test_content = "valid.com\n*.valid.org\n";
    std::fs::write("./test_blocklist_mixed_valid.list", test_content).unwrap();

    let files = vec![
        "./test_blocklist_mixed_valid.list".to_string(),
        "./nonexistent_file.list".to_string(),
    ];

    let builder = BlocklistBuilder::from(files);

    assert!(builder.contains("valid.com"));
    assert!(builder.contains("valid.org"));
    assert_eq!(builder.len(), 2);

    std::fs::remove_file("./test_blocklist_mixed_valid.list").unwrap();
}

#[test]
fn test_blocklist_builder_from_option_some() {
    let test_content = "example.com\n*.blocked.org\n";
    std::fs::write("./test_blocklist_option_some.list", test_content).unwrap();

    let files = Some(vec!["./test_blocklist_option_some.list".to_string()]);
    let builder = BlocklistBuilder::from(files);

    assert!(builder.contains("example.com"));
    assert!(builder.contains("blocked.org"));
    assert_eq!(builder.len(), 2);

    std::fs::remove_file("./test_blocklist_option_some.list").unwrap();
}

#[test]
fn test_blocklist_builder_from_option_none() {
    let files: Option<Vec<String>> = None;
    let builder = BlocklistBuilder::from(files);

    assert!(builder.is_empty());
}

#[test]
fn test_blocklist_builder_edge_case_just_wildcard() {
    let mut builder = BlocklistBuilder::default();
    builder.set_item("*.");

    assert!(builder.contains(""));
    assert_eq!(builder.len(), 1);
}

#[test]
fn test_blocklist_builder_edge_case_multiple_wildcards() {
    let mut builder = BlocklistBuilder::default();
    builder.set_item("*.*.example.com");

    assert!(builder.contains("*.example.com"));
    assert!(!builder.contains("*.*.example.com"));
    assert_eq!(builder.len(), 1);
}

#[test]
fn test_blocklist_builder_edge_case_unicode_domains() {
    let mut builder = BlocklistBuilder::default();
    builder.set_item("тест.com");
    builder.set_item("*.例え.テスト");

    assert!(builder.contains("тест.com"));
    assert!(builder.contains("例え.テスト"));
    assert_eq!(builder.len(), 2);
}

#[test]
fn test_blocklist_builder_edge_case_very_long_domain() {
    let mut builder = BlocklistBuilder::default();
    let long_domain = "a".repeat(253) + ".com";
    builder.set_item(&long_domain);

    assert!(builder.contains(&long_domain));
    assert_eq!(builder.len(), 1);
}

#[test]
fn test_blocklist_builder_build_and_check_false_postives() {
    let mut builder = BlocklistBuilder::default();
    builder.set_item("blocked.com");
    builder.set_item("*.blocked.org");

    let filter = builder.build();

    assert!(filter.contains("blocked.com"));
    assert!(filter.contains("blocked.org"));
    assert!(!filter.contains("notblocked.com"));
    assert!(!filter.contains("different.net"));
}

#[test]
fn test_blocklist_builder_integration_file_to_filter() {
    let test_content = "example.com\n*.blocked.org\n\nanothersite.net\n";
    std::fs::write("./test_blocklist_integration.list", test_content).unwrap();

    let files = vec!["./test_blocklist_integration.list".to_string()];
    let builder = BlocklistBuilder::from(files);
    let filter = builder.build();

    assert!(filter.contains("example.com"));
    assert!(filter.contains("blocked.org"));
    assert!(filter.contains("anothersite.net"));
    assert!(!filter.contains("notblocked.com"));

    std::fs::remove_file("./test_blocklist_integration.list").unwrap();
}
