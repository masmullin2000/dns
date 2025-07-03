use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::server::{self, ChannelData};

#[test]
fn test_channel_data_creation() {
    let bytes = vec![1, 2, 3, 4];
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    // We can't easily create a real UdpSocket in tests, so we'll create a mock
    // This tests the basic structure and constructor
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock = Arc::new(sock);

        let channel_data = ChannelData::new(bytes.clone(), addr, sock.clone());

        // Test that the data is stored correctly
        assert_eq!(channel_data.bytes, bytes);
        assert_eq!(channel_data.addr, addr);
        assert_eq!(Arc::strong_count(&channel_data.sock), 2); // One in channel_data, one in sock
    });
}

#[test]
fn test_udp_socket_creation() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Test socket creation with different addresses
        let sock = crate::server::udp_sock("127.0.0.1:0").unwrap();
        assert!(sock.local_addr().is_ok());

        // Test that the socket is bound to the correct protocol
        let local_addr = sock.local_addr().unwrap();
        assert!(local_addr.port() > 0);
        assert_eq!(
            local_addr.ip(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
    });
}

#[test]
fn test_udp_socket_invalid_address() {
    // Test that invalid addresses return errors
    let result = server::udp_sock("invalid_address");
    assert!(result.is_err());

    let result = server::udp_sock("256.256.256.256:53");
    assert!(result.is_err());
}

#[test]
fn test_channel_data_with_empty_bytes() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let bytes = vec![];
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let channel_data = ChannelData::new(bytes.clone(), addr, sock);

        assert!(channel_data.bytes.is_empty());
        assert_eq!(channel_data.addr, addr);
    });
}

#[test]
fn test_channel_data_with_large_bytes() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let bytes = vec![0u8; 65535]; // Max UDP packet size
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let channel_data = ChannelData::new(bytes.clone(), addr, sock);

        assert_eq!(channel_data.bytes.len(), 65535);
        assert_eq!(channel_data.addr, addr);
    });
}
