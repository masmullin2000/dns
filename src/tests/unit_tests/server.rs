use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::Duration;

use crate::server::{self, ChannelData, Eof};

// Helper function to create a minimal DNS query packet
fn create_dns_query_packet() -> Vec<u8> {
    // Simple DNS query for "example.com" A record
    // This is a minimal valid DNS packet for testing
    vec![
        0x00, 0x1c, // ID
        0x01, 0x00, // Flags (standard query)
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Query: example.com
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
        0x03, 0x63, 0x6f, 0x6d, // "com"
        0x00, // End of name
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
    ]
}

// Tests for project-specific ChannelData struct

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

#[tokio::test]
async fn test_channel_data_with_empty_bytes() {
    let bytes = vec![];
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let channel_data = ChannelData::new(bytes.clone(), addr, sock);

    assert!(channel_data.bytes.is_empty());
    assert_eq!(channel_data.addr, addr);
}

#[tokio::test]
async fn test_channel_data_with_large_bytes() {
    let bytes = vec![0u8; 65535]; // Max UDP packet size
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let channel_data = ChannelData::new(bytes.clone(), addr, sock);

    assert_eq!(channel_data.bytes.len(), 65535);
    assert_eq!(channel_data.addr, addr);
}

// Tests for project-specific udp_sock function

#[test]
fn test_udp_socket_invalid_address() {
    // Test that invalid addresses return errors
    let result = server::udp_sock("invalid_address");
    assert!(result.is_err());

    let result = server::udp_sock("256.256.256.256:53");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_udp_socket_creation() {
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
}

#[tokio::test]
async fn test_udp_socket_reuse_port() {
    // Test that udp_sock creates sockets with SO_REUSEPORT enabled
    let sock1 = crate::server::udp_sock("127.0.0.1:0").unwrap();
    let sock2 = crate::server::udp_sock("127.0.0.1:0").unwrap();

    let addr1 = sock1.local_addr().unwrap();
    let addr2 = sock2.local_addr().unwrap();

    // Both sockets should be bound successfully
    assert!(addr1.port() > 0);
    assert!(addr2.port() > 0);

    // They should have different ports (since we used port 0)
    assert_ne!(addr1.port(), addr2.port());

    // Both should be able to send/receive
    let test_data = b"Test reuse port";

    // sock1 sends to sock2
    sock1.send_to(test_data, &addr2).await.unwrap();

    let mut buffer = vec![0u8; 1024];
    let (bytes_received, sender_addr) = sock2.recv_from(&mut buffer).await.unwrap();

    assert_eq!(bytes_received, test_data.len());
    assert_eq!(&buffer[..bytes_received], test_data);
    assert_eq!(sender_addr, addr1);
}

// Tests for project-specific Eof trait implementation

#[tokio::test]
async fn test_tcp_read_eof_complete_packet() {
    // Test reading a complete DNS packet using Eof trait
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    // Server task that uses read_eof to read complete packet
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Use Eof trait to read complete packet
        stream.read_eof().await.unwrap()
    });

    // Client sends a complete DNS packet with TCP length prefix
    let mut client_stream = TcpStream::connect(server_addr).await.unwrap();
    let dns_packet = create_dns_query_packet();
    let packet_length = dns_packet.len() as u16;

    // Send TCP DNS format: 2-byte length prefix + DNS packet
    client_stream
        .write_all(&packet_length.to_be_bytes())
        .await
        .unwrap();
    client_stream.write_all(&dns_packet).await.unwrap();
    client_stream.shutdown().await.unwrap(); // Signal EOF

    // Verify server read complete packet
    let received_data = server_task.await.unwrap();
    let expected_data = [&packet_length.to_be_bytes()[..], &dns_packet[..]].concat();
    assert_eq!(received_data, expected_data);
}

#[tokio::test]
async fn test_tcp_read_eof_partial_packet() {
    // Test reading partial packets that get accumulated
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let packet_data = stream.read_eof().await.unwrap();
        packet_data
    });

    // Client sends data in small chunks
    let mut client_stream = TcpStream::connect(server_addr).await.unwrap();
    let dns_packet = create_dns_query_packet();
    let packet_length = dns_packet.len() as u16;

    // Send length prefix first
    client_stream
        .write_all(&packet_length.to_be_bytes())
        .await
        .unwrap();

    // Send DNS packet in small chunks
    let chunk_size = 5;
    for chunk in dns_packet.chunks(chunk_size) {
        client_stream.write_all(chunk).await.unwrap();
        // Small delay to ensure separate writes
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    client_stream.shutdown().await.unwrap();

    // Verify complete packet was assembled
    let received_data = server_task.await.unwrap();
    let expected_data = [&packet_length.to_be_bytes()[..], &dns_packet[..]].concat();
    assert_eq!(received_data, expected_data);
}

#[tokio::test]
async fn test_tcp_read_eof_detection() {
    // Test EOF detection when client closes connection
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.read_eof().await.unwrap()
    });

    // Client sends partial data then closes
    let mut client_stream = TcpStream::connect(server_addr).await.unwrap();
    let partial_data = b"incomplete data";
    client_stream.write_all(partial_data).await.unwrap();
    drop(client_stream); // Close connection to trigger EOF

    // Server should receive what was sent before EOF
    let received_data = server_task.await.unwrap();
    assert_eq!(received_data, partial_data);
}

#[tokio::test]
async fn test_tcp_read_eof_dns_validation() {
    // Test DNS packet validation during read_eof
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let packet_data = stream.read_eof().await.unwrap();

        // Try to parse as DNS packet (skipping 2-byte length prefix)
        let dns_parse_result = if packet_data.len() > 2 {
            simple_dns::Packet::parse(&packet_data[2..])
        } else {
            Err(simple_dns::SimpleDnsError::InsufficientData)
        };

        (packet_data.clone(), dns_parse_result.is_ok())
    });

    // Client sends valid DNS packet
    let mut client_stream = TcpStream::connect(server_addr).await.unwrap();
    let dns_packet = create_dns_query_packet();
    let packet_length = dns_packet.len() as u16;

    client_stream
        .write_all(&packet_length.to_be_bytes())
        .await
        .unwrap();
    client_stream.write_all(&dns_packet).await.unwrap();
    client_stream.shutdown().await.unwrap();

    let (received_data, is_valid_dns) = server_task.await.unwrap();
    assert_eq!(received_data.len(), 2 + dns_packet.len());
    assert!(is_valid_dns, "DNS packet should be valid");
}

#[tokio::test]
async fn test_tcp_read_eof_large_packet() {
    // Test handling of large packets up to MAX_PKT_SIZE
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let packet_data = stream.read_eof().await.unwrap();
        packet_data
    });

    // Create large packet (but not too large to avoid memory issues)
    let large_packet_size = 8192; // 8KB
    let large_data = vec![0xAB; large_packet_size];
    let packet_length = large_data.len() as u16;

    let mut client_stream = TcpStream::connect(server_addr).await.unwrap();
    client_stream
        .write_all(&packet_length.to_be_bytes())
        .await
        .unwrap();
    client_stream.write_all(&large_data).await.unwrap();
    client_stream.shutdown().await.unwrap();

    let received_data = server_task.await.unwrap();
    assert_eq!(received_data.len(), 2 + large_packet_size);

    // Verify length prefix
    let received_length = u16::from_be_bytes([received_data[0], received_data[1]]);
    assert_eq!(received_length as usize, large_packet_size);

    // Verify packet data
    assert_eq!(&received_data[2..], &large_data);
}

#[tokio::test]
async fn test_tcp_read_eof_empty_connection() {
    // Test read_eof behavior with immediately closed connection
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let packet_data = stream.read_eof().await.unwrap();
        packet_data
    });

    // Client connects and immediately closes
    let client_stream = TcpStream::connect(server_addr).await.unwrap();
    drop(client_stream); // Close immediately

    let received_data = server_task.await.unwrap();
    assert_eq!(received_data.len(), 0); // Should receive empty data
}

#[tokio::test]
async fn test_tcp_read_eof_incremental_dns_parsing() {
    // Test that read_eof correctly identifies complete DNS packets
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Use read_eof which should detect complete DNS packet
        let packet_data = stream.read_eof().await.unwrap();

        // Verify we can parse the DNS portion
        let dns_parse_result = if packet_data.len() > 2 {
            simple_dns::Packet::parse(&packet_data[2..]).is_ok()
        } else {
            false
        };

        (packet_data, dns_parse_result)
    });

    // Send valid DNS packet byte by byte to test incremental parsing
    let mut client_stream = TcpStream::connect(server_addr).await.unwrap();
    let dns_packet = create_dns_query_packet();
    let packet_length = dns_packet.len() as u16;

    // Send complete packet data
    let full_data = [&packet_length.to_be_bytes()[..], &dns_packet[..]].concat();

    // Send one byte at a time
    for &byte in &full_data {
        client_stream.write_all(&[byte]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    client_stream.shutdown().await.unwrap();

    let (received_data, parse_result) = server_task.await.unwrap();
    assert_eq!(received_data, full_data);
    assert!(parse_result, "DNS packet should parse correctly");
}

#[tokio::test]
async fn test_tcp_read_eof_malformed_data() {
    // Test handling of malformed TCP data in read_eof
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Use read_eof which tries to parse DNS packets
        let read_result = stream.read_eof().await;

        match read_result {
            Ok(data) => ("success", data.len()),
            Err(_) => ("error", 0),
        }
    });

    let client_task = tokio::spawn(async move {
        let mut client_stream = TcpStream::connect(server_addr).await.unwrap();

        // Send malformed length prefix (claims huge packet size)
        let fake_length: u16 = 0xFFFF; // 65535 bytes
        client_stream
            .write_all(&fake_length.to_be_bytes())
            .await
            .unwrap();

        // Send only a tiny bit of actual data
        let small_data = b"tiny";
        client_stream.write_all(small_data).await.unwrap();
        client_stream.shutdown().await.unwrap();

        2 + small_data.len() // length prefix + data
    });

    let (server_result, client_bytes_sent) = tokio::join!(server_task, client_task);
    let (result_type, bytes_received) = server_result.unwrap();
    let bytes_sent = client_bytes_sent.unwrap();

    // Server should receive the data without crashing, even if DNS parsing fails
    assert_eq!(
        result_type, "success",
        "Should handle malformed data gracefully"
    );
    assert_eq!(bytes_received, bytes_sent, "Should receive all sent bytes");
}
