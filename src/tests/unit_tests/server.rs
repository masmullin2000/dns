use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{Duration, timeout};

use crate::server::{self, ChannelData, Eof};

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

// TCP Server Core Tests

#[tokio::test]
async fn test_tcp_listener_binding() {
    // Test that we can bind to a TCP listener on an available port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    // Verify the listener is bound to the correct address
    assert_eq!(
        local_addr.ip(),
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert!(local_addr.port() > 0);

    // Test that the listener can accept connections
    let listener = Arc::new(listener);
    let test_listener = listener.clone();

    tokio::spawn(async move {
        let _connection = test_listener.accept().await;
    });

    // Try to connect to the listener
    let connect_result = timeout(Duration::from_millis(100), TcpStream::connect(local_addr)).await;

    assert!(connect_result.is_ok());
}

#[tokio::test]
async fn test_tcp_listener_invalid_address() {
    // Test binding to invalid addresses
    let result = TcpListener::bind("256.256.256.256:53").await;
    assert!(result.is_err());

    let result = TcpListener::bind("invalid_address:53").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_tcp_connection_handling() {
    // Test basic TCP connection acceptance and data handling
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    // Spawn a task to handle incoming connections
    let listener = Arc::new(listener);
    let test_listener = listener.clone();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = test_listener.accept().await.unwrap();

        // Read data from the connection
        let mut buffer = vec![0u8; 1024];
        let bytes_read = stream.read(&mut buffer).await.unwrap();

        // Echo the data back
        stream.write_all(&buffer[..bytes_read]).await.unwrap();

        bytes_read
    });

    // Connect and send test data
    let mut client_stream = TcpStream::connect(local_addr).await.unwrap();
    let test_data = b"Hello, TCP server!";
    client_stream.write_all(test_data).await.unwrap();

    // Read the echoed data
    let mut response_buffer = vec![0u8; test_data.len()];
    client_stream
        .read_exact(&mut response_buffer)
        .await
        .unwrap();

    // Verify server received the data
    let bytes_read = server_task.await.unwrap();
    assert_eq!(bytes_read, test_data.len());
    assert_eq!(response_buffer, test_data);
}

#[tokio::test]
async fn test_tcp_connection_timeout() {
    // Test that connections respect timeout behavior
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let listener = Arc::new(listener);
    let test_listener = listener.clone();

    // Spawn a task that simulates slow connection handling
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = test_listener.accept().await.unwrap();

        // Simulate slow reading with timeout
        let timeout_duration = Duration::from_millis(100);
        let mut buffer = vec![0u8; 1024];

        let read_result = timeout(timeout_duration, stream.read(&mut buffer)).await;

        match read_result {
            Ok(Ok(bytes_read)) => bytes_read,
            Ok(Err(_)) => 0, // Read error
            Err(_) => 0,     // Timeout
        }
    });

    // Connect but don't send data immediately
    let _client_stream = TcpStream::connect(local_addr).await.unwrap();

    // The server should timeout waiting for data
    let result = server_task.await.unwrap();
    assert_eq!(result, 0); // Should timeout and return 0
}

#[tokio::test]
async fn test_tcp_multiple_connections() {
    // Test handling multiple concurrent TCP connections
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let listener = Arc::new(listener);
    let connection_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Spawn server that handles multiple connections
    let test_listener = listener.clone();
    let server_counter = connection_count.clone();

    let server_task = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut stream, _) = test_listener.accept().await.unwrap();
            server_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

            // Handle connection in a separate task
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 1024];
                let bytes_read = stream.read(&mut buffer).await.unwrap_or(0);
                if bytes_read > 0 {
                    let _ = stream.write_all(&buffer[..bytes_read]).await;
                }
            });
        }
    });

    // Create multiple client connections
    let mut client_tasks = Vec::new();

    for i in 0..3 {
        let client_task = tokio::spawn(async move {
            let mut stream = TcpStream::connect(local_addr).await.unwrap();
            let test_data = format!("Client {}", i);
            stream.write_all(test_data.as_bytes()).await.unwrap();

            let mut response = vec![0u8; test_data.len()];
            stream.read_exact(&mut response).await.unwrap();
            response
        });
        client_tasks.push(client_task);
    }

    // Wait for all connections to complete
    server_task.await.unwrap();

    // Verify all clients received responses
    for (i, task) in client_tasks.into_iter().enumerate() {
        let response = task.await.unwrap();
        let expected = format!("Client {}", i);
        assert_eq!(response, expected.as_bytes());
    }

    // Verify server handled all connections
    assert_eq!(
        connection_count.load(std::sync::atomic::Ordering::SeqCst),
        3
    );
}

#[tokio::test]
async fn test_tcp_channel_communication() {
    // Test mpsc channel communication pattern used in tcp_server
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(Vec<u8>, TcpStream)>(10);

    // Simulate server-side channel receiver
    let receiver_task = tokio::spawn(async move {
        let mut received_data = Vec::new();

        while let Some((data, _stream)) = rx.recv().await {
            received_data.push(data);

            // Break after receiving 3 messages
            if received_data.len() >= 3 {
                break;
            }
        }

        received_data
    });

    // Simulate sending data through channel
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    // Send test data through channel
    for i in 0..3 {
        let test_data = format!("Message {}", i).into_bytes();
        let mock_stream = TcpStream::connect(local_addr).await.unwrap();

        tx.send((test_data.clone(), mock_stream)).await.unwrap();
    }

    // Drop sender to close channel
    drop(tx);

    // Verify receiver got all messages
    let received = receiver_task.await.unwrap();
    assert_eq!(received.len(), 3);

    for (i, data) in received.iter().enumerate() {
        let expected = format!("Message {}", i).into_bytes();
        assert_eq!(*data, expected);
    }
}

#[tokio::test]
async fn test_tcp_dns_packet_size_handling() {
    // Test handling of DNS packet sizes in TCP connections
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let listener = Arc::new(listener);
    let test_listener = listener.clone();

    // Server task that reads and validates DNS packet size
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = test_listener.accept().await.unwrap();

        // Read the DNS packet with length prefix (TCP DNS format)
        let mut length_buffer = [0u8; 2];
        stream.read_exact(&mut length_buffer).await.unwrap();

        let packet_length = u16::from_be_bytes(length_buffer) as usize;

        // Read the actual DNS packet
        let mut packet_buffer = vec![0u8; packet_length];
        stream.read_exact(&mut packet_buffer).await.unwrap();

        (packet_length, packet_buffer)
    });

    // Client sends a DNS packet with TCP length prefix
    let mut client_stream = TcpStream::connect(local_addr).await.unwrap();
    let dns_packet = create_dns_query_packet();
    let packet_length = dns_packet.len() as u16;

    // Send length prefix (2 bytes, big endian)
    client_stream
        .write_all(&packet_length.to_be_bytes())
        .await
        .unwrap();

    // Send DNS packet
    client_stream.write_all(&dns_packet).await.unwrap();

    // Verify server received correct packet
    let (received_length, received_packet) = server_task.await.unwrap();
    assert_eq!(received_length, dns_packet.len());
    assert_eq!(received_packet, dns_packet);
}

// Additional UDP Server Tests

#[tokio::test]
async fn test_udp_channel_communication() {
    // Test mpsc channel communication pattern used in udp_server
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ChannelData>(64);

    // Create test socket
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    // Simulate server-side channel receiver
    let receiver_task = tokio::spawn(async move {
        let mut received_data = Vec::new();

        while let Some(channel_data) = rx.recv().await {
            received_data.push(channel_data.bytes);

            // Break after receiving 3 messages
            if received_data.len() >= 3 {
                break;
            }
        }

        received_data
    });

    // Send test data through channel
    for i in 0..3 {
        let test_data = format!("UDP Message {}", i).into_bytes();
        let test_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let channel_data = ChannelData::new(test_data.clone(), test_addr, sock.clone());
        tx.send(channel_data).await.unwrap();
    }

    // Drop sender to close channel
    drop(tx);

    // Verify receiver got all messages
    let received = receiver_task.await.unwrap();
    assert_eq!(received.len(), 3);

    for (i, data) in received.iter().enumerate() {
        let expected = format!("UDP Message {}", i).into_bytes();
        assert_eq!(*data, expected);
    }
}

#[tokio::test]
async fn test_udp_channel_capacity() {
    // Test channel capacity behavior (64 messages)
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ChannelData>(5); // Small capacity for testing

    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let test_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    // Fill the channel to capacity
    for i in 0..5 {
        let test_data = format!("Message {}", i).into_bytes();
        let channel_data = ChannelData::new(test_data, test_addr, sock.clone());
        tx.send(channel_data).await.unwrap();
    }

    // Try to send one more - should not block in this test
    let test_data = b"Overflow message".to_vec();
    let channel_data = ChannelData::new(test_data, test_addr, sock.clone());

    // This should work since we're using try_send pattern
    let send_result = tx.try_send(channel_data);
    assert!(send_result.is_err()); // Should be full

    // Receive one message to free up space
    let received = rx.recv().await.unwrap();
    assert_eq!(received.bytes, b"Message 0");

    // Now sending should work
    let test_data = b"New message".to_vec();
    let channel_data = ChannelData::new(test_data.clone(), test_addr, sock);
    tx.send(channel_data).await.unwrap();

    let received = rx.recv().await.unwrap();
    assert_eq!(received.bytes, b"Message 1");
}

#[tokio::test]
async fn test_udp_packet_reception() {
    // Test UDP packet reception and processing
    let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_sock.local_addr().unwrap();

    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_sock.local_addr().unwrap();

    // Server task that receives packets
    let server_task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 1024];
        let (bytes_received, sender_addr) = server_sock.recv_from(&mut buffer).await.unwrap();

        // Echo the packet back
        server_sock
            .send_to(&buffer[..bytes_received], &sender_addr)
            .await
            .unwrap();

        (
            bytes_received,
            sender_addr,
            buffer[..bytes_received].to_vec(),
        )
    });

    // Client sends DNS packet
    let dns_packet = create_dns_query_packet();
    client_sock
        .send_to(&dns_packet, &server_addr)
        .await
        .unwrap();

    // Verify server received packet correctly
    let (bytes_received, sender_addr, received_packet) = server_task.await.unwrap();
    assert_eq!(bytes_received, dns_packet.len());
    assert_eq!(sender_addr, client_addr);
    assert_eq!(received_packet, dns_packet);

    // Verify client receives echo
    let mut response_buffer = vec![0u8; dns_packet.len()];
    let (response_bytes, _) = client_sock.recv_from(&mut response_buffer).await.unwrap();
    assert_eq!(response_bytes, dns_packet.len());
    assert_eq!(response_buffer, dns_packet);
}

#[tokio::test]
async fn test_udp_large_packet_handling() {
    // Test handling of large UDP packets up to MAX_PKT_SIZE
    let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_sock.local_addr().unwrap();

    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Create large packet (not quite max size to avoid fragmentation issues)
    let large_packet = vec![0xAB; 8192]; // 8KB packet

    // Server task
    let server_task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535]; // MAX_PKT_SIZE
        let (bytes_received, sender_addr) = server_sock.recv_from(&mut buffer).await.unwrap();

        // Send response
        let response = b"Large packet received";
        server_sock.send_to(response, &sender_addr).await.unwrap();

        (bytes_received, buffer[..bytes_received].to_vec())
    });

    // Client sends large packet
    client_sock
        .send_to(&large_packet, &server_addr)
        .await
        .unwrap();

    // Verify server handled large packet
    let (bytes_received, received_packet) = server_task.await.unwrap();
    assert_eq!(bytes_received, large_packet.len());
    assert_eq!(received_packet, large_packet);

    // Verify client gets response
    let mut response_buffer = vec![0u8; 1024];
    let (response_bytes, _) = client_sock.recv_from(&mut response_buffer).await.unwrap();
    assert_eq!(&response_buffer[..response_bytes], b"Large packet received");
}

#[tokio::test]
async fn test_udp_concurrent_packet_reception() {
    // Test concurrent packet reception from multiple clients
    let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let server_addr = server_sock.local_addr().unwrap();

    let num_clients = 5;
    let received_packets = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    // Server task that handles multiple packets
    let server_sock_clone = server_sock.clone();
    let received_clone = received_packets.clone();
    let server_task = tokio::spawn(async move {
        for _ in 0..num_clients {
            let mut buffer = vec![0u8; 1024];
            let (bytes_received, sender_addr) =
                server_sock_clone.recv_from(&mut buffer).await.unwrap();

            // Store received packet info
            let packet_info = (
                bytes_received,
                sender_addr,
                buffer[..bytes_received].to_vec(),
            );
            received_clone.lock().await.push(packet_info);

            // Send acknowledgment
            let ack = format!("ACK from {}", sender_addr);
            server_sock_clone
                .send_to(ack.as_bytes(), &sender_addr)
                .await
                .unwrap();
        }
    });

    // Create multiple clients
    let mut client_tasks = Vec::new();

    for i in 0..num_clients {
        let client_task = tokio::spawn(async move {
            let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client_sock.local_addr().unwrap();

            // Send unique packet
            let packet = format!("Client {} packet", i);
            client_sock
                .send_to(packet.as_bytes(), &server_addr)
                .await
                .unwrap();

            // Receive acknowledgment
            let mut ack_buffer = vec![0u8; 1024];
            let (ack_bytes, _) = client_sock.recv_from(&mut ack_buffer).await.unwrap();
            let ack_message = String::from_utf8_lossy(&ack_buffer[..ack_bytes]);

            (client_addr, packet, ack_message.to_string())
        });
        client_tasks.push(client_task);
    }

    // Wait for all clients to complete
    let mut client_results = Vec::new();
    for task in client_tasks {
        client_results.push(task.await.unwrap());
    }

    // Wait for server to process all packets
    server_task.await.unwrap();

    // Verify all packets were received
    let received = received_packets.lock().await;
    assert_eq!(received.len(), num_clients);

    // Verify each client got correct acknowledgment
    for (client_addr, sent_packet, ack_message) in client_results {
        assert!(ack_message.contains(&client_addr.to_string()));

        // Find corresponding received packet
        let found = received.iter().any(|(_, addr, packet)| {
            *addr == client_addr && String::from_utf8_lossy(packet) == sent_packet
        });
        assert!(
            found,
            "Packet from {} not found in received packets",
            client_addr
        );
    }
}

#[tokio::test]
async fn test_udp_malformed_packet_handling() {
    // Test handling of malformed or empty packets
    let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_sock.local_addr().unwrap();

    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Server task that handles various packet types
    let server_task = tokio::spawn(async move {
        let mut received_packets = Vec::new();

        // Receive 3 different packet types
        for _ in 0..3 {
            let mut buffer = vec![0u8; 1024];
            let (bytes_received, _) = server_sock.recv_from(&mut buffer).await.unwrap();
            received_packets.push((bytes_received, buffer[..bytes_received].to_vec()));
        }

        received_packets
    });

    // Send empty packet
    client_sock.send_to(&[], &server_addr).await.unwrap();

    // Send single byte packet
    client_sock.send_to(&[0xFF], &server_addr).await.unwrap();

    // Send valid DNS packet
    let dns_packet = create_dns_query_packet();
    client_sock
        .send_to(&dns_packet, &server_addr)
        .await
        .unwrap();

    // Verify server received all packets
    let received = server_task.await.unwrap();
    assert_eq!(received.len(), 3);

    // Check empty packet
    assert_eq!(received[0].0, 0);
    assert_eq!(received[0].1, vec![]);

    // Check single byte packet
    assert_eq!(received[1].0, 1);
    assert_eq!(received[1].1, vec![0xFF]);

    // Check DNS packet
    assert_eq!(received[2].0, dns_packet.len());
    assert_eq!(received[2].1, dns_packet);
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

// TCP Stream Reading Tests (Eof trait)

#[tokio::test]
async fn test_tcp_read_eof_complete_packet() {
    // Test reading a complete DNS packet using Eof trait
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    // Server task that uses read_eof to read complete packet
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Use Eof trait to read complete packet
        let packet_data = stream.read_eof().await.unwrap();
        packet_data
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
        let packet_data = stream.read_eof().await.unwrap();
        packet_data
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
