use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{Duration, timeout};

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
