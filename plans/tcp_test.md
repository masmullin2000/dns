# Unit Tests for tcp_server in src/server.rs

## Analysis of Current State
- Existing unit tests in `src/tests/unit_tests/server.rs` only cover UDP components (ChannelData, udp_sock)
- No tests for tcp_server function or TCP-specific functionality
- Current test infrastructure uses standard tokio test setup

## Test Strategy

### 1. **Add TCP Server Core Tests**
- Test TCP listener binding and configuration
- Test connection acceptance and handling
- Test timeout behavior (250ms configured timeout)
- Test channel communication between TCP handler and processor

### 2. **Add TCP Stream Reading Tests (Eof trait)**
- Test `read_eof()` method for complete DNS packet reading
- Test handling of partial packets
- Test EOF detection
- Test DNS packet parsing validation in stream reading
- Test large packet handling (up to MAX_PKT_SIZE)

### 3. **Add TCP Integration Tests**
- Test complete TCP DNS request/response cycle
- Test TCP vs UDP behavior differences
- Test connection lifecycle management
- Test error handling for malformed TCP connections

### 4. **Add TCP-specific Error Cases**
- Test bind failures
- Test connection timeout scenarios
- Test channel send failures
- Test write failures on TCP stream

## Implementation Plan

### Files to Modify:
1. `src/tests/unit_tests/server.rs` - Add TCP server tests
2. `Cargo.toml` - Add test dependencies if needed (tokio-test, mockall)

### Test Structure:
- Use tokio::test for async tests
- Mock TCP connections using tokio test utilities
- Test both success and failure scenarios
- Follow existing test patterns in the codebase

### Key Test Cases:
- `test_tcp_server_binding()`
- `test_tcp_connection_handling()`
- `test_tcp_read_eof_complete_packet()`
- `test_tcp_read_eof_partial_packet()`
- `test_tcp_timeout_behavior()`
- `test_tcp_channel_communication()`
- `test_tcp_error_scenarios()`

## Technical Implementation Details

### TCP Server Function Analysis
The `tcp_server` function in `src/server.rs:242-307` has these key components:
- Binds to "0.0.0.0:53" with TCP listener
- Uses 250ms timeout for connection reads
- Spawns async tasks for request processing
- Uses mpsc channel for communication between accept loop and processor
- Implements custom `Eof` trait for TCP stream reading

### Eof Trait Implementation
The `Eof` trait (`src/server.rs:309-333`) needs comprehensive testing:
- Reads data in chunks up to MAX_PKT_SIZE (65535 bytes)
- Accumulates data until complete DNS packet is received
- Validates DNS packet structure using `dns::Packet::parse()`
- Handles partial reads and EOF conditions

### Testing Challenges
1. **Port 53 Binding**: Tests cannot bind to port 53 (requires root), need to use alternative ports
2. **Async Complexity**: TCP server runs in infinite loop, requires careful test setup/teardown
3. **Channel Testing**: Need to verify mpsc channel communication works correctly
4. **Timeout Testing**: Need to simulate slow connections and verify timeout behavior
5. **DNS Packet Validation**: Need valid DNS packet data for realistic testing

### Mock Strategy
- Use `tokio::net::TcpListener::bind("127.0.0.1:0")` for dynamic port allocation
- Create helper functions to generate valid DNS packets
- Use `tokio::time::timeout()` in tests to prevent hanging
- Mock upstream DNS responses for integration tests