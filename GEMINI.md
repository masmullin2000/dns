# Gemini Project Context: dns

## Project Overview

This project is a local DNS forwarder written in Rust. It is designed to provide DNS services for a local network, with the ability to block domains using blocklists. The application reads its configuration from a `dns.toml` file, which defines local DNS mappings, upstream nameservers, and paths to blocklist files. The server listens on both UDP and TCP ports 53.

## Key Files

- **`src/main.rs`**: The main source file containing the application logic. It handles DNS request parsing, local name resolution, blocklist checking, and forwarding requests to upstream nameservers.
- **`dns.toml`**: The configuration file. It specifies local network DNS entries, upstream nameservers, and the locations of the blocklist files.
- **`dns.service`**: A systemd service file for running the application as a background service on Linux systems.
- **`get_lists.sh`**: A shell script to download and update the domain blocklists from various sources.
- **`justfile`**: A command runner file (similar to a Makefile) that defines common project commands for building, running, and managing the application.
- **`Cargo.toml`**: The Rust package manifest, which defines project metadata, dependencies, and build profiles.

## Commands

The `justfile` provides the following commands:

- `just rel target triple=<target-triple>`: Compiles the project in release mode for a specific target.
- `just dev`: Compiles the project in development mode.
- `just run`: Runs the application in development mode.
- `just run-rel target triple=<target-triple>`: Runs the application in release mode.
- `just clippy type`: Runs the clippy linter to check for common mistakes and style issues.
- `just clean`: Cleans the build artifacts and downloaded blocklists.
- `just lists`: Executes the `get_lists.sh` script to download the latest blocklists.

## Dependencies

The project uses several key Rust libraries:

- **`tokio`**: An asynchronous runtime for writing network applications.
- **`simple-dns`**: A library for parsing and building DNS packets.
- **`bloomfilter`**: Used for efficient blocklist checking with a low memory footprint.
- **`anyhow`**: For flexible error handling.
- **`toml`**: For parsing the `dns.toml` configuration file.
