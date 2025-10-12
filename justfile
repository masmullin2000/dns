# Show all available targets
show:
    @just --list

# Build binary with specified options (opt: dev/release, target: gnu/musl, triple: arch-unknown-linux, bin: dns/dns-web/all)
build opt="dev" target="musl" triple=(arch() + "-unknown-linux") bin="all":
    #!/usr/bin/env sh
    echo {{opt}} {{target}} {{triple}} {{bin}}
    if [ {{bin}} = "all" ]; then
        cargo build --profile {{opt}} --target {{triple}}-{{target}}
    else
        cargo build --profile {{opt}} --target {{triple}}-{{target}} --bin {{bin}}
    fi

# Build and run debug binary with sudo
run opt="dev" target="musl" triple=(arch() + "-unknown-linux"):
    #!/usr/bin/env sh
    just build {{opt}} {{target}} {{triple}}
    if [ {{opt}} = "dev" ]; then TYPE="debug"; else TYPE="release"; fi
    echo Running {{triple}}-{{target}}/$TYPE/dns
    sudo ./target/{{triple}}-{{target}}/$TYPE/dns -c ./dns.toml -l debug

# Run clippy linter with pedantic/nursery lints
clippy type="stable":
    cargo +{{type}} clippy -- -D clippy::pedantic -D clippy::nursery -D clippy::unwrap-used

# Run full pre-commit checks (clean, check, fmt, clippy, test)
pre: clean check fmt clippy test
    just clippy beta
    just clippy nightly

# Checks compile
check:
    cargo check

# Checks formatting
fmt:
    cargo fmt --check

# Run unit tests
test:
    cargo test

# Run benchmarks
bench:
    cargo bench

# Clean build artifacts and downloaded blocklists
clean:
    cargo clean
    -rm *.list

# Download/update domain blocklists
lists:
    bash get_lists.sh

# Build and run web UI
web opt="dev" target="musl" triple=(arch() + "-unknown-linux"):
    #!/usr/bin/env sh
    just build {{opt}} {{target}} {{triple}} dns-web
    if [ {{opt}} = "dev" ]; then TYPE="debug"; else TYPE="release"; fi
    echo Running {{triple}}-{{target}}/$TYPE/dns-web
    ./target/{{triple}}-{{target}}/$TYPE/dns-web -c ./dns.toml -p 3000 -d /code/dns -l debug 
