# Show all available targets
list:
    @just --list

# Build optimized release binary
rel target triple=(arch() + "-unknown-linux"):
    echo {{target}} {{triple}}
    JEMALLOC_SYS_WITH_MALLOC_CONF=narenas:1,tcache:false,dirty_decay_ms:0,muzzy_decay_ms:0,abort_conf:true \
    cargo build -r --target {{triple}}-{{target}}

# Build debug binary
dev target triple=(arch() + "-unknown-linux"):
    JEMALLOC_SYS_WITH_MALLOC_CONF=narenas:1,tcache:false,dirty_decay_ms:0,muzzy_decay_ms:0,abort_conf:true \
    cargo build --target {{triple}}-{{target}}

# Build and run debug binary with sudo
run target triple=(arch() + "-unknown-linux"):
    just dev {{target}} {{triple}}
    sudo ./target/debug/dns -c ./dns.toml

# Build and run release binary with sudo
run-rel target triple=(arch() + "-unknown-linux-musl"): (rel target)
    sudo ./target/{{triple}}/release/dns -c ./dns.toml

# Run clippy linter with pedantic/nursery lints
clippy type="stable":
    cargo +{{type}} clippy -- -D clippy::pedantic -D clippy::nursery

# Run full pre-commit checks (clean, check, fmt, clippy, test)
pre: clean
    cargo check
    cargo fmt --check
    just clippy
    just test

# Run unit tests
test:
    cargo test

# Run domain blocking benchmarks
bench-block-domain target triple=(arch() + "-unknown-linux"):
    # cargo bench --features "bloom" -- "blocked domain"
    cargo bench --no-default-features --features "bloom" --target {{triple}}-{{target}} -- "not blocked domain"
    cargo bench --no-default-features --features "fatset" --target {{triple}}-{{target}} -- "not blocked domain"
    cargo bench --no-default-features --features "bloom, fatset" --target {{triple}}-{{target}} -- "not blocked domain"
    # cargo bench --no-default-features --features "slimset" --target {{triple}}-{{target}} -- "blocked domain"
    # JEMALLOC_SYS_WITH_MALLOC_CONF=narenas:1,tcache:false,dirty_decay_ms:0,muzzy_decay_ms:0,abort_conf:true \
    # cargo bench --no-default-features --features "slimset, jemalloc" -- "blocked domain"
    # cargo bench --no-default-features --features "slimset, mimalloc" -- "blocked domain"
    #
    # cargo bench --no-default-features --features "fatset" --target {{triple}}-{{target}} -- "blocked domain"
    # JEMALLOC_SYS_WITH_MALLOC_CONF=narenas:1,tcache:false,dirty_decay_ms:0,muzzy_decay_ms:0,abort_conf:true \
    # cargo bench --no-default-features --features "fatset, jemalloc" -- "blocked domain"
    # cargo bench --no-default-features --features "fatset, mimalloc" -- "blocked domain"

    # cargo bench --features "fatset, bloom" -- "blocked domain"
    #
    # JEMALLOC_SYS_WITH_MALLOC_CONF=narenas:1,tcache:false,dirty_decay_ms:0,muzzy_decay_ms:0,abort_conf:true \
    # cargo bench --features "bloom, jemalloc" -- "blocked domain"
    # JEMALLOC_SYS_WITH_MALLOC_CONF=narenas:1,tcache:false,dirty_decay_ms:0,muzzy_decay_ms:0,abort_conf:true \
    # cargo bench --features "fatset, jemalloc" -- "blocked domain"
    # JEMALLOC_SYS_WITH_MALLOC_CONF=narenas:1,tcache:false,dirty_decay_ms:0,muzzy_decay_ms:0,abort_conf:true \
    # cargo bench --features "fatset, bloom, jemalloc" -- "blocked domain"

    # cargo bench --features "bloom, mimalloc" -- "blocked domain"
    # cargo bench --features "fatset, mimalloc" -- "blocked domain"
    # cargo bench --features "fatset, bloom, mimalloc" -- "blocked domain"

# Run benchmarks
bench:
    JEMALLOC_SYS_WITH_MALLOC_CONF=narenas:1,tcache:false,dirty_decay_ms:0,muzzy_decay_ms:0,abort_conf:true \
    cargo bench

# Clean build artifacts and downloaded blocklists
clean:
    cargo clean
    -rm *.list

# Download/update domain blocklists
lists:
    bash get_lists.sh
