rel target triple=(arch() + "-unknown-linux"):
    echo {{target}} {{triple}}
    JEMALLOC_SYS_WITH_MALLOC_CONF=narenas:1,tcache:false,dirty_decay_ms:0,muzzy_decay_ms:0,abort_conf:true \
    cargo build -r --target {{triple}}-{{target}}

dev target triple=(arch() + "-unknown-linux"):
    JEMALLOC_SYS_WITH_MALLOC_CONF=narenas:1,tcache:false,dirty_decay_ms:0,muzzy_decay_ms:0,abort_conf:true \
    cargo build --target {{triple}}-{{target}}

run target triple=(arch() + "-unknown-linux"):
    just dev {{target}} {{triple}}
    sudo ./target/debug/dns -c ./dns.toml

run-rel target triple=(arch() + "-unknown-linux-musl"): (rel target)
    sudo ./target/{{triple}}/release/dns

clippy type="stable":
    cargo +{{type}} clippy -- -D clippy::pedantic -D clippy::nursery

pre: clean
    cargo check
    cargo fmt --check
    just clippy
    just test

test:
    cargo test

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


bench:
    JEMALLOC_SYS_WITH_MALLOC_CONF=narenas:1,tcache:false,dirty_decay_ms:0,muzzy_decay_ms:0,abort_conf:true \
    cargo bench

clean:
    cargo clean
    -rm *.list

lists:
    bash get_lists.sh
