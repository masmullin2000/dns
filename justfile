
rel target triple=(arch() + "-unknown-linux"):
    JEMALLOC_SYS_WITH_MALLOC_CONF=narenas:1,tcache:false,dirty_decay_ms:0,muzzy_decay_ms:0,abort_conf:true \
    cargo build -r --target {{triple}}-{{target}}
    
dev:
    cargo build

run: (dev)
    cargo run

run-rel target triple=(arch() + "-unknown-linux-musl"): (rel target)
    sudo ./target/{{triple}}/release/dns

clippy type:
    cargo +{{type}} clippy -- -D clippy::pedantic -D clippy::nursery

clean:
    cargo clean
    rm *.list

lists:
    bash get_lists.sh
