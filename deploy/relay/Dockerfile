# Build from the repository root: docker build -f deploy/relay/Dockerfile .
FROM rust:1.99-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY rust/ ./rust/
RUN cargo build --manifest-path rust/Cargo.toml -p kv-server --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 8787 keyvalet-relay-server \
    && useradd --uid 8787 --gid 8787 --no-create-home --shell /usr/sbin/nologin keyvalet-relay-server \
    && mkdir -p /var/lib/keyvalet-relay && chown 8787:8787 /var/lib/keyvalet-relay
COPY --from=build /source/rust/target/release/kv-server /usr/local/bin/kv-server
USER 8787:8787
VOLUME ["/var/lib/keyvalet-relay"]
# Use --network=host on Linux so host nginx reaches this loopback-only listener.
ENTRYPOINT ["/usr/local/bin/kv-server"]
CMD ["--listen", "127.0.0.1:8787", "--data", "/var/lib/keyvalet-relay"]
