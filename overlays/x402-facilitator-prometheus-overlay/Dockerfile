# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM rust:trixie AS builder

ARG CARGO_FEATURES=full

ENV PORT=8080
ENV CONFIG=/app/config.json
ENV RUST_LOG=info

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*

COPY . ./
RUN cargo build --package x402-facilitator-prometheus-overlay --release --locked --features "${CARGO_FEATURES}"

FROM --platform=$TARGETPLATFORM debian:trixie-slim

ENV PORT=8080
ENV CONFIG=/app/config.json
ENV RUST_LOG=info

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/x402-facilitator-prometheus-overlay /usr/local/bin/x402-facilitator-prometheus-overlay

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/x402-facilitator-prometheus-overlay"]
