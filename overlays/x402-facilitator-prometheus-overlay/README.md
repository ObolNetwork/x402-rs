# x402-facilitator-prometheus-overlay

Operator-owned overlay for the stock `x402-facilitator` that follows the composable path described in `docs/build-your-own-facilitator.md`.

This package does not modify `x402-facilitator-local`. Instead it:

- wraps `FacilitatorLocal` in `PrometheusFacilitatorLocal`
- records metrics in `verify` and `settle` pre/post logic
- exposes `GET /metrics` from its own isolated Prometheus registry
- merges that route into the main Axum router with `Router::merge()`

## Run

```bash
cargo run -p x402-facilitator-prometheus-overlay
```

## Docker

Build from the workspace root so the overlay can use local path dependencies:

```bash
docker build -f overlays/x402-facilitator-prometheus-overlay/Dockerfile -t x402-facilitator-prometheus-overlay .
docker run --rm -p 8080:8080 -v $(pwd)/config.json:/app/config.json x402-facilitator-prometheus-overlay
```

To slim the image to selected chains:

```bash
docker build \
  -f overlays/x402-facilitator-prometheus-overlay/Dockerfile \
  --build-arg CARGO_FEATURES=chain-eip155,chain-solana \
  -t x402-facilitator-prometheus-overlay .
```

Once running:

```bash
curl http://localhost:8080/health
curl http://localhost:8080/metrics
```
