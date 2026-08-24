# AllenHark ShredStream Proxy

This is the AllenHark-maintained ShredStream proxy — a drop-in replacement for
Jito's ShredStream proxy, which shut down on September 5, 2026. It is a
minimal fork of the upstream `jito-labs/shredstream-proxy` client: same
binary, same CLI, same wire protocol, pointed at the AllenHark gateway
instead of Jito's block engine.

ShredStream provides the lowest latency path to shreds from leaders on
Solana, forwarding them to your local consumers (e.g. a validator or
downstream service).

## Migrating from Jito

No code changes are required. Point `--block-engine-url` (and `--auth-url`
if you use a separate one) at your AllenHark region gateway instead of
Jito's, keep using your existing auth keypair, and register that keypair's
pubkey in the AllenHark console/dashboard so it gets whitelisted. Everything
else — `--desired-regions`, `--dest-ip-ports`, `--src-bind-port`, etc. —
works exactly as before.

## Setup

1. **Auth keypair**: Use your existing Solana keypair (or generate a new one
   with `solana-keygen new --outfile shredstream-keypair.json`). This
   keypair is only used to authenticate with the gateway — it does not need
   to hold funds.
2. **Whitelist your keypair**: Register the keypair's pubkey in the
   AllenHark console/dashboard to get it whitelisted for ShredStream access.
3. **Point at your region gateway**: Use the AllenHark gateway URL for the
   region you want, e.g. `https://<region>.shreds.allenhark.network`.

## Running

### With Cargo

```bash
RUST_LOG=info cargo run --release --bin jito-shredstream-proxy -- shredstream \
  --block-engine-url https://<region>.shreds.allenhark.network \
  --auth-keypair shredstream-keypair.json \
  --desired-regions <region1>,<region2> \
  --dest-ip-ports 127.0.0.1:8001,10.0.0.1:8001
```

- `--block-engine-url`: your AllenHark gateway URL for the desired region.
- `--auth-keypair`: path to your (whitelisted) auth keypair file.
- `--desired-regions`: comma-separated list of regions to receive shreds
  from (max 2).
- `--dest-ip-ports`: comma-separated `IP:PORT` destinations to forward
  decoded shreds to (e.g. your validator's TVU port, found via
  `scripts/get_tvu_port.sh`).

Run `cargo run --release --bin jito-shredstream-proxy -- shredstream --help`
for the full list of flags (multicast, dynamic endpoint discovery, gRPC
entry service, etc.).

### With Docker

```bash
docker build -t allenhark-shredstream-proxy .
docker run -d --network host \
  -e RUST_LOG=info \
  -v $(pwd)/shredstream-keypair.json:/app/shredstream-keypair.json \
  allenhark-shredstream-proxy \
  shredstream \
  --block-engine-url https://<region>.shreds.allenhark.network \
  --auth-keypair /app/shredstream-keypair.json \
  --desired-regions <region1>,<region2> \
  --dest-ip-ports 127.0.0.1:8001
```

## Maintenance

This fork is maintained by AllenHark as a trusted, byte-faithful drop-in for
the upstream Jito ShredStream proxy client, with the only differences being
the AllenHark gateway defaults and removal of Jito's end-of-life kill
switch. See https://docs.jito.wtf/lowlatencytxnfeed/ for background on how
ShredStream works.
