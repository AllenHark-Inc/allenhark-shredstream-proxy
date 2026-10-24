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
if you use a separate one) at the AllenHark gateway instead of Jito's, keep
using your existing auth keypair, and register that keypair's pubkey in the
AllenHark console/dashboard so it gets whitelisted. Everything else —
`--dest-ip-ports`, `--src-bind-port`, etc. — works exactly as before.

The AllenHark gateway serves **Frankfurt only**. `--desired-regions` is
accepted for CLI compatibility but is not used for routing.

## Setup

1. **Auth keypair**: Use your existing Solana keypair (or generate a new one
   with `solana-keygen new --outfile shredstream-keypair.json`). This
   keypair is only used to authenticate with the gateway — it does not need
   to hold funds.
2. **Whitelist your keypair**: Register the keypair's pubkey in the
   AllenHark console/dashboard to get it whitelisted for ShredStream access.
   One pubkey per subscription, one subscription per account.
3. **Point at the gateway**: `https://fra.jito.allenhark.network`
   (Frankfurt).

## Access

Jito Shreds is **$50/month**, with a **24-hour trial** available per account.
Manage the subscription and the whitelisted pubkey in the AllenHark console.

## Running

### Prebuilt binary

Each [release](https://github.com/AllenHark-Inc/allenhark-shredstream-proxy/releases)
has a Linux x86-64 binary built for generic x86-64 CPUs (no AVX2 needed) and
glibc 2.29 or newer (Ubuntu 20.04+, Debian 11+), with its SHA-256 checksum.

```bash
curl -LO https://github.com/AllenHark-Inc/allenhark-shredstream-proxy/releases/latest/download/jito-shredstream-proxy-x86_64-unknown-linux-gnu
curl -LO https://github.com/AllenHark-Inc/allenhark-shredstream-proxy/releases/latest/download/jito-shredstream-proxy-x86_64-unknown-linux-gnu.sha256
sha256sum -c jito-shredstream-proxy-x86_64-unknown-linux-gnu.sha256
chmod +x jito-shredstream-proxy-x86_64-unknown-linux-gnu
RUST_LOG=info ./jito-shredstream-proxy-x86_64-unknown-linux-gnu shredstream \
  --block-engine-url https://fra.jito.allenhark.network \
  --auth-keypair shredstream-keypair.json \
  --dest-ip-ports 127.0.0.1:8001
```

### With Cargo

```bash
RUST_LOG=info cargo run --release --bin jito-shredstream-proxy -- shredstream \
  --block-engine-url https://fra.jito.allenhark.network \
  --auth-keypair shredstream-keypair.json \
  --dest-ip-ports 127.0.0.1:8001,10.0.0.1:8001
```

- `--block-engine-url`: the AllenHark gateway URL,
  `https://fra.jito.allenhark.network`.
- `--auth-keypair`: path to your (whitelisted) auth keypair file.
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
  --block-engine-url https://fra.jito.allenhark.network \
  --auth-keypair /app/shredstream-keypair.json \
  --dest-ip-ports 127.0.0.1:8001
```

## Maintenance

This fork is maintained by AllenHark as a trusted, byte-faithful drop-in for
the upstream Jito ShredStream proxy client, with the only differences being
the AllenHark gateway defaults and removal of Jito's end-of-life kill
switch. See https://docs.jito.wtf/lowlatencytxnfeed/ for background on how
ShredStream works.
