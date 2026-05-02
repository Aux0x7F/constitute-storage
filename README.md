# constitute-storage

`constitute-storage` is the CAAC Storage service MVP for encrypted content-addressed objects, encrypted index shards, key-grant records, pin leases, pruning, local materialized search, and watch events.

Storage is not key custody. It stores ciphertext, manifests, wrapped-key envelopes, pin leases, availability refs, and local materialized indexes. Browser device wallets stay with account/runtime; native service keyrings stay with the services that own them.

## MVP Surface

- SQLite metadata database plus encrypted content-addressed chunk files.
- HTTP/JSON API for object, index shard, key grant, pin, prune, and local-index operations.
- WebSocket watch channel for object availability, priority lanes, and critical acknowledgements.
- CAAC Storage vocabulary from `constitute-protocol`.
- Logging archive target: encrypted log archive objects, encrypted log index shards, safe materialized facts, availability refs, and pin offers.
- Gateway installed-service inventory endpoint: `/hosted-service.json` exposes only safe service/version/capability hints.

## Run

```powershell
cargo run -- --bind 127.0.0.1:7478 --data-dir .\data
```

## Boundary

This service does not decrypt application data, own wallet keys, authorize account identity by itself, observe services directly, formulate logging safe facts, or provide server-side encrypted search in v1. Authorized clients or agents decrypt encrypted index shards and submit safe local materializations for search.
