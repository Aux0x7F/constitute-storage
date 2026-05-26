# constitute-storage

`constitute-storage` is the encrypted storage capability for Constitution.

It handles content-addressed objects, encrypted chunks, encrypted indexes, pin
leases, availability, grants, pruning, and storage projections for services that
need durable backing and redundancy.

The current engine is local filesystem blobs plus SQLite metadata. Operator
routes expose backend posture and bounded snapshots for counts, bytes, pins,
leases, attestations, queryable graph edges, materialized entries, and missing
chunk detection without leaking local filesystem paths.

The engine can also emit a host-fabric storage-journal/cache member
contribution from backend posture and snapshot evidence. Fabric reduces that
composition signal; Storage still owns byte retrieval, pin/cache fulfillment,
and encrypted storage records.

The filesystem-facing surface is a virtual materialization view over storage
refs. It exposes safe relative paths for future mount/FUSE adapters and does
not expose machine-local blob paths.

Canonical storage records use content-addressed `storage:object:<hash>` and
`storage:chunk:<hash>` refs plus the resolved storage-member public key that can
serve them. Service labels, package names, source/module refs, and filesystem
paths are resolver inputs or projected indexes; they are not storage truth.

Source systems may store source object packs through a storage-owned adapter
that writes the encrypted object, journals a source-snapshot-to-object graph
edge, and derives pin availability posture. Storage proves bytes and
availability; source graph, branch, release, and project semantics stay with
the source/project contracts.

Module materialization follows the same rule. Build/source tooling may receive
a projected filesystem layout for Cargo or other toolchains, but storage proof
continues to point at resolved object refs, chunk refs, pin attestations, and
availability posture rather than local paths.

Logging may reference encrypted event details through storage pin intents, but
Storage remains the fulfillment substrate. It does not own event grammar,
correlation, query semantics, or detection policy.

Product coordination uses the gateway-owned `swarm.edge` WebSocket stream. Pin
intent and attestation records flow through opened/sealed CAAC edge frames;
direct pin, local-index, projection, and watch adapters are operator-only under
`/operator/storage/...`.

## Commands

```powershell
cargo test
cargo run -- --bind 127.0.0.1:7478 --data-dir data
```

Operator views:

```powershell
curl.exe http://127.0.0.1:7478/operator/storage/v1/backend-posture
curl.exe http://127.0.0.1:7478/operator/storage/v1/snapshot
curl.exe http://127.0.0.1:7478/operator/storage/v1/filesystem-view
curl.exe http://127.0.0.1:7478/operator/storage/v1/graph-edges
curl.exe http://127.0.0.1:7478/operator/storage/v1/source-objects
```
