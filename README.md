# constitute-storage

`constitute-storage` is the encrypted storage capability for Constitution.

It handles content-addressed objects, encrypted chunks, encrypted indexes, pin
leases, availability, grants, pruning, and storage projections for services that
need durable backing and redundancy.

The current engine is local filesystem blobs plus SQLite metadata. Operator
routes expose backend posture and bounded snapshots for counts, bytes, pins,
leases, attestations, materialized entries, and missing chunk detection without
leaking local filesystem paths.

Logging may reference encrypted event details through storage pin intents, but
Storage remains the fulfillment substrate. It does not own event grammar,
correlation, query semantics, or detection policy.

Product coordination uses the gateway-owned `swarm.edge` WebSocket stream. Pin
intent and attestation records flow through opened/sealed CAAC edge frames;
direct pin, local-index, projection, and watch adapters are operator-only under
`/operator/storage/...`.
