# constitute-storage Architecture

`constitute-storage` is the local storage substrate for CAAC Storage capabilities. It provides durable encrypted object storage and local searchable projections without taking custody of plaintext or long-lived keys.

## Owned Here

- Encrypted content-addressed chunk persistence.
- Object manifests and chunk validation.
- Encrypted index shard persistence.
- Wrapped key-grant records.
- Pin leases, owner unpin, expiry prune, and last-access prune.
- Local materialized indexes populated by authorized decrypting agents.
- Watch events for sync/progress/availability acknowledgements.
- Safe hosted-service manifest and health projection for gateway installed-service inventory.

## Not Owned Here

- Browser device wallets.
- Native service keyrings.
- Account identity authority.
- Gateway grant policy.
- Logging product semantics.
- Notification/detection workflows.
- DHT hot-query behavior.

## Gateway Projection

Storage is a gateway-hosted capability service, not an app launcher.
It exposes safe service facts so `constitute-gateway` can publish it in the gateway hosted-services inventory:
- service slug: `storage`
- label and version
- health endpoint hint
- API endpoint hint
- capability labels for objects, encrypted indexes, key grants, pinning, pruning, local search, and watch events

The projection must not include wallet keys, grants, ciphertext payloads, decrypted metadata, access timing, or account/device secrets.

## Delete Semantics

- Logical delete: object/index metadata is tombstoned and hidden from normal reads.
- Crypto delete: a principal removes wallet/keyring material; storage cannot perform this because it does not own keys.
- Physical delete: local pins are removed and unpinned ciphertext can be pruned.

## Index Model

Encrypted index shards are synchronized as opaque ciphertext. Authorized clients or local service agents decrypt shards and submit safe materialized records for local search. V1 intentionally avoids blind server-side encrypted search.
