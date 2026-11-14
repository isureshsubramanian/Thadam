# Thadam

Thadam records what AI coding tools do on a Mac (file access, commands, network
connections, prompts) in a local, append-only, hash-chained store, and will show it in
a local web dashboard.

Status: early development. Current crates:

- `crates/thadam-core`: event model, canonical encoding and hash chain, sensitive-data
  detectors and redaction. No I/O.
- `crates/thadam-store`: append-only SQLite event store and chain verification. The store
  is a folder: one segment file per ISO week (UTC), chained through each other, plus a
  chained `catalog.db` recording each segment's state. Old weeks are retired whole when
  they pass the age or size limit, or when free disk space is low; every retirement is
  recorded in the catalog. `thadam-store verify <db | store folder>` checks the chain and
  names retired ranges and writing pauses.
- Storage limits: the registry's optional `retention` block, e.g.
  `{ "max_age_days": 90, "max_store_gb": 20, "min_free_gb": 10, "archive_dir": "/Volumes/…" }`
  (those are the defaults, without `archive_dir`). With `archive_dir` set, retired segments
  are moved there instead of deleted. Below `min_free_gb`, once only the current week is
  left, the collector stops writing, counts what it skips, and records the gap.
- The collector's store and registry belong in `/Library/Application Support/Thadam/`
  (owned by root), so programs running as the user can read the record but not delete or
  change it. `sudo scripts/migrate-store.sh` moves an older single-file store there.
- `crates/thadam-collector`: the collector daemon. Reads the OS event stream and the
  network extension's flow records, keeps only AI tools' process trees, and writes rows
  (`thadam-collector run --registry <file> --store <folder>`).
- `macos/`: `ThadamNet.app` and its content filter system extension, which report network
  flows (host, port, bytes; no payloads) to the collector over a local socket. Observe only:
  nothing is blocked. `macos/ThadamNetKit` holds its testable parts (`swift test`).
  To sign a build, put `DEVELOPMENT_TEAM = <team id>` in `macos/Config/Local.xcconfig`.

Run the local gate with `scripts/gate.sh`.

Licensed under Apache-2.0. Third-party notices: `THIRD-PARTY-NOTICES.txt`.
