# Thadam

Thadam records what AI coding tools do on a Mac (file access, commands, network
connections, prompts) in a local, append-only, hash-chained store, and will show it in
a local web dashboard.

Status: early development. Current crates:

- `crates/thadam-core`: event model, canonical encoding and hash chain, sensitive-data
  detectors and redaction. No I/O.
- `crates/thadam-store`: append-only SQLite event store and chain verification
  (`thadam-store verify <db>`).

Run the local gate with `scripts/gate.sh`.

Licensed under Apache-2.0. Third-party notices: `THIRD-PARTY-NOTICES.txt`.
