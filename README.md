# Thadam

Thadam records what AI coding tools do on a Mac (file access, commands, network
connections, prompts) in a local, append-only, hash-chained store, and will show it in
a local web dashboard.

Status: early development. Current crates:

- `crates/thadam-core`: event model, canonical encoding and hash chain, sensitive-data
  detectors and redaction. No I/O.
- `crates/thadam-store`: append-only SQLite event store and chain verification
  (`thadam-store verify <db>`).
- `crates/thadam-collector`: the collector daemon. Reads the OS event stream and the
  network extension's flow records, keeps only AI tools' process trees, and writes rows.
- `macos/`: `ThadamNet.app` and its content filter system extension, which report network
  flows (host, port, bytes; no payloads) to the collector over a local socket. Observe only:
  nothing is blocked. `macos/ThadamNetKit` holds its testable parts (`swift test`).
  To sign a build, put `DEVELOPMENT_TEAM = <team id>` in `macos/Config/Local.xcconfig`.

Run the local gate with `scripts/gate.sh`.

Licensed under Apache-2.0. Third-party notices: `THIRD-PARTY-NOTICES.txt`.
