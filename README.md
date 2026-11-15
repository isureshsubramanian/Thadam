# Thadam

Thadam is an audit trail for AI coding tools on macOS. It records what those tools do on
your Mac (the files they open, the commands they run, the hosts they connect to, and the
prompts they are given) and shows it in a local web dashboard.

Everything stays on your Mac. The record is append-only and hash-chained, so a changed or
deleted row is detected. Thadam observes only: it never blocks a tool.

Status: early development (0.1.x). Apple silicon Macs only.

## What it records

- **Files**: opens, writes, renames and deletes by an AI tool or anything it started.
  Repeated opens of the same file in one session become one row with a count.
- **Commands**: every program a tool runs, with its command line. Tokens and other secrets
  found in a command line are redacted before they are stored. The environment is never
  stored.
- **Network**: the host, port and bytes sent and received for each connection. Payloads are
  never read.
- **Prompts and sessions**: through the tools' own hooks, where a tool offers them.

Thadam never stores file contents or the sensitive values it detects. Activity from programs
that are not AI tools (most of what happens on a Mac) is dropped in memory and never written.

It flags activity worth a look: a secret in a command or prompt, a sensitive path, reading
or changing files outside the project, a host the tool is not expected to reach, a large
upload, and actions refused by you, the tool or macOS. Flags wait in a review queue in the
dashboard, where you mark them reviewed one at a time or in bulk.

## How it works

```
OS event stream ─┐
network filter ──┼─▶ collector (root) ─▶ store (append-only, hash-chained SQLite)
tool hooks ──────┘                              │
                                                ▼
                         API + dashboard (you, 127.0.0.1 only) ─▶ browser
```

- **Collector** (`crates/thadam-collector`): a launch daemon running as root. Reads the
  macOS Endpoint Security event stream, keeps only the process trees of the AI tools named
  in the registry, matches tools by code-signing identity rather than file name, and writes
  rows to the store.
- **Store** (`crates/thadam-store`, event model and hash chain in `crates/thadam-core`): one
  SQLite file per ISO week (UTC), chained to each other, plus a chained `catalog.db` that
  records each segment's state. `thadam-store verify <store folder>` checks the whole chain
  and names any retired ranges and writing pauses.
- **Network filter** (`macos/`): `ThadamNet.app` and its content-filter system extension
  report each flow (host, port, bytes) to the collector over a local socket.
- **Hooks** (`crates/thadam-hook`): a small program the tools call from their hook
  settings, so prompts and session ids join the record.
- **API and dashboard** (`api/`, `web/`): runs as you, listens on `127.0.0.1:7341` only, and
  needs a password. It reads the store and cannot change it. Each review and search is
  written to an audit log, which only the collector can append to.

The store and the registry live in `/Library/Application Support/Thadam/` and belong to
root, so programs running as you, AI tools included, can read the record but not change or
delete it.

## Install

Download the signed, notarized installer (`Thadam-<version>.pkg`) from this repository's
Releases and open it. Then:

1. **Approve the network filter** when macOS asks (System Settings, General, Login Items &
   Extensions, Network Extensions).
2. **Grant Full Disk Access** to `thadam-collector` (System Settings, Privacy & Security).
   Without it, macOS gives the collector no file events.
3. **Set the dashboard password**:
   `"/Library/Application Support/Thadam/app/thadam-api" set-password`, then run the
   `thadam-api install` command the installer printed.
4. **Name your AI tools** in the registry (below), then open <http://127.0.0.1:7341>.

### The registry

`/Library/Application Support/Thadam/registry.json` (owned by root) names the tools to watch.
Find a tool's team id and signing id with `codesign -dv <path to the tool>`.

```json
{
  "version": 1,
  "tools": [
    { "key": "cli_agent", "display_name": "CLI agent",
      "match": [ { "team_id": "TEAM000001", "signing_id": "com.example.cli-agent" } ],
      "state_dirs": [ "~/.cli-agent/" ],
      "network": { "known_hosts": [ "api.example.com" ] } },
    { "key": "local_tool",
      "match": [ { "path": "/usr/local/bin/local-tool" } ] }
  ],
  "paths": { "not_outside": [ "/opt/toolchains/" ], "sensitive": [ "~/.ssh/" ] },
  "retention": { "max_age_days": 90, "max_store_gb": 20, "min_free_gb": 10 }
}
```

- `match`: a team id with an exact `signing_id` or a `signing_id_prefix`, or a `path` alone
  for unsigned tools.
- `state_dirs`: the tool's own folders. Activity there is marked as the tool's internal
  activity, not flagged.
- `retention`: whole weeks are retired when they pass the age or size limit, or when free
  disk space runs low. The values shown are the defaults. Add `"archive_dir": "/Volumes/…"`
  to move retired weeks there instead of deleting them. Below `min_free_gb`, once only the
  current week is left, the collector stops writing, counts what it skips, and records the
  gap. Every retirement and gap is recorded in the catalog and shown in the dashboard's
  coverage timeline.

## Build from source

Requirements: macOS on Apple silicon, Xcode, the Rust toolchain in `rust-toolchain.toml`,
the .NET SDK in `api/global.json`, and Node.js.

```sh
scripts/gate.sh                  # everything below, as run before every commit
cargo test --workspace           # collector, store, hooks
(cd api && dotnet test)          # API
(cd web && npm ci && npm test)   # dashboard
(cd macos/ThadamNetKit && swift test)
```

To install a local build, sign with your own Developer ID: put the certificate SHA-1s in
`scripts/signing.local` (see `scripts/preflight.sh`), then run `scripts/install-collector.sh`,
`scripts/install-hooks.sh` and `scripts/install-api.sh`. For the network extension, put
`DEVELOPMENT_TEAM = <team id>` in `macos/Config/Local.xcconfig`. `scripts/package.sh`
builds the signed and notarized installer package.

The Endpoint Security event stream needs Full Disk Access for the collector. The network
filter needs the system extension and content-filter entitlements from Apple.

## Privacy and security

- Nothing leaves your Mac. The API listens on the loopback address only.
- Never stored: file contents, the exec environment, payloads, detected secret values.
- The dashboard needs a password. Sessions expire, and every sign-in, review and search is
  in the audit log (ids only, never what was searched for).
- Report a security issue privately through GitHub's "Report a vulnerability" on this
  repository, not in a public issue.

## Licence

Apache License 2.0, see `LICENSE`. Third-party components and their notices are listed in
`THIRD-PARTY-NOTICES.txt`, which also ships inside the package.
