//! Event table schema. Allowed enum values in the CHECK constraints are generated from the
//! core crate's wire names, so the two cannot drift apart.

use rusqlite::Connection;
use thadam_core::{Action, Category, Encoding, Outcome, WireName};

use crate::StoreError;

/// The row encoding of a segment with this schema version (`user_version`). New segments are
/// version 3 since ADR-011 (`agent_session_id`, `transcript`, encoding v3); version 2
/// segments (ADR-004) stay as they are and are still read and verified. Version 1 files are
/// refused, not migrated: the only v1 data was pilot test runs.
pub fn encoding_of(version: i64) -> Result<Encoding, StoreError> {
    match version {
        2 => Ok(Encoding::V2),
        3 => Ok(Encoding::V3),
        v => Err(StoreError::SchemaVersion(v)),
    }
}

fn version_of(encoding: Encoding) -> i64 {
    match encoding {
        Encoding::V2 => 2,
        Encoding::V3 => 3,
    }
}

fn in_list<T: WireName>(all: &[T]) -> String {
    all.iter()
        .map(|v| format!("'{}'", v.wire_name()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Creates the table in a new file with `encoding`'s schema, or returns the encoding of an
/// existing file (which keeps its own version).
pub fn apply(conn: &Connection, encoding: Encoding) -> Result<Encoding, StoreError> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version != 0 {
        return encoding_of(version);
    }
    // A v2 table cannot hold the outcomes added with v3.
    let outcomes: Vec<Outcome> = Outcome::ALL
        .iter()
        .copied()
        .filter(|o| encoding >= Encoding::V3 || *o != Outcome::NeverRan)
        .collect();
    let agent_columns = match encoding {
        Encoding::V2 => "",
        Encoding::V3 => "agent_session_id TEXT,\n            transcript   TEXT,",
    };
    let version = version_of(encoding);
    let sql = format!(
        "BEGIN;
        CREATE TABLE events (
            seq          INTEGER PRIMARY KEY,
            event_id     TEXT    NOT NULL UNIQUE,
            ts_us        INTEGER NOT NULL,
            tool         TEXT    NOT NULL,
            session_id   TEXT,
            parent_session_id TEXT,
            pid          INTEGER NOT NULL,
            process_path TEXT    NOT NULL,
            category     TEXT    NOT NULL CHECK (category IN ({categories})),
            action       TEXT    NOT NULL CHECK (action IN ({actions})),
            target       TEXT    NOT NULL,
            outcome      TEXT    NOT NULL CHECK (outcome IN ({outcomes})),
            size_bytes   INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
            bytes_out    INTEGER CHECK (bytes_out IS NULL OR bytes_out >= 0),
            bytes_in     INTEGER CHECK (bytes_in IS NULL OR bytes_in >= 0),
            project      TEXT,
            flags        TEXT    NOT NULL DEFAULT '',
            count        INTEGER NOT NULL DEFAULT 1 CHECK (count >= 1),
            detections   TEXT    NOT NULL DEFAULT '',
            source       TEXT    NOT NULL,
            {agent_columns}
            prev_hash    BLOB    NOT NULL CHECK (length(prev_hash) = 32),
            hash         BLOB    NOT NULL CHECK (length(hash) = 32)
        ) STRICT;
        CREATE INDEX events_ts ON events (ts_us);
        CREATE INDEX events_tool_ts ON events (tool, ts_us);
        CREATE INDEX events_session ON events (session_id, seq);
        CREATE INDEX events_parent_session ON events (parent_session_id, seq)
            WHERE parent_session_id IS NOT NULL;
        CREATE TRIGGER events_no_update BEFORE UPDATE ON events
            BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
        CREATE TRIGGER events_no_delete BEFORE DELETE ON events
            BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
        PRAGMA user_version = {version};
        COMMIT;",
        categories = in_list(Category::ALL),
        actions = in_list(Action::ALL),
        outcomes = in_list(&outcomes),
    );
    conn.execute_batch(&sql)?;
    Ok(encoding)
}

/// The encoding of an existing file; refuses unknown versions.
pub fn check_version(conn: &Connection) -> Result<Encoding, StoreError> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    encoding_of(version)
}
