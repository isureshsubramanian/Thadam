//! Event table schema. Allowed enum values in the CHECK constraints are generated from the
//! core crate's wire names, so the two cannot drift apart.

use rusqlite::Connection;
use thadam_core::{Action, Category, Outcome, WireName};

use crate::StoreError;

pub const SCHEMA_VERSION: i64 = 1;

fn in_list<T: WireName>(all: &[T]) -> String {
    all.iter()
        .map(|v| format!("'{}'", v.wire_name()))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn apply(conn: &Connection) -> Result<(), StoreError> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(StoreError::SchemaVersion(version));
    }
    let sql = format!(
        "BEGIN;
        CREATE TABLE events (
            seq          INTEGER PRIMARY KEY,
            event_id     TEXT    NOT NULL UNIQUE,
            ts_us        INTEGER NOT NULL,
            tool         TEXT    NOT NULL,
            session_id   TEXT,
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
            prev_hash    BLOB    NOT NULL CHECK (length(prev_hash) = 32),
            hash         BLOB    NOT NULL CHECK (length(hash) = 32)
        ) STRICT;
        CREATE INDEX events_ts ON events (ts_us);
        CREATE INDEX events_tool_ts ON events (tool, ts_us);
        CREATE INDEX events_session ON events (session_id, seq);
        CREATE TRIGGER events_no_update BEFORE UPDATE ON events
            BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
        CREATE TRIGGER events_no_delete BEFORE DELETE ON events
            BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
        PRAGMA user_version = {SCHEMA_VERSION};
        COMMIT;",
        categories = in_list(Category::ALL),
        actions = in_list(Action::ALL),
        outcomes = in_list(Outcome::ALL),
    );
    conn.execute_batch(&sql)?;
    Ok(())
}

pub fn check_version(conn: &Connection) -> Result<(), StoreError> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(StoreError::SchemaVersion(version))
    }
}
