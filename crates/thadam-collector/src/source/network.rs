//! The network source (ADR-007 Decisions 1 and 2): flow records from the content filter
//! extension, over a local Unix socket.
//!
//! CONTRACT: `thadam.flow.v1`, one JSON object per line. This is the only coupling with the
//! extension. Records are checked for shape (serde, unknown fields rejected) and meaning
//! (garde and the checks below) here, at the input boundary. A rejected record is counted,
//! never echoed: it may hold a host name of any app on the machine.

use std::fs::{self, DirBuilder};
use std::io::{self, BufRead, BufReader};
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use garde::Validate;
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

/// Where the collector listens. Its folder is root-only (ADR-007 Decision 1).
pub const DEFAULT_SOCKET: &str = "/var/run/thadam/flow.sock";
/// Longest accepted line. An estimate: a record with a 253-byte host and 16 ancestors is
/// under 1 KB.
pub const MAX_LINE: usize = 8 * 1024;
/// Longest host name (RFC 1035, as text).
pub const MAX_HOST: usize = 253;
/// Most ancestors in a record (ADR-007 Decision 2).
pub const MAX_PPIDS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub const fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Out,
    In,
}

/// Where the host name came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostFrom {
    Sni,
    Http,
    Api,
    None,
}

/// A flow started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowOpen {
    pub pid: u32,
    pub pidversion: u32,
    /// Ancestors at flow start, nearest first.
    pub ppids: Vec<u32>,
    pub proto: Proto,
    pub direction: Direction,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    /// Lower case, no trailing dot. `None` when `host_from` is `None`.
    pub host: Option<String>,
    pub host_from: HostFrom,
}

/// What happened to a flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowEvent {
    Open(FlowOpen),
    /// Running byte totals for the flow; `closed` on the last report.
    Bytes {
        closed: bool,
        bytes_out: Option<u64>,
        bytes_in: Option<u64>,
    },
}

/// Why a line produced no flow event. Carries no content from the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RejectReason {
    /// Not JSON, an unknown field, or a field of the wrong type.
    Malformed,
    /// Well formed, but a value out of range or a field missing for its kind.
    Invalid,
    /// Longer than `MAX_LINE`.
    TooLong,
}

impl RejectReason {
    pub const fn name(self) -> &'static str {
        match self {
            RejectReason::Malformed => "malformed",
            RejectReason::Invalid => "invalid",
            RejectReason::TooLong => "too_long",
        }
    }
}

/// What the network source yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowItem {
    Flow {
        flow: Uuid,
        ts: OffsetDateTime,
        event: FlowEvent,
    },
    /// The extension dropped `missed` records while the collector was away.
    Gap {
        missed: u64,
    },
    Rejected(RejectReason),
    /// An extension connected or disconnected.
    Connected,
    Disconnected,
}

// ---- Wire format (input boundary: serde for shape, garde and `into_item` for meaning) ----

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum WireKind {
    Open,
    Stats,
    Close,
    Gap,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum WireProto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum WireDirection {
    Out,
    In,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum WireHostFrom {
    Sni,
    Http,
    Api,
    None,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct Wire {
    #[garde(range(min = 1, max = 1))]
    v: u32,
    #[garde(skip)]
    kind: WireKind,
    /// A hyphenated UUID.
    #[garde(inner(length(min = 36, max = 36)))]
    flow: Option<String>,
    /// RFC 3339 with nanoseconds is at most 35 bytes; 64 bounds an offset form.
    #[garde(length(min = 1, max = 64))]
    ts: String,
    #[garde(skip)]
    pid: Option<u32>,
    #[garde(skip)]
    pidversion: Option<u32>,
    #[garde(inner(length(max = MAX_PPIDS)))]
    ppids: Option<Vec<u32>>,
    #[garde(skip)]
    proto: Option<WireProto>,
    #[garde(skip)]
    direction: Option<WireDirection>,
    /// The longest IPv6 text form is 45 bytes.
    #[garde(inner(length(min = 2, max = 45)))]
    remote_ip: Option<String>,
    #[garde(inner(range(min = 1)))]
    remote_port: Option<u16>,
    #[garde(inner(length(min = 1, max = MAX_HOST), custom(host_name)))]
    host: Option<String>,
    #[garde(skip)]
    host_from: Option<WireHostFrom>,
    #[garde(skip)]
    bytes_out: Option<u64>,
    #[garde(skip)]
    bytes_in: Option<u64>,
    #[garde(skip)]
    missed: Option<u64>,
}

fn host_name(value: &str, _ctx: &()) -> garde::Result {
    if is_host_name(value) {
        Ok(())
    } else {
        Err(garde::Error::new("not a host name"))
    }
}

/// True for a DNS name: dot-separated labels of 1 to 63 ASCII letters, digits, `-` or `_`,
/// optionally ending in a dot.
pub fn is_host_name(value: &str) -> bool {
    let name = value.strip_suffix('.').unwrap_or(value);
    !name.is_empty()
        && name.len() <= MAX_HOST
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Parses one line. Never returns content from the line.
pub fn parse_line(line: &str) -> FlowItem {
    let wire: Wire = match serde_json::from_str(line) {
        Ok(w) => w,
        Err(_) => return FlowItem::Rejected(RejectReason::Malformed),
    };
    if wire.validate().is_err() {
        return FlowItem::Rejected(RejectReason::Invalid);
    }
    wire.into_item()
        .unwrap_or(FlowItem::Rejected(RejectReason::Invalid))
}

impl Wire {
    /// Checks the fields each kind needs, and that it has none it doesn't.
    fn into_item(self) -> Option<FlowItem> {
        let ts = OffsetDateTime::parse(&self.ts, &Rfc3339).ok()?;
        let open_fields = self.pid.is_some()
            || self.pidversion.is_some()
            || self.ppids.is_some()
            || self.proto.is_some()
            || self.direction.is_some()
            || self.remote_ip.is_some()
            || self.remote_port.is_some()
            || self.host.is_some()
            || self.host_from.is_some();
        let byte_fields = self.bytes_out.is_some() || self.bytes_in.is_some();
        if let WireKind::Gap = self.kind {
            if open_fields || byte_fields || self.flow.is_some() {
                return None;
            }
            return Some(FlowItem::Gap {
                missed: self.missed?,
            });
        }
        if self.missed.is_some() {
            return None;
        }
        let flow = Uuid::parse_str(self.flow.as_deref()?).ok()?;
        let event = match self.kind {
            WireKind::Open => {
                if byte_fields {
                    return None;
                }
                let host_from = match self.host_from? {
                    WireHostFrom::Sni => HostFrom::Sni,
                    WireHostFrom::Http => HostFrom::Http,
                    WireHostFrom::Api => HostFrom::Api,
                    WireHostFrom::None => HostFrom::None,
                };
                // A name and its origin come together, or neither does.
                if (host_from == HostFrom::None) != self.host.is_none() {
                    return None;
                }
                let host = self.host.map(|h| {
                    let h = h.strip_suffix('.').unwrap_or(&h);
                    h.to_ascii_lowercase()
                });
                FlowEvent::Open(FlowOpen {
                    pid: self.pid?,
                    pidversion: self.pidversion?,
                    ppids: self.ppids?,
                    proto: match self.proto? {
                        WireProto::Tcp => Proto::Tcp,
                        WireProto::Udp => Proto::Udp,
                    },
                    direction: match self.direction? {
                        WireDirection::Out => Direction::Out,
                        WireDirection::In => Direction::In,
                    },
                    remote_ip: self.remote_ip?.parse().ok()?,
                    remote_port: self.remote_port?,
                    host,
                    host_from,
                })
            }
            WireKind::Stats | WireKind::Close => {
                if open_fields {
                    return None;
                }
                FlowEvent::Bytes {
                    closed: matches!(self.kind, WireKind::Close),
                    bytes_out: self.bytes_out,
                    bytes_in: self.bytes_in,
                }
            }
            WireKind::Gap => return None,
        };
        Some(FlowItem::Flow { flow, ts, event })
    }
}

// ---- Socket ----

/// A listening socket, removed again when dropped.
#[derive(Debug)]
pub struct FlowListener {
    listener: UnixListener,
    path: PathBuf,
}

impl FlowListener {
    /// Creates the socket's folder (mode 0700) if needed, replaces a stale socket, and
    /// listens. Refuses a folder others can open, and anything at `path` that is not a
    /// socket.
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "flow socket needs a folder")
            })?;
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        if fs::metadata(dir)?.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "flow socket folder must be private (mode 0700)",
            ));
        }
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_socket() => fs::remove_file(&path)?,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "flow socket path exists and is not a socket",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(Self { listener, path })
    }

    /// Accepts connections until `send` returns false, reading each on its own thread.
    /// `send` must be cheap to clone into those threads.
    pub fn serve<F>(self, send: F)
    where
        F: Fn(FlowItem) -> bool + Clone + Send + 'static,
    {
        for stream in self.listener.incoming() {
            let Ok(stream) = stream else { continue };
            let send = send.clone();
            if !send(FlowItem::Connected) {
                return;
            }
            std::thread::spawn(move || {
                read_connection(stream, &send);
                send(FlowItem::Disconnected);
            });
        }
    }
}

impl Drop for FlowListener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn read_connection(stream: UnixStream, send: &impl Fn(FlowItem) -> bool) {
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    loop {
        let item = match read_line_limited(&mut reader, &mut buf, MAX_LINE) {
            Ok(Line::End) | Err(_) => return,
            Ok(Line::TooLong) => FlowItem::Rejected(RejectReason::TooLong),
            Ok(Line::Done) => match std::str::from_utf8(&buf) {
                Ok(text) if text.trim().is_empty() => continue,
                Ok(text) => parse_line(text),
                Err(_) => FlowItem::Rejected(RejectReason::Malformed),
            },
        };
        if !send(item) {
            return;
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Line {
    /// A line is in the buffer, without its newline.
    Done,
    /// A line over the limit was read and thrown away.
    TooLong,
    End,
}

/// Reads one line into `buf`, keeping at most `max` bytes in memory however long it is.
fn read_line_limited(reader: &mut impl BufRead, buf: &mut Vec<u8>, max: usize) -> io::Result<Line> {
    buf.clear();
    let mut too_long = false;
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            return Ok(match (too_long, buf.is_empty()) {
                (true, _) => Line::TooLong,
                (false, true) => Line::End,
                // A last line without a newline still counts.
                (false, false) => Line::Done,
            });
        }
        let (part, found) = match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => (&chunk[..i], Some(i + 1)),
            None => (chunk, None),
        };
        if !too_long {
            if buf.len() + part.len() > max {
                too_long = true;
                buf.clear();
            } else {
                buf.extend_from_slice(part);
            }
        }
        let used = found.unwrap_or(chunk.len());
        reader.consume(used);
        if found.is_some() {
            return Ok(if too_long { Line::TooLong } else { Line::Done });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOW: &str = "0192f3a4-0000-7000-8000-000000000001";

    fn open(extra: &str) -> String {
        format!(
            r#"{{"v":1,"kind":"open","flow":"{FLOW}","ts":"2026-11-14T09:33:00.5Z","pid":4211,"pidversion":3,"ppids":[4100,1],"proto":"tcp","direction":"out","remote_ip":"203.0.113.7","remote_port":443{extra}}}"#
        )
    }

    #[test]
    fn valid_records_parse() {
        let item = parse_line(&open(r#","host":"API.Example.TEST.","host_from":"api""#));
        let FlowItem::Flow {
            event: FlowEvent::Open(o),
            ..
        } = item
        else {
            panic!("not an open: {item:?}");
        };
        assert_eq!(o.host.as_deref(), Some("api.example.test"));
        assert_eq!(o.ppids, vec![4100, 1]);
        assert_eq!(o.remote_ip, "203.0.113.7".parse::<IpAddr>().unwrap());

        let item = parse_line(&open(r#","host_from":"none""#));
        assert!(matches!(item, FlowItem::Flow { .. }), "{item:?}");

        let stats = format!(
            r#"{{"v":1,"kind":"stats","flow":"{FLOW}","ts":"2026-11-14T09:33:10Z","bytes_out":10,"bytes_in":2000}}"#
        );
        assert!(matches!(
            parse_line(&stats),
            FlowItem::Flow {
                event: FlowEvent::Bytes {
                    closed: false,
                    bytes_out: Some(10),
                    bytes_in: Some(2000)
                },
                ..
            }
        ));
        let close =
            format!(r#"{{"v":1,"kind":"close","flow":"{FLOW}","ts":"2026-11-14T09:33:10Z"}}"#);
        assert!(matches!(
            parse_line(&close),
            FlowItem::Flow {
                event: FlowEvent::Bytes { closed: true, .. },
                ..
            }
        ));
        let gap = r#"{"v":1,"kind":"gap","ts":"2026-11-14T09:33:10Z","missed":42}"#;
        assert_eq!(parse_line(gap), FlowItem::Gap { missed: 42 });
    }

    #[test]
    fn bad_records_are_rejected_without_values() {
        let long_host = format!(r#","host":"{}.test","host_from":"sni""#, "a".repeat(250));
        let cases = [
            (
                open(r#","host_from":"none","secret":"x""#),
                RejectReason::Malformed,
            ),
            (
                open(r#","host_from":"none""#).replace("203.0.113.7", "999.1.1.1"),
                RejectReason::Invalid,
            ),
            (
                open(r#","host_from":"none""#).replace(":443", ":70000"),
                RejectReason::Malformed,
            ),
            (
                open(r#","host_from":"none""#).replace(":443", ":0"),
                RejectReason::Invalid,
            ),
            (open(&long_host), RejectReason::Invalid),
            (
                open(r#","host":"bad host/path","host_from":"http""#),
                RejectReason::Invalid,
            ),
            (
                open(r#","host":"a.test","host_from":"none""#),
                RejectReason::Invalid,
            ),
            (open(r#","host_from":"sni""#), RejectReason::Invalid),
            (
                open(r#","host_from":"none""#).replace(r#""open""#, r#""opened""#),
                RejectReason::Malformed,
            ),
            (
                open(r#","host_from":"none""#).replace(r#""v":1"#, r#""v":2"#),
                RejectReason::Invalid,
            ),
            (
                open(r#","host_from":"none","bytes_out":5"#),
                RejectReason::Invalid,
            ),
            (
                open(r#","host_from":"none""#).replace(FLOW, "not-a-uuid-not-a-uuid-not-a-uuid-xx"),
                RejectReason::Invalid,
            ),
            (
                open(r#","host_from":"none""#).replace("2026-11-14T09:33:00.5Z", "yesterday"),
                RejectReason::Invalid,
            ),
            ("not json".to_string(), RejectReason::Malformed),
            (
                r#"{"v":1,"kind":"gap","ts":"2026-11-14T09:33:10Z"}"#.to_string(),
                RejectReason::Invalid,
            ),
        ];
        for (line, want) in cases {
            assert_eq!(parse_line(&line), FlowItem::Rejected(want), "{line}");
        }
        let many = (0..17).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        let line = open(r#","host_from":"none""#).replace("[4100,1]", &format!("[{many}]"));
        assert_eq!(parse_line(&line), FlowItem::Rejected(RejectReason::Invalid));
    }

    #[test]
    fn host_names() {
        assert!(is_host_name("api.example.test"));
        assert!(is_host_name("_dmarc.example.test."));
        assert!(!is_host_name(""));
        assert!(!is_host_name("a..test"));
        assert!(!is_host_name("a b.test"));
        assert!(!is_host_name(&format!("{}.test", "a".repeat(64))));
    }

    #[test]
    fn long_lines_are_dropped_and_reading_continues() {
        let input = format!("{}\nshort\nlast", "x".repeat(100));
        let mut reader = BufReader::with_capacity(16, input.as_bytes());
        let mut buf = Vec::new();
        assert_eq!(
            read_line_limited(&mut reader, &mut buf, 20).unwrap(),
            Line::TooLong
        );
        assert_eq!(
            read_line_limited(&mut reader, &mut buf, 20).unwrap(),
            Line::Done
        );
        assert_eq!(buf, b"short");
        assert_eq!(
            read_line_limited(&mut reader, &mut buf, 20).unwrap(),
            Line::Done
        );
        assert_eq!(buf, b"last");
        assert_eq!(
            read_line_limited(&mut reader, &mut buf, 20).unwrap(),
            Line::End
        );
    }

    #[test]
    fn socket_round_trip() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("thadam-flow-sock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("sub").join("flow.sock");
        let listener = FlowListener::bind(&path).unwrap();
        let mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || listener.serve(move |item| tx.send(item).is_ok()));
        let mut client = UnixStream::connect(&path).unwrap();
        writeln!(client, "{}", open(r#","host_from":"none""#)).unwrap();
        writeln!(client, "garbage").unwrap();
        drop(client);
        let items: Vec<FlowItem> = rx.iter().take(4).collect();
        assert_eq!(items[0], FlowItem::Connected);
        assert!(matches!(items[1], FlowItem::Flow { .. }));
        assert_eq!(items[2], FlowItem::Rejected(RejectReason::Malformed));
        assert_eq!(items[3], FlowItem::Disconnected);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bind_refuses_to_replace_a_plain_file() {
        let dir = std::env::temp_dir().join(format!("thadam-flow-file-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("flow.sock");
        fs::write(&path, b"keep").unwrap();
        assert!(FlowListener::bind(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"keep");
        let _ = fs::remove_dir_all(&dir);
    }
}
