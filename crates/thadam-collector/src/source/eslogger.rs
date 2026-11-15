//! Typed JSON-line adapter for the built-in macOS event logger.

use std::io::BufRead;

use serde::{Deserialize, de::IgnoredAny};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    EventKind, EventSource, Identity, OsEvent, ProcessRef, SkipReason, SourceError, SourceItem,
};

/// Reads one JSON event per line without retaining exec environments.
pub struct EsloggerSource<R: BufRead> {
    reader: R,
    buffer: Vec<u8>,
    previous: Option<u64>,
    pending: Option<SourceItem>,
}

impl<R: BufRead> EsloggerSource<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Vec::with_capacity(2048),
            previous: None,
            pending: None,
        }
    }

    /// Tracks the sequence number of every line that has one, skipped lines included, so
    /// a skipped line is never counted as a dropped event.
    fn track(&mut self, seq: Option<u64>, item: SourceItem) -> SourceItem {
        let Some(seq) = seq else {
            return item;
        };
        let previous = self.previous.replace(seq);
        match previous {
            Some(previous) if seq > previous && seq - previous > 1 => {
                self.pending = Some(item);
                SourceItem::Gap {
                    missed: seq - previous - 1,
                }
            }
            _ => item,
        }
    }
}

impl<R: BufRead> EventSource for EsloggerSource<R> {
    fn next(&mut self) -> Result<Option<SourceItem>, SourceError> {
        if let Some(item) = self.pending.take() {
            return Ok(Some(item));
        }
        loop {
            self.buffer.clear();
            if self
                .reader
                .read_until(b'\n', &mut self.buffer)
                .map_err(SourceError)?
                == 0
            {
                return Ok(None);
            }
            let line = match std::str::from_utf8(&self.buffer) {
                Ok(line) => line.trim(),
                Err(_) => return Ok(Some(SourceItem::Skipped(SkipReason::Malformed))),
            };
            if line.is_empty() {
                continue;
            }
            let (seq, item) = match parse(line) {
                Ok(event) => (Some(event.seq), SourceItem::Event(event)),
                Err(skip) => (skip.seq, SourceItem::Skipped(skip.reason)),
            };
            return Ok(Some(self.track(seq, item)));
        }
    }
}

/// A line that produced no event, with its sequence number when it had a readable one.
#[derive(Debug)]
struct Skip {
    reason: SkipReason,
    seq: Option<u64>,
}

#[derive(Deserialize)]
struct Shape {
    event: EventKeys,
    #[serde(default)]
    global_seq_num: Option<SeqField>,
}

/// Accepts any value, so a bad sequence number is reported as a missing field by the
/// full parse, not as a malformed line here.
#[derive(Deserialize)]
#[serde(untagged)]
enum SeqField {
    Number(u64),
    Other(IgnoredAny),
}

impl SeqField {
    fn value(&self) -> Option<u64> {
        match self {
            SeqField::Number(n) => Some(*n),
            SeqField::Other(_) => None,
        }
    }
}

struct EventKeys(Vec<String>);

impl<'de> Deserialize<'de> for EventKeys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeysVisitor;
        impl<'de> serde::de::Visitor<'de> for KeysVisitor {
            type Value = EventKeys;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an event object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut keys = Vec::with_capacity(1);
                while let Some(key) = map.next_key::<String>()? {
                    keys.push(key);
                    map.next_value::<IgnoredAny>()?;
                }
                Ok(EventKeys(keys))
            }
        }
        deserializer.deserialize_map(KeysVisitor)
    }
}

#[derive(Deserialize)]
struct Line {
    time: String,
    global_seq_num: u64,
    process: Process,
    event: Body,
}

#[derive(Deserialize)]
struct Token {
    pid: u32,
    pidversion: u32,
}

#[derive(Deserialize)]
struct ResponsibleToken {
    pid: u32,
}

#[derive(Deserialize)]
struct Process {
    audit_token: Token,
    ppid: u32,
    responsible_audit_token: Option<ResponsibleToken>,
    executable: File,
    team_id: Option<String>,
    signing_id: Option<String>,
    #[serde(default)]
    is_platform_binary: bool,
}

impl Process {
    fn into_ref(self) -> ProcessRef {
        ProcessRef {
            pid: self.audit_token.pid,
            pidversion: self.audit_token.pidversion,
            ppid: self.ppid,
            responsible_pid: self
                .responsible_audit_token
                .map(|token| token.pid)
                .filter(|pid| *pid != self.audit_token.pid),
            executable: self.executable.path,
            identity: Identity {
                team_id: self.team_id.filter(|id| !id.is_empty()),
                signing_id: self.signing_id.filter(|id| !id.is_empty()),
                platform: self.is_platform_binary,
            },
        }
    }
}

#[derive(Deserialize)]
struct File {
    path: String,
    stat: Option<Stat>,
}

impl File {
    fn size(&self) -> Option<i64> {
        self.stat
            .as_ref()
            .map(|stat| stat.st_size)
            .filter(|size| *size >= 0)
    }
}

#[derive(Deserialize)]
struct Stat {
    st_size: i64,
}

#[derive(Deserialize)]
struct Destination {
    existing_file: Option<File>,
    new_path: Option<NewPath>,
}

#[derive(Deserialize)]
struct NewPath {
    dir: File,
    filename: String,
}

impl Destination {
    fn path(self) -> Result<String, SkipReason> {
        match (self.existing_file, self.new_path) {
            (Some(file), None) => Ok(file.path),
            (None, Some(new)) => Ok(format!(
                "{}/{}",
                new.dir.path.trim_end_matches('/'),
                new.filename.trim_start_matches('/')
            )),
            _ => Err(SkipReason::MissingField),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Body {
    Exec {
        target: Process,
        #[serde(default)]
        args: Vec<String>,
        cwd: Option<File>,
    },
    Fork {
        child: Process,
    },
    Exit {
        stat: i64,
    },
    Open {
        fflag: u32,
        file: File,
    },
    Close {
        modified: bool,
        target: File,
    },
    Create {
        destination: Destination,
    },
    Rename {
        source: File,
        destination: Destination,
    },
    Unlink {
        target: File,
    },
}

/// Why a line that did not parse as a handled event was skipped. The envelope is checked and
/// all event keys counted, including unhandled ones, without allocating ignored values.
fn why_skipped(line: &str) -> Skip {
    let Ok(shape) = serde_json::from_str::<Shape>(line) else {
        return Skip {
            reason: SkipReason::Malformed,
            seq: None,
        };
    };
    let seq = shape.global_seq_num.as_ref().and_then(SeqField::value);
    let reason = match shape.event.0.as_slice() {
        [kind]
            if !matches!(
                kind.as_str(),
                "exec" | "fork" | "exit" | "open" | "close" | "create" | "rename" | "unlink"
            ) =>
        {
            SkipReason::UnknownEvent
        }
        [_] => SkipReason::MissingField,
        _ => SkipReason::Malformed,
    };
    Skip { reason, seq }
}

fn parse(line: &str) -> Result<OsEvent, Skip> {
    if !line.starts_with('{') {
        return Err(Skip {
            reason: SkipReason::Malformed,
            seq: None,
        });
    }
    // Nearly every line is a handled event and parses in this one pass; only a line that
    // fails is read again, to find its sequence number and why it was skipped.
    let line: Line = serde_json::from_str(line).map_err(|_| why_skipped(line))?;
    let skip = |reason| Skip {
        reason,
        seq: Some(line.global_seq_num),
    };
    let ts =
        OffsetDateTime::parse(&line.time, &Rfc3339).map_err(|_| skip(SkipReason::MissingField))?;
    let kind = match line.event {
        Body::Exec { target, args, cwd } => EventKind::Exec {
            target: target.into_ref(),
            args,
            cwd: cwd.map(|file| file.path),
        },
        Body::Fork { child } => EventKind::Fork {
            child: child.into_ref(),
        },
        Body::Exit { stat } => {
            let _ = stat;
            EventKind::Exit
        }
        Body::Open { fflag, file } => {
            let size = file.size();
            EventKind::Open {
                path: file.path,
                readable: fflag & 1 != 0,
                writable: fflag & 2 != 0,
                size,
            }
        }
        Body::Close { modified, target } => {
            let size = target.size();
            EventKind::Close {
                path: target.path,
                modified,
                size,
            }
        }
        Body::Create { destination } => EventKind::Create {
            path: destination.path().map_err(skip)?,
        },
        Body::Rename {
            source,
            destination,
        } => EventKind::Rename {
            from: source.path,
            to: destination.path().map_err(skip)?,
        },
        Body::Unlink { target } => EventKind::Unlink { path: target.path },
    };
    Ok(OsEvent {
        ts,
        seq: line.global_seq_num,
        process: line.process.into_ref(),
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::io::{self, BufReader, Read};

    fn process() -> Value {
        json!({"audit_token":{"pid":42,"pidversion":3},"ppid":40,
            "responsible_audit_token":{"pid":40},"executable":{"path":"/Users/test/tool"},
            "team_id":"TEAM000001","signing_id":"com.example.cli-agent"})
    }
    fn line(body: Value, seq: u64) -> Value {
        json!({"time":"2026-11-14T09:33:00.123456789Z","global_seq_num":seq,
            "process":process(),"event":body})
    }
    fn file() -> Value {
        json!({"path":"/Users/test/x","stat":{"st_size":1234}})
    }
    fn event(body: Value) -> OsEvent {
        parse(&line(body, 1).to_string()).unwrap()
    }
    fn existing() -> Value {
        json!({"existing_file":file()})
    }
    fn new_path(dir: &str) -> Value {
        json!({"new_path":{"dir":{"path":dir},"filename":"x"}})
    }

    #[test]
    fn exec() {
        let parsed = event(json!({"exec":{"target":process(),"args":["tool","status"],
            "cwd":{"path":"/Users/test"},"env":["API_KEY=SYNTHETIC-ENV-MARKER"]}}));
        assert!(!format!("{parsed:?}").contains("SYNTHETIC-ENV-MARKER"));
        assert_eq!(
            parsed.kind,
            EventKind::Exec {
                target: parsed.process.clone(),
                args: vec!["tool".into(), "status".into()],
                cwd: Some("/Users/test".into())
            }
        );
        assert!(
            matches!(event(json!({"exec":{"target":process()}})).kind, EventKind::Exec { args, cwd: None, .. } if args.is_empty())
        );
    }
    #[test]
    fn fork() {
        let parsed = event(json!({"fork":{"child":process()}}));
        assert_eq!(
            parsed.kind,
            EventKind::Fork {
                child: parsed.process
            }
        );
    }
    #[test]
    fn exit() {
        assert_eq!(event(json!({"exit":{"stat":0}})).kind, EventKind::Exit);
    }
    #[test]
    fn open() {
        assert_eq!(
            event(json!({"open":{"fflag":1,"file":file()}})).kind,
            EventKind::Open {
                path: "/Users/test/x".into(),
                readable: true,
                writable: false,
                size: Some(1234)
            }
        );
    }
    #[test]
    fn close() {
        assert_eq!(
            event(json!({"close":{"modified":true,"target":file()}})).kind,
            EventKind::Close {
                path: "/Users/test/x".into(),
                modified: true,
                size: Some(1234)
            }
        );
    }
    #[test]
    fn create() {
        assert_eq!(
            event(json!({"create":{"destination":existing()}})).kind,
            EventKind::Create {
                path: "/Users/test/x".into()
            }
        );
        for (dir, path) in [
            ("/", "/x"),
            ("/Users/test", "/Users/test/x"),
            ("/Users/test/", "/Users/test/x"),
        ] {
            assert_eq!(
                event(json!({"create":{"destination":new_path(dir)}})).kind,
                EventKind::Create { path: path.into() }
            );
        }
    }
    #[test]
    fn rename() {
        for destination in [existing(), new_path("/Users/test/")] {
            assert_eq!(
                event(json!({"rename":{"source":file(),"destination":destination}})).kind,
                EventKind::Rename {
                    from: "/Users/test/x".into(),
                    to: "/Users/test/x".into()
                }
            );
        }
    }
    #[test]
    fn unlink() {
        assert_eq!(
            event(json!({"unlink":{"target":file()}})).kind,
            EventKind::Unlink {
                path: "/Users/test/x".into()
            }
        );
    }
    #[test]
    fn gaps_and_lines() {
        let input = [100, 103, 2, 3]
            .map(|seq| line(json!({"exit":{"stat":0}}), seq).to_string())
            .join("\r\n");
        let text = format!("\n \r\n{input}\r\n");
        let mut source = EsloggerSource::new(text.as_bytes());
        for expected in [Some(100), None, Some(103), Some(2), Some(3)] {
            match (expected, source.next().unwrap().unwrap()) {
                (Some(seq), SourceItem::Event(event)) => assert_eq!(event.seq, seq),
                (None, SourceItem::Gap { missed: 2 }) => (),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(source.next().unwrap(), None);
    }
    #[test]
    fn skipped_lines_still_advance_the_sequence() {
        let unknown = line(json!({"mmap":{}}), 101).to_string();
        let broken = line(json!({"exit":{}}), 102).to_string();
        let input = [
            line(json!({"exit":{"stat":0}}), 100).to_string(),
            unknown,
            broken,
            line(json!({"exit":{"stat":0}}), 103).to_string(),
        ]
        .join("\n");
        let mut source = EsloggerSource::new(input.as_bytes());
        let mut items = Vec::new();
        while let Some(item) = source.next().unwrap() {
            items.push(item);
        }
        assert!(
            !items.iter().any(|i| matches!(i, SourceItem::Gap { .. })),
            "{items:?}"
        );
        assert_eq!(items.len(), 4);
    }

    #[test]
    fn junk_and_edges() {
        use SkipReason::{Malformed as M, MissingField as F, UnknownEvent as U};
        let mut cases: Vec<(Vec<u8>, SkipReason)> = [
            "{}",
            "[]",
            "4",
            "null",
            "{",
            "{\"event\":null}",
            "{\"event\":[]}",
            "{\"event\":{}}",
            "{\"event\":{\"open\":{},\"exit\":{}}}",
        ]
        .into_iter()
        .map(|s| (s.as_bytes().to_vec(), M))
        .collect();
        cases.push((vec![0xff, b'\n'], M));
        cases.push((b"{\"event\":{\"signal\":{}}}".to_vec(), U));
        let base = line(json!({"open":{"fflag":1,"file":file()}}), 1);
        for (pointer, value) in [
            ("/process/audit_token/pid", json!(null)),
            ("/process/audit_token/pid", json!(-1)),
            ("/process/audit_token/pid", json!(4294967296u64)),
            ("/process/audit_token/pidversion", json!(-1)),
            ("/process/ppid", json!(4294967296u64)),
            ("/time", json!("bad")),
            ("/time", json!(0)),
            ("/global_seq_num", json!(-1)),
            ("/event/open/fflag", json!("read")),
            ("/event/open/file/path", json!(false)),
            ("/process/executable", json!(null)),
            ("/event/open/file/stat/st_size", json!("large")),
        ] {
            let mut input = base.clone();
            *input.pointer_mut(pointer).unwrap() = value;
            cases.push((input.to_string().into_bytes(), F));
        }
        let mut missing = base.clone();
        missing["process"]["audit_token"]
            .as_object_mut()
            .unwrap()
            .remove("pid");
        cases.push((missing.to_string().into_bytes(), F));
        for body in [
            json!({"exec":{}}),
            json!({"fork":{}}),
            json!({"exit":{}}),
            json!({"close":{"modified":0,"target":file()}}),
            json!({"create":{"destination":{}}}),
            json!({"rename":{}}),
            json!({"unlink":{}}),
        ] {
            cases.push((line(body, 1).to_string().into_bytes(), F));
        }
        assert!(cases.len() >= 20);
        for (input, reason) in cases {
            let mut source = EsloggerSource::new(input.as_slice());
            assert_eq!(source.next().unwrap(), Some(SourceItem::Skipped(reason)));
            assert_eq!(source.next().unwrap(), None);
        }
    }
    #[test]
    fn optional_metadata() {
        let mut input = line(
            json!({"open":{"fflag":0,"file":{"path":"/Users/test/x","stat":{"st_size":-1}}}}),
            1,
        );
        input["process"]["team_id"] = json!("");
        input["process"]["signing_id"] = Value::Null;
        input["process"]["responsible_audit_token"]["pid"] = json!(42);
        let parsed = parse(&input.to_string()).unwrap();
        assert_eq!(parsed.process.identity, Identity::default());
        assert_eq!(parsed.process.responsible_pid, None);
        assert!(matches!(
            parsed.kind,
            EventKind::Open {
                readable: false,
                writable: false,
                size: None,
                ..
            }
        ));
    }
    #[test]
    fn read_error() {
        struct Fails;
        impl Read for Fails {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("synthetic failure"))
            }
        }
        let mut source = EsloggerSource::new(BufReader::new(Fails));
        assert!(source.next().is_err());
    }
    #[test]
    #[ignore]
    fn throughput_500k_lines() {
        let target = process();
        let mut process = process();
        for index in 0..30 {
            process[format!("ignored_{index}")] = json!("");
        }
        let bodies = [
            json!({"open":{"fflag":1,"file":file()}}),
            json!({"close":{"modified":false,"target":file()}}),
            json!({"exec":{"target":target.clone(),"env":(0..40).map(|i|format!("KEY_{i}=x")).collect::<Vec<_>>()}}),
            json!({"fork":{"child":target}}),
        ];
        let templates = bodies.map(|body| {
            let mut value = line(body, 1);
            value["process"] = process.clone();
            let padding = "x".repeat(1900usize.saturating_sub(value.to_string().len()) / 30);
            for index in 0..30 {
                value["process"][format!("ignored_{index}")] = json!(padding);
            }
            let template = value.to_string() + "\n";
            assert!((1500..=2000).contains(&template.len()));
            template
        });
        // Lines are generated as they are read, so the 500,000 lines (about 1 GB) are
        // never held in memory at once.
        struct Lines {
            templates: [Vec<u8>; 4],
            line: usize,
            offset: usize,
        }
        impl Read for Lines {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.line == 500_000 {
                    return Ok(0);
                }
                let template = &self.templates[self.line % 4];
                let n = buf.len().min(template.len() - self.offset);
                buf[..n].copy_from_slice(&template[self.offset..self.offset + n]);
                self.offset += n;
                if self.offset == template.len() {
                    self.offset = 0;
                    self.line += 1;
                }
                Ok(n)
            }
        }
        let mut source = EsloggerSource::new(BufReader::new(Lines {
            templates: templates.map(String::into_bytes),
            line: 0,
            offset: 0,
        }));
        let start = std::time::Instant::now();
        let mut count = 0;
        while let Some(item) = source.next().unwrap() {
            assert!(matches!(item, SourceItem::Event(_)));
            count += 1;
        }
        assert_eq!(count, 500_000);
        let rate = f64::from(count) / start.elapsed().as_secs_f64();
        eprintln!("{rate:.0} lines/s");
        #[cfg(not(debug_assertions))]
        assert!(rate >= 20_000.0);
    }
}
