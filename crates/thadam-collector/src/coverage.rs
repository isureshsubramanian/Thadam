//! Windows the collector did not watch (ADR-013 Decision 1).
//!
//! A heartbeat file in the store folder says when the collector was last known to be
//! running, and whether it stopped cleanly. It is only a hint for the next start, so it is not
//! chained; the gaps worked out from it are written to the chained catalog. A crash is placed
//! to within `BEAT_EVERY` of the truth.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use thadam_store::{Gap, GapReason};

/// The heartbeat file, in the store folder. Not `*.db`, so no store reader picks it up.
pub const HEARTBEAT_FILE: &str = "collector.heartbeat";
/// How often the heartbeat is rewritten (estimate, ADR-013 Decision 1). The writer thread
/// beats on its retention tick, which has the same period.
pub const BEAT_EVERY: Duration = Duration::from_secs(60);

/// What the heartbeat file says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Beat {
    pub at_us: i64,
    /// True when written by a clean stop.
    pub stopped: bool,
}

impl Beat {
    fn line(self) -> String {
        let state = if self.stopped { "stopped" } else { "running" };
        format!("{state} {}\n", self.at_us)
    }

    fn parse(text: &str) -> Option<Self> {
        let (state, at) = text.trim().split_once(' ')?;
        let stopped = match state {
            "running" => false,
            "stopped" => true,
            _ => return None,
        };
        Some(Self {
            at_us: at.parse().ok()?,
            stopped,
        })
    }
}

/// The heartbeat file of one store folder.
#[derive(Debug, Clone)]
pub struct Heartbeat {
    path: PathBuf,
}

impl Heartbeat {
    pub fn in_store(store: &Path) -> Self {
        Self {
            path: store.join(HEARTBEAT_FILE),
        }
    }

    /// The last beat, or `None` when there is no readable one (a first start, or a damaged
    /// file: no gap is claimed without evidence).
    pub fn read(&self) -> Option<Beat> {
        Beat::parse(&std::fs::read_to_string(&self.path).ok()?)
    }

    /// Replaces the file whole, so a reader never sees half a line.
    pub fn write(&self, beat: Beat) -> io::Result<()> {
        let tmp = self.path.with_extension("heartbeat.tmp");
        std::fs::write(&tmp, beat.line())?;
        std::fs::rename(&tmp, &self.path)
    }
}

/// The gaps to record at start, from the last beat and the OS's boot time.
///
/// - Booted after the last beat: `machine_off` from the beat to boot, then `before_start`
///   from boot to now.
/// - Otherwise: `not_running` from the beat to now, `stopped` or `crashed`.
///
/// No beat (first start) gives no gap. Empty windows are left out.
pub fn start_gaps(last: Option<Beat>, boot_us: Option<i64>, now_us: i64) -> Vec<Gap> {
    let Some(last) = last else {
        return Vec::new();
    };
    let window = |from_us: i64, to_us: i64, reason, detail| Gap {
        from_us,
        to_us,
        reason,
        detail,
        missed: None,
    };
    let mut gaps = match boot_us {
        Some(boot) if boot > last.at_us && boot <= now_us => vec![
            window(last.at_us, boot, GapReason::MachineOff, None),
            window(boot, now_us, GapReason::BeforeStart, None),
        ],
        _ => {
            let detail = if last.stopped { "stopped" } else { "crashed" };
            vec![window(
                last.at_us,
                now_us,
                GapReason::NotRunning,
                Some(detail.to_string()),
            )]
        }
    };
    gaps.retain(|g| g.to_us > g.from_us);
    gaps
}

/// When the OS last booted, from `kern.boottime`; `None` if it cannot be read.
pub fn boot_time_us() -> Option<i64> {
    let out = Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.boottime"])
        .output()
        .ok()?;
    parse_boot_time(std::str::from_utf8(&out.stdout).ok()?)
}

/// Parses `{ sec = 1794674732, usec = 994354 } Sat Nov 14 22:15:32 2026`.
fn parse_boot_time(text: &str) -> Option<i64> {
    let field = |name: &str| -> Option<i64> {
        let rest = text.split_once(&format!("{name} = "))?.1;
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    };
    field("sec")?
        .checked_mul(1_000_000)?
        .checked_add(field("usec")?)
}

/// A `dropped` gap for the minute that just passed, when a source lost events in it.
pub fn dropped(from_us: i64, to_us: i64, source: &'static str, missed: u64) -> Option<Gap> {
    (missed > 0).then_some(Gap {
        from_us,
        to_us,
        reason: GapReason::Dropped,
        detail: Some(source.to_string()),
        missed: Some(missed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: i64 = 60_000_000;

    fn beat(at_us: i64, stopped: bool) -> Option<Beat> {
        Some(Beat { at_us, stopped })
    }

    #[test]
    fn a_clean_stop_then_start_is_one_stopped_gap() {
        let gaps = start_gaps(beat(10 * MIN, true), Some(MIN), 25 * MIN);
        assert_eq!(gaps.len(), 1);
        assert_eq!(
            (
                gaps[0].from_us,
                gaps[0].to_us,
                gaps[0].reason,
                gaps[0].detail.as_deref()
            ),
            (10 * MIN, 25 * MIN, GapReason::NotRunning, Some("stopped"))
        );
    }

    #[test]
    fn a_running_beat_means_it_crashed() {
        let gaps = start_gaps(beat(10 * MIN, false), None, 12 * MIN);
        assert_eq!(gaps[0].detail.as_deref(), Some("crashed"));
        assert_eq!(gaps[0].reason, GapReason::NotRunning);
    }

    #[test]
    fn a_boot_after_the_last_beat_is_mac_off_then_before_start() {
        let gaps = start_gaps(beat(10 * MIN, false), Some(70 * MIN), 71 * MIN);
        let got: Vec<_> = gaps
            .iter()
            .map(|g| (g.reason, g.from_us, g.to_us))
            .collect();
        assert_eq!(
            got,
            [
                (GapReason::MachineOff, 10 * MIN, 70 * MIN),
                (GapReason::BeforeStart, 70 * MIN, 71 * MIN),
            ]
        );
    }

    #[test]
    fn no_beat_no_gap_and_empty_windows_are_dropped() {
        assert!(start_gaps(None, Some(MIN), 2 * MIN).is_empty());
        assert!(start_gaps(beat(5 * MIN, true), None, 5 * MIN).is_empty());
        // A boot time in the future (clock change) is not trusted.
        let gaps = start_gaps(beat(5 * MIN, true), Some(9 * MIN), 6 * MIN);
        assert_eq!(gaps[0].reason, GapReason::NotRunning);
    }

    #[test]
    fn the_heartbeat_round_trips_and_ignores_damage() {
        let dir = std::env::temp_dir().join(format!("thadam-beat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hb = Heartbeat::in_store(&dir);
        assert_eq!(hb.read(), None);
        hb.write(Beat {
            at_us: 42,
            stopped: false,
        })
        .unwrap();
        assert_eq!(hb.read(), beat(42, false));
        hb.write(Beat {
            at_us: 43,
            stopped: true,
        })
        .unwrap();
        assert_eq!(hb.read(), beat(43, true));
        std::fs::write(dir.join(HEARTBEAT_FILE), "garbage").unwrap();
        assert_eq!(hb.read(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn boot_time_parses_the_sysctl_line() {
        assert_eq!(
            parse_boot_time("{ sec = 1794674732, usec = 994354 } Sat Nov 14 22:15:32 2026\n"),
            Some(1_794_674_732_994_354)
        );
        assert_eq!(parse_boot_time("nonsense"), None);
        assert!(boot_time_us().is_some_and(|b| b > 0));
    }

    #[test]
    fn dropped_only_when_something_was_lost() {
        assert!(dropped(0, MIN, "os", 0).is_none());
        let g = dropped(0, MIN, "network", 7).unwrap();
        assert_eq!(
            (g.reason, g.detail.as_deref(), g.missed),
            (GapReason::Dropped, Some("network"), Some(7))
        );
    }
}
