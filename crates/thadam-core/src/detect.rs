//! Sensitive-data detection and redaction (ADR-001 decisions 2a, 2b, 8a; ADR-002 Decision 6).
//!
//! Detectors only report byte ranges. The `Redactor` decides what is replaced and counts
//! detections, so a detector can be added without touching redaction or storage.

use std::collections::BTreeMap;
use std::ops::Range;

use crate::detectors::default_detectors;
use crate::error::CoreError;

/// The kind of sensitive value found. Variants are declared in ascending order of their
/// wire names, so a `BTreeMap` keyed by kind iterates in wire order (see `to_wire`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DetectorKind {
    Aadhaar,
    Email,
    Secret,
    UsSsn,
}

impl DetectorKind {
    pub const fn wire_name(self) -> &'static str {
        match self {
            DetectorKind::Aadhaar => "AADHAAR",
            DetectorKind::Email => "EMAIL",
            DetectorKind::Secret => "SECRET",
            DetectorKind::UsSsn => "US_SSN",
        }
    }
}

/// Finds sensitive values in text. Implementations return the byte ranges to replace; a
/// range must lie on UTF-8 character boundaries and may cover only part of a match (for
/// example the token after `Bearer `).
pub trait Detector: Send + Sync {
    fn kind(&self) -> DetectorKind;
    fn find(&self, text: &str) -> Vec<Range<usize>>;
}

/// Count of detections per kind. Only types and counts are ever stored, never values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Detections(BTreeMap<DetectorKind, u32>);

impl Detections {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, kind: DetectorKind, n: u32) {
        if n > 0 {
            let entry = self.0.entry(kind).or_insert(0);
            *entry = entry.saturating_add(n);
        }
    }

    pub fn get(&self, kind: DetectorKind) -> u32 {
        self.0.get(&kind).copied().unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn merge(&mut self, other: &Detections) {
        for (kind, n) in &other.0 {
            self.add(*kind, *n);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (DetectorKind, u32)> + '_ {
        self.0.iter().map(|(k, n)| (*k, *n))
    }

    /// Canonical stored form: `TYPE:n` sorted by type, joined by `,`; empty if none.
    pub fn to_wire(&self) -> String {
        self.iter()
            .map(|(k, n)| format!("{}:{n}", k.wire_name()))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Text after redaction, with what was removed counted by kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redacted {
    pub text: String,
    pub detections: Detections,
}

/// Runs every detector over a text and replaces each finding with `[TYPE]`.
pub struct Redactor {
    detectors: Vec<Box<dyn Detector>>,
}

impl Redactor {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self { detectors }
    }

    /// The standard set: email, secrets, US SSN, Aadhaar.
    pub fn with_default_detectors() -> Result<Self, CoreError> {
        Ok(Self::new(default_detectors()?))
    }

    /// Counts findings without producing redacted text (for file contents scanned in
    /// memory and then discarded, ADR-001 decision 2b).
    pub fn scan(&self, text: &str) -> Detections {
        self.redact(text).detections
    }

    /// Replaces every finding with `[TYPE]`. Overlapping findings are merged into one
    /// replacement, labelled with the kind of the finding that starts first (the longer
    /// one on a tie), so no part of any finding survives.
    pub fn redact(&self, text: &str) -> Redacted {
        let mut hits: Vec<(Range<usize>, DetectorKind)> = Vec::new();
        for detector in &self.detectors {
            let kind = detector.kind();
            for range in detector.find(text) {
                if range.start < range.end
                    && text.is_char_boundary(range.start)
                    && text.is_char_boundary(range.end)
                {
                    hits.push((range, kind));
                }
            }
        }
        hits.sort_by(|a, b| a.0.start.cmp(&b.0.start).then(b.0.end.cmp(&a.0.end)));

        let mut spans: Vec<(Range<usize>, DetectorKind)> = Vec::new();
        for (range, kind) in hits {
            match spans.last_mut() {
                Some((last, _)) if range.start < last.end => last.end = last.end.max(range.end),
                _ => spans.push((range, kind)),
            }
        }

        let mut out = String::with_capacity(text.len());
        let mut detections = Detections::new();
        let mut pos = 0;
        for (range, kind) in spans {
            out.push_str(text.get(pos..range.start).unwrap_or_default());
            out.push('[');
            out.push_str(kind.wire_name());
            out.push(']');
            detections.add(kind, 1);
            pos = range.end;
        }
        out.push_str(text.get(pos..).unwrap_or_default());
        Redacted {
            text: out,
            detections,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test detector returning fixed `(start, end)` byte ranges.
    struct Fixed(DetectorKind, Vec<(usize, usize)>);
    impl Detector for Fixed {
        fn kind(&self) -> DetectorKind {
            self.0
        }
        fn find(&self, _text: &str) -> Vec<Range<usize>> {
            self.1.iter().map(|&(s, e)| s..e).collect()
        }
    }

    #[test]
    fn replaces_findings_and_counts_by_kind() {
        let r = Redactor::new(vec![
            Box::new(Fixed(DetectorKind::Secret, vec![(4, 8)])),
            Box::new(Fixed(DetectorKind::Email, vec![(12, 16)])),
        ]);
        let out = r.redact("key=abcd to wxyz now");
        assert_eq!(out.text, "key=[SECRET] to [EMAIL] now");
        assert_eq!(out.detections.to_wire(), "EMAIL:1,SECRET:1");
    }

    #[test]
    fn overlapping_findings_merge_so_nothing_leaks() {
        let r = Redactor::new(vec![
            Box::new(Fixed(DetectorKind::Secret, vec![(2, 6)])),
            Box::new(Fixed(DetectorKind::Email, vec![(4, 10)])),
        ]);
        let out = r.redact("x=abcdefgh!");
        assert_eq!(out.text, "x=[SECRET]!");
        assert_eq!(out.detections.to_wire(), "SECRET:1");
    }

    #[test]
    fn ignores_ranges_that_are_empty_or_split_a_character() {
        let r = Redactor::new(vec![Box::new(Fixed(
            DetectorKind::Secret,
            vec![(3, 3), (1, 2)],
        ))]);
        let out = r.redact("é ok");
        assert_eq!(out.text, "é ok");
        assert!(out.detections.is_empty());
    }

    #[test]
    fn wire_form_is_sorted_and_empty_when_none() {
        let mut d = Detections::new();
        assert_eq!(d.to_wire(), "");
        d.add(DetectorKind::UsSsn, 1);
        d.add(DetectorKind::Aadhaar, 2);
        d.add(DetectorKind::Email, 0);
        assert_eq!(d.to_wire(), "AADHAAR:2,US_SSN:1");
    }
}
