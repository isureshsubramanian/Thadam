//! Built-in detectors for sensitive values, reporting UTF-8 byte ranges.

use std::ops::Range;

use regex::Regex;

use crate::detect::{Detector, DetectorKind};
use crate::error::CoreError;

struct PatternDetector {
    kind: DetectorKind,
    pattern: Regex,
}

impl Detector for PatternDetector {
    fn kind(&self) -> DetectorKind {
        self.kind
    }

    fn find(&self, text: &str) -> Vec<Range<usize>> {
        self.pattern
            .find_iter(text)
            .filter(|m| match self.kind {
                DetectorKind::UsSsn => {
                    let s = m.as_str();
                    match (s.get(..3), s.get(4..6), s.get(7..)) {
                        (Some(area), Some(group), Some(serial)) => {
                            area != "000"
                                && area != "666"
                                && area < "900"
                                && group != "00"
                                && serial != "0000"
                        }
                        _ => false,
                    }
                }
                DetectorKind::Aadhaar => {
                    let digits: Vec<_> = m.as_str().bytes().filter(u8::is_ascii_digit).collect();
                    verhoeff_valid(&digits)
                }
                _ => true,
            })
            .map(|m| m.range())
            .collect()
    }
}

struct SecretDetector {
    values: Vec<Regex>,
    headers: Regex,
    endings: Regex,
}

impl SecretDetector {
    fn new() -> Result<Self, CoreError> {
        let patterns = [
            r"(?i)\bBearer[ \t]+([A-Za-z0-9._~+/=-]{8,})",
            r"(?i)\bAuthorization:[ \t]*Basic[ \t]+([A-Za-z0-9+/=]{8,})",
            // Key names, also inside longer variable names such as `SERVICE_API_KEY` or
            // `DB_PASSWORD_PRIMARY` (words joined by `_` or `-`).
            r#"(?i)\b(?:[A-Za-z0-9]+[_-])*(?:api_key|api-key|apikey|access_key|secret|client_secret|token|access_token|password|passwd|pwd)(?:[_-][A-Za-z0-9]+)*\b\s*[:=]\s*(?:"([^"\s]{4,})"|'([^'\s]{4,})'|([^\s"']{4,}))"#,
            // Environment variables whose name ends in a key word with no separator, such as
            // `PGPASSWORD`. Upper case only, as environment names are, so that ordinary words
            // such as `notpassword` stay text.
            r#"\b[A-Z][A-Z0-9]*(?:PASSWORD|PASSWD|TOKEN|SECRET|APIKEY)(?:_[A-Z0-9]+)*\s*=\s*(?:"([^"\s]{4,})"|'([^'\s]{4,})'|([^\s"']{4,}))"#,
            // Flags ending in a key word, such as `--password`, `--auth-token` or `--api-key`.
            // A spaced value starting with `-` is the next flag (`--no-password --verbose`).
            r#"(?i)(?:^|\s)--(?:[A-Za-z0-9]+-)*(?:password|passwd|token|secret|api-key|apikey|access-key)(?:=(?:"([^"\s]+)"|'([^'\s]+)'|([^\s"']+))|[ \t]+(?:"([^"\s]+)"|'([^'\s]+)'|([^\s"'-][^\s"']*)))"#,
            // Database clients take the password glued to `-p`; `-P` is the port.
            r#"(?:^|[\s/])(?:mysql|mysqldump|mysqladmin|mariadb)\b[^|;&\n]*?[ \t]-p([^\s"'-][^\s"']*)"#,
            r#"(?:^|[\s/])sshpass\b[^|;&\n]*?[ \t]-p[ \t]*([^\s"'-][^\s"']*)"#,
            // `-u user:password` and `--user user:password`: the part after the colon.
            r#"(?:^|\s)(?:-u|--user)(?:[ \t]+|=)(?:"[^"\s:]*:([^"\s]+)"|'[^'\s:]*:([^'\s]+)'|[^\s"':]*:([^\s"']+))"#,
            r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:([^\s/@]+)@",
            // Well-known provider token prefixes.
            r"\b(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}\b|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}\b|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{36}\b|hf_[A-Za-z0-9]{30,})",
            // A signed token (header.payload.signature) with or without `Bearer`.
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
        ];
        Ok(Self {
            values: patterns
                .iter()
                .map(|p| Regex::new(p))
                .collect::<Result<_, _>>()?,
            headers: Regex::new(r"-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----")?,
            endings: Regex::new(r"(?m)^-----END ((?:[A-Z0-9]+ )*PRIVATE KEY)-----\r?$")?,
        })
    }
}

impl Detector for SecretDetector {
    fn kind(&self) -> DetectorKind {
        DetectorKind::Secret
    }

    fn find(&self, text: &str) -> Vec<Range<usize>> {
        let mut ranges = Vec::new();
        for pattern in &self.values {
            for captures in pattern.captures_iter(text) {
                if let Some(value) = captures.iter().skip(1).flatten().next() {
                    ranges.push(value.range());
                }
            }
        }
        for header in self.headers.captures_iter(text) {
            if let (Some(whole), Some(label)) = (header.get(0), header.get(1)) {
                let end = self
                    .endings
                    .captures_iter(&text[whole.end()..])
                    .find_map(|c| match (c.get(0), c.get(1)) {
                        (Some(line), Some(end_label)) if end_label.as_str() == label.as_str() => {
                            Some(whole.end() + line.end())
                        }
                        _ => None,
                    });
                // Without a matching END line, redact to the end of the text so no key material leaks.
                ranges.push(whole.start()..end.unwrap_or(text.len()));
            }
        }
        ranges.sort_by_key(|r| (r.start, r.end));
        ranges.dedup();
        ranges
    }
}

const D: [[usize; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const P: [[usize; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

fn verhoeff_valid(digits: &[u8]) -> bool {
    let mut state = 0;
    for (i, digit) in digits.iter().rev().enumerate() {
        if !digit.is_ascii_digit() {
            return false;
        }
        state = D[state][P[i % 8][usize::from(digit - b'0')]];
    }
    state == 0
}

/// The standard detector set, with patterns compiled once per construction.
pub fn default_detectors() -> Result<Vec<Box<dyn Detector>>, CoreError> {
    Ok(vec![
        Box::new(PatternDetector {
            kind: DetectorKind::Email,
            pattern: Regex::new(
                r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)*\.[A-Z]{2,}\b",
            )?,
        }),
        Box::new(SecretDetector::new()?),
        Box::new(PatternDetector {
            kind: DetectorKind::UsSsn,
            pattern: Regex::new(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")?,
        }),
        Box::new(PatternDetector {
            kind: DetectorKind::Aadhaar,
            pattern: Regex::new(
                r"\b(?:[2-9][0-9]{11}|[2-9][0-9]{3} [0-9]{4} [0-9]{4}|[2-9][0-9]{3}-[0-9]{4}-[0-9]{4})\b",
            )?,
        }),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::Redactor;

    fn values(kind: DetectorKind, text: &str) -> Vec<&str> {
        default_detectors()
            .unwrap()
            .iter()
            .find(|d| d.kind() == kind)
            .unwrap()
            .find(text)
            .into_iter()
            .map(|r| &text[r])
            .collect()
    }

    #[test]
    fn email_addresses() {
        assert_eq!(
            values(DetectorKind::Email, "é Mira.Test+tag@EXAMPLE.test!"),
            ["Mira.Test+tag@EXAMPLE.test"]
        );
        for text in [
            "name@",
            "@example.test",
            "name@example",
            "name at example.test",
        ] {
            assert!(values(DetectorKind::Email, text).is_empty());
        }
    }

    #[test]
    fn bearer_values_and_redaction() {
        for text in [
            "Bearer abc123def456ghi",
            "Authorization: Bearer abc123def456ghi",
        ] {
            assert_eq!(values(DetectorKind::Secret, text), ["abc123def456ghi"]);
        }
        assert!(values(DetectorKind::Secret, "Bearer short").is_empty());
        let input =
            "curl -H \"Authorization: Bearer abc123def456ghi\" https://api.example.test/v1/items";
        let out = Redactor::with_default_detectors().unwrap().redact(input);
        assert_eq!(
            out.text,
            "curl -H \"Authorization: Bearer [SECRET]\" https://api.example.test/v1/items"
        );
        assert_eq!(out.detections.to_wire(), "SECRET:1");
    }

    #[test]
    fn assignments() {
        for key in [
            "api_key",
            "api-key",
            "apikey",
            "access_key",
            "secret",
            "client_secret",
            "token",
            "access_token",
            "password",
            "passwd",
            "pwd",
        ] {
            for suffix in ["=abcd1234", ": abcd1234", "='abcd1234'", "=\"abcd1234\""] {
                assert_eq!(
                    values(
                        DetectorKind::Secret,
                        &format!("{}{suffix}", key.to_uppercase())
                    ),
                    ["abcd1234"]
                );
            }
        }
        for text in [
            "export SAMPLE_TOKEN=abcd1234",
            "DB_PASSWORD=abcd1234 ./run",
            "SAMPLE_SECRET_ACCESS_KEY: abcd1234",
            "client-secret-primary=abcd1234",
        ] {
            assert_eq!(values(DetectorKind::Secret, text), ["abcd1234"], "{text}");
        }
        assert_eq!(
            values(
                DetectorKind::Secret,
                "curl -H \"Authorization: Basic c3ludGg6bWFkZXVw\" https://example.test"
            ),
            ["c3ludGg6bWFkZXVw"]
        );
        for text in [
            "password=abc",
            "tokenizer=abcd1234",
            "a basic understanding",
            "other=abcd1234",
            "notpassword=abcd1234",
            "secret=''",
            "token=\"abc\"",
        ] {
            assert!(values(DetectorKind::Secret, text).is_empty(), "{text}");
        }
    }

    #[test]
    fn flags() {
        for flag in ["password", "token", "api-key", "secret"] {
            for separator in [" ", "="] {
                assert_eq!(
                    values(DetectorKind::Secret, &format!("--{flag}{separator}X")),
                    ["X"]
                );
                assert_eq!(
                    values(
                        DetectorKind::Secret,
                        &format!("--{flag}{separator}abcd1234")
                    ),
                    ["abcd1234"]
                );
            }
        }
        for text in [
            "-p abcd1234",
            "--other abcd1234",
            "--password ",
            "--tokenize abcd1234",
        ] {
            assert!(values(DetectorKind::Secret, text).is_empty());
        }
    }

    #[test]
    fn forms_that_used_to_get_past() {
        for (text, secret) in [
            ("PGPASSWORD=abcd1234 psql -h db", "abcd1234"),
            ("export GITHUBTOKEN='abcd1234'", "abcd1234"),
            ("MYSECRET_PRIMARY=abcd1234", "abcd1234"),
            ("tool --auth-token abcd1234", "abcd1234"),
            ("tool --access-token=abcd1234", "abcd1234"),
            ("tool --github-token \"abcd1234\"", "abcd1234"),
            ("tool --db-password X", "X"),
            ("mysql -u root -pS3cretPw sample", "S3cretPw"),
            ("/usr/local/bin/mysqldump -h db -pS3cretPw", "S3cretPw"),
            ("sshpass -p madeup-pw ssh dev@example.test", "madeup-pw"),
            ("sshpass -pmadeup-pw ssh host", "madeup-pw"),
            (
                "curl -u mira:madeup-pass https://example.test",
                "madeup-pass",
            ),
            (
                "curl --user=mira:madeup-pass https://example.test",
                "madeup-pass",
            ),
            (
                "curl -u 'mira:madeup-pass' https://example.test",
                "madeup-pass",
            ),
        ] {
            assert_eq!(values(DetectorKind::Secret, text), [secret], "{text}");
        }
        for (prefix, count) in [
            ("sk_live_", 24),
            ("rk_live_", 24),
            ("sk_test_", 24),
            ("glpat-", 20),
            ("npm_", 36),
            ("hf_", 34),
        ] {
            let token = format!("{prefix}{}", "a".repeat(count));
            assert_eq!(
                values(DetectorKind::Secret, &format!("use {token} now")),
                [token.as_str()]
            );
        }
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aCJ9.c2lnbmF0dXJlLW1hZGV1cA";
        assert_eq!(
            values(DetectorKind::Secret, &format!("cookie={jwt};")),
            [jwt]
        );
        let out = Redactor::with_default_detectors()
            .unwrap()
            .redact(&format!("curl -H 'Authorization: Bearer {jwt}' x"));
        assert_eq!(out.text, "curl -H 'Authorization: Bearer [SECRET]' x");
        for text in [
            "max_tokens=1000",
            "MAX_TOKENS=1000",
            "OLDPWD=/tmp/sample",
            "tool --no-password --verbose",
            "tool --token-file ./sample",
            "mysql -u root -P3306 -h db",
            "mysql -p sample",
            "sort -u names.txt",
            "git log -u",
            "curl -u mira https://example.test",
            "eyJhbGciOiJIUzI1NiJ9 alone",
        ] {
            assert!(values(DetectorKind::Secret, text).is_empty(), "{text}");
        }
    }

    #[test]
    fn url_credentials() {
        assert_eq!(
            values(
                DetectorKind::Secret,
                "custom://mira:madeup-pass@example.test/path"
            ),
            ["madeup-pass"]
        );
        for text in [
            "https://example.test/path",
            "https://mira@example.test",
            "https://mira:@example.test",
        ] {
            assert!(values(DetectorKind::Secret, text).is_empty());
        }
    }

    #[test]
    fn provider_prefixes() {
        for (prefix, count, character) in [
            ("sk-", 16, 'a'),
            ("ghp_", 20, 'a'),
            ("gho_", 20, 'a'),
            ("ghu_", 20, 'a'),
            ("ghs_", 20, 'a'),
            ("ghr_", 20, 'a'),
            ("AKIA", 16, 'A'),
            ("xoxb-", 10, 'a'),
            ("xoxa-", 10, 'a'),
            ("xoxp-", 10, 'a'),
            ("xoxr-", 10, 'a'),
            ("xoxs-", 10, 'a'),
            ("AIza", 35, 'a'),
        ] {
            let token = format!("{prefix}{}", character.to_string().repeat(count));
            assert_eq!(values(DetectorKind::Secret, &token), [token.as_str()]);
            assert!(values(DetectorKind::Secret, &token[..token.len() - 1]).is_empty());
        }
    }

    #[test]
    fn private_key_blocks() {
        for label in ["PRIVATE KEY", "RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY"] {
            let header = format!("-----BEGIN {label}-----");
            let block = format!("{header}\nsynthetic-content\n-----END {label}-----");
            assert_eq!(values(DetectorKind::Secret, &block), [block.as_str()]);
            let unfinished = format!("{header}\nunfinished");
            assert_eq!(
                values(DetectorKind::Secret, &unfinished),
                [unfinished.as_str()]
            );
            let mismatched = format!("{header}\n-----END OTHER PRIVATE KEY-----");
            assert_eq!(
                values(DetectorKind::Secret, &mismatched),
                [mismatched.as_str()]
            );
        }
        assert!(values(DetectorKind::Secret, "-----BEGIN PUBLIC KEY-----").is_empty());
    }

    #[test]
    fn ssn_validation() {
        assert_eq!(
            values(DetectorKind::UsSsn, "é 123-45-6789"),
            ["123-45-6789"]
        );
        for text in [
            "000-45-6789",
            "666-45-6789",
            "900-45-6789",
            "999-45-6789",
            "123-00-6789",
            "123-45-0000",
            "1123-45-6789",
            "123-45-67890",
            "a123-45-6789",
        ] {
            assert!(values(DetectorKind::UsSsn, text).is_empty());
        }
    }

    fn generated_number(prefix: &str) -> String {
        (b'0'..=b'9')
            .map(|digit| format!("{prefix}{}", char::from(digit)))
            .find(|number| verhoeff_valid(number.as_bytes()))
            .unwrap()
    }

    #[test]
    fn aadhaar_validation() {
        let number = generated_number("23456789012");
        for separator in ["", " ", "-"] {
            let grouped = format!(
                "{}{separator}{}{separator}{}",
                &number[..4],
                &number[4..8],
                &number[8..]
            );
            assert_eq!(
                values(DetectorKind::Aadhaar, &format!("é {grouped}!")),
                [grouped.as_str()]
            );
        }
        let invalid_check = format!(
            "{}{}",
            &number[..11],
            (number.as_bytes()[11] - b'0' + 1) % 10
        );
        for text in [
            invalid_check,
            generated_number("13456789012"),
            format!("0{number}"),
            format!("{number}0"),
            format!("a{number}"),
            format!("{}-{} {}", &number[..4], &number[4..8], &number[8..]),
        ] {
            assert!(values(DetectorKind::Aadhaar, &text).is_empty(), "{text}");
        }
    }
}
