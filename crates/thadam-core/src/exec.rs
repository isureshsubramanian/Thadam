//! Process-execution observations from the OS event source.

/// One exec as reported by the OS. The OS event carries the full environment, which can
/// contain API keys. It is held here only so that dropping it is explicit and testable:
/// `into_command_line` consumes the observation and the environment goes no further.
#[derive(Debug, Clone)]
pub struct ExecObservation {
    pub executable: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env: Vec<String>,
}

impl ExecObservation {
    /// Returns the command line for the event's `target`, dropping the environment. The
    /// result still needs redaction, which `EventRecord::new` applies to every target.
    pub fn into_command_line(self) -> String {
        let ExecObservation {
            executable, args, ..
        } = self;
        if args.is_empty() {
            return quote_arg(&executable);
        }
        args.iter()
            .map(|a| quote_arg(a))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn quote_arg(arg: &str) -> String {
    let needs_quotes = arg.is_empty()
        || arg
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\'');
    if needs_quotes {
        format!("\"{}\"", arg.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        arg.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_keeps_args_and_drops_environment() {
        let obs = ExecObservation {
            executable: "/usr/bin/curl".into(),
            args: vec!["curl".into(), "-H".into(), "X-Trace: abc".into()],
            cwd: Some("/Users/dev/projects/sample-app".into()),
            env: vec!["SAMPLE_ENV_VALUE=env-marker-3f9c".into()],
        };
        let line = obs.into_command_line();
        assert_eq!(line, "curl -H \"X-Trace: abc\"");
        assert!(!line.contains("env-marker-3f9c"));
    }
}
