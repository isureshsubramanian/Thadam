# Security Policy

Thadam keeps an audit record of what AI coding tools do on a Mac. Part of it runs as root,
and the record is only useful if it can be trusted, so security reports are welcome and
taken seriously.

## Supported versions

Thadam is in early development. Only the latest release gets security fixes.

| Version              | Supported |
| -------------------- | --------- |
| Latest 0.1.x release | Yes       |
| Older releases       | No        |

## Reporting a vulnerability

Please report privately. Do not open a public issue, discussion or pull request.

1. Go to this repository's **Security** tab and choose **Report a vulnerability**.
2. Include the Thadam version (`pkgutil --pkg-info com.nerttiyana.thadam`), the macOS
   version, the steps to reproduce it, and what an attacker gains.
3. Use made-up data in examples. Do not send real prompts, file contents, credentials or
   records from an audit store.

What to expect:

- An acknowledgement within 7 days.
- An assessment (accepted or declined, with the reason) within 30 days.
- For accepted reports: a fix in a new release, and a published advisory once the fix is
  out. You will be credited in the advisory unless you prefer not to be.

Please give us a reasonable time to release a fix before you disclose the issue publicly.

## What Thadam protects

These are the guarantees, and a way around any of them is a vulnerability:

- **The record cannot be changed or removed by programs running as you**, AI tools
  included. The collector runs as root, and the store and registry are owned by root.
- **Tampering is detected.** Rows are hash-chained, so a changed, deleted or reordered row,
  or a removed segment, fails `thadam-store verify` and shows in the dashboard.
- **Records cannot be forged.** The collector checks who sends to each of its sockets: the
  network socket is reachable only by root, the audit socket accepts only the installed
  API, and hook messages carry the sender's identity as the kernel reports it.
- **Sensitive values are not stored.** No file contents, no exec environment, no network
  payloads, and detected secrets in command lines and prompts are redacted.
- **The dashboard is local and needs a password.** The API listens on 127.0.0.1 only and
  only reads the store. Reviews go through the collector's append-only audit log.
- **Gaps are visible.** When the collector is stopped, short of disk space or dropping
  events, the gap is recorded and shown.

## Out of scope

- An attacker who already has root or can load kernel code. Root can stop the collector
  and rewrite the store; Thadam can show that a gap happened but cannot prevent it.
- What the AI tools themselves do. Thadam records their behaviour; it does not judge or
  block it.
- Attacks that need physical access to an unlocked Mac, or that need you to switch off
  System Integrity Protection.
- Missing hardening with no concrete way to exploit it.
- Vulnerabilities in third-party components, unless Thadam uses them in a way that makes
  them exploitable. Please report those to the component's maintainers as well.
