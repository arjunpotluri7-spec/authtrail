# Authtrail

Turn noisy authentication logs into explainable detections and narrated **attack stories**, with the exact evidence lines and MITRE ATT&CK technique behind every step.

![CI](../../actions/workflows/ci.yml/badge.svg)

## Why this exists

A busy SSH server or domain controller logs thousands of failed logins a day. Most tools either drown you in per-line alerts ("failed password", "failed password", ...) or give you a single score with no explanation. During triage the real questions are different: *did any of this work? which account? from where? what do I do first?*

Authtrail answers those questions offline, from log files you already have. Every alert says why it fired using the actual numbers versus the threshold, and points at the exact `file:line` that supports it.

## Distinctive feature: attack stories

Authtrail correlates related alerts into one **story**: a single incident with a title, an ordered timeline, ATT&CK techniques, affected accounts, sources and hosts, and suggested next defensive actions.

- Alerts that share a **source IP or account** and are within a configurable gap (default 2 hours) are merged with union-find, so the links can be transitive and can cross log sources (the sample spray hits a Linux server and a Mac, and both show up in one story).
- Stories **escalate** when their alerts combine into something worse than either alone: a password spray followed by a successful login from the same source becomes **critical**; a spray that also causes a lockout storm becomes at least **high**.
- Titles, narratives and next steps are produced **deterministically from templates** filled with each alert's numbers, so the same input always gives the same report and nothing is written by hand per sample.

Example title produced from the sample data: *"Password spray from 203.0.113.45 led to a successful login as bob"*, with next steps such as *"Reset bob's credentials..."*, *"Review sessions from 203.0.113.45 after 02:14 UTC..."*, and *"Consider blocking 203.0.113.0/24 at the edge"*.

## Features

- **Three input formats, auto-detected per file** (override with `--format-in`):
  - Linux `auth.log` / `secure`: classic BSD syslog (`Oct 14 02:14:09 host sshd[1]: ...`), rsyslog ISO-8601 timestamps, and RFC 5424. Understands `Failed ...`, `Accepted ...`, `Invalid user ...`, sudo `COMMAND=` lines (success and failure), and rsyslog `message repeated N times`.
  - macOS unified log exports from `log show --style ndjson` (or `--style json`): sshd / sshd-session and sudo messages in `eventMessage`. Authtrail never runs `log` itself; it only parses the file you give it.
  - Windows Security events as a JSON array or NDJSON: 4624, 4625, 4740 and 4672, with `TimeCreated` as ISO 8601 or PowerShell `/Date(ms)/`, UTF-8 or UTF-16 (PowerShell 5.1 default).
- Everything is normalized to one `AuthEvent` with a timezone-aware UTC timestamp and a `file:line` evidence reference. Unparseable lines are counted and reported, never fatal.
- **Seven rule types**, tuned by YAML rules shipped as package data. You can add your own with `--rules-dir`:

| Rule id | Type | Default severity | ATT&CK | Fires when |
|---|---|---|---|---|
| `brute-force` | `brute_force` | medium | T1110.001 | >= 5 failures for one user from one IP within 10 min |
| `password-spray` | `password_spray` | medium | T1110.003 | one IP fails against >= 5 distinct users within 30 min |
| `success-after-failures` | `success_after_failures` | high | T1110, T1078 | a success preceded by >= 5 failures from that IP (or that user+IP) within 30 min |
| `impossible-travel` | `impossible_travel` | high | T1078 | two successes for a user from configured locations imply > 900 km/h |
| `off-hours-privileged` | `off_hours_privileged` | medium | T1078.003 | success or sudo by a privileged user outside business hours |
| `new-source-for-user` | `new_source_for_user` | low | T1078 | a success from a /24 (or /64) never seen earlier for that user |
| `lockout-storm` | `lockout_storm` | medium | T1110 | >= 3 account lockouts (4740) within 15 min |

- **Explainable alerts**: each one has the rule, severity, technique, entity, first/last time, count, a "why it fired" sentence with real numbers, and capped evidence lines (the decisive last line, such as the successful login, is always kept).
- **Three report formats**: a terminal table, a stable JSON schema, and a Markdown incident report.
- **Defensive by design**: read-only, offline, no GeoIP or DNS lookups, no subprocesses, safe YAML, size limits, reports written `0600` and never overwritten without `--force`.

## Architecture

```
 log files ──► parsers/ ──► AuthEvent[] ──► detectors.py ──► Alert[] ──► stories.py ──► Story[]
 (named by     linux.py       (UTC, user,     (rule types,      (why + evidence)  (union-find,     │
  the user)    macos.py        ip, outcome,    params from                        escalation,      │
               windows.py      file:line)      rules/*.yaml)                      narrative.py)    ▼
                                                                                     render/: table | json | markdown
 config.yaml ──► config.py (business hours, privileged users, ip_locations, overrides) ──┘
```

| Module | Role |
|---|---|
| `cli.py` | argparse subcommands, exit codes, safe output writing |
| `analyzer.py` | pipeline: read and parse each file, apply `--since/--until`, run rules, build stories |
| `parsers/` | `common.py` (size-limited reading, encodings, JSON array/NDJSON record iteration with line numbers), `messages.py` (shared sshd/sudo message parsing), one module per format, auto-detection in `__init__.py` |
| `models.py` | `AuthEvent`, `EvidenceRef`, `Alert`, `Story`, `StoryStep`, `Severity` |
| `config.py` | YAML config validation with messages that name the file, key and expected value |
| `rules.py` + `rules/*.yaml` | rule schema, parameter specs per rule type, loading, per-rule overrides |
| `detectors.py` | the seven rule types, a sliding-window burst finder, evidence capping |
| `stories.py` | correlation (shared user/IP within the gap), escalation table, story assembly |
| `narrative.py` | template-based step sentences, story titles, and ordered next actions |
| `render/` | `table.py`, `jsonout.py`, `markdown.py` |
| `logsetup.py` | structured diagnostics to stderr (`--log-format json|text`) |

## Install

Requires Python 3.11 or newer. The only runtime dependency is PyYAML.

```bash
git clone <this repository> authtrail && cd authtrail
python3 -m venv .venv
. .venv/bin/activate                 # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt  # runtime + test/lint tools
pip install -e .
authtrail --version
```

- **macOS / Linux**: works as above.
- **Windows**: works as above. Python on Windows has no time zone database, so if you use a time zone other than `UTC` in the config, also run `pip install tzdata`.

## Quick start (sample data)

The `samples/` folder holds synthetic logs (see `samples/README.md`). BSD syslog lines carry no year, so pass `--year 2026`:

```bash
authtrail analyze samples/linux_auth.log samples/macos_unified.ndjson \
    samples/windows_security.json --config config.example.yaml --year 2026

# Markdown incident report
authtrail analyze samples/linux_auth.log samples/macos_unified.ndjson \
    samples/windows_security.json --config config.example.yaml --year 2026 \
    --format markdown --output report.md
```

The first command exits with code `1` because findings exist (see [exit codes](#output-formats-and-exit-codes)).

## Usage

```
authtrail analyze PATH... [--config FILE] [--rules-dir DIR] [--format table|json|markdown]
                          [--format-in auto|linux|macos|windows] [-o/--output FILE] [--force]
                          [--fail-on low|medium|high|critical|none] [--year N]
                          [--since ISO] [--until ISO] [--stories | --no-stories]
                          [--log-level LEVEL] [--log-format text|json]
authtrail rules list [--rules-dir DIR] [--config FILE]
authtrail rules show RULE_ID [--rules-dir DIR] [--config FILE]
authtrail validate-config FILE [--rules-dir DIR]
authtrail --version
```

| Flag | Meaning |
|---|---|
| `PATH...` | One or more log files. Directories are rejected; name files explicitly. |
| `--config FILE` | YAML config (see below). Without it, safe defaults are used. |
| `--rules-dir DIR` | Load extra `*.yaml` rules after the built-ins. Ids must be unique. |
| `--format` | `table` (default), `json`, or `markdown`. |
| `--format-in` | Force the input format for all files instead of auto-detecting. |
| `-o, --output FILE` | Write the report to a file (mode `0600`). Refuses to overwrite unless `--force`, and refuses to write over an input. |
| `--fail-on SEVERITY` | Exit `1` if any alert *or story* is at or above this severity. Default `low` (any finding); `none` never fails on findings. |
| `--year N` | Year of the first line of BSD syslog files. Default: the current UTC year. When the month goes backwards by six months or more (Dec -> Jan), the year is incremented, so a log that crosses New Year is dated correctly. ISO-8601 and RFC 5424 lines carry their own year and ignore this. |
| `--since / --until ISO` | Only analyze events in this time range (ISO 8601; naive times are UTC). |
| `--stories / --no-stories` | Turn story correlation on (default) or off. |
| `--log-level`, `--log-format` | Diagnostics on stderr. Reports never mix with logs. |

Rule tuning:

```bash
authtrail rules list
authtrail rules show success-after-failures   # every parameter, effective value, meaning
```

## Configuration

Copy and edit [`config.example.yaml`](config.example.yaml); every key is documented there and optional. Check it with `authtrail validate-config my.yaml`.

| Key | Purpose | Default |
|---|---|---|
| `syslog_timezone` | zone for syslog timestamps without one | `UTC` |
| `business_hours` | `timezone`, `start`, `end` (quoted `"HH:MM"`, may wrap past midnight), `days` | Mon-Fri 08:00-18:00 UTC |
| `privileged_users` | accounts checked by `off-hours-privileged` (case-insensitive) | `[root, administrator]` |
| `ip_locations` | map of CIDR -> `{name, lat, lon}` for impossible travel; most specific match wins. **No GeoIP is ever used.** | empty (rule inactive) |
| `stories.gap_minutes` | maximum gap for correlating alerts into one story | `120` |
| `evidence.max_per_alert` | evidence lines kept per alert | `5` |
| `limits.max_file_size_mb` | refuse larger input files | `200` |
| `rules.<id>` | `enabled`, `severity`, `params` overrides per rule | none |

Errors name the file, the key and what was expected, for example:

```
authtrail: error: my.yaml: 'business_hours.start': expected a time as "HH:MM" (24-hour), got '8am'
```

## Sample output

Real output from the quick-start command above. stderr reports the intentionally malformed sample lines:

```
WARNING unparseable lines skipped event=unparseable_lines path=samples/linux_auth.log count=2 first_lines=[68, 77]
WARNING unparseable lines skipped event=unparseable_lines path=samples/macos_unified.ndjson count=1 first_lines=[10]
WARNING unparseable lines skipped event=unparseable_lines path=samples/windows_security.json count=1 first_lines=[42]
```

stdout (trimmed after the second story; the full report continues with stories S-003 to S-006 and then every alert with its evidence):

```
Authtrail 0.1.0 report
Inputs: 3 file(s), 88 events analyzed (52 lines skipped as not auth-related, 4 unparseable)
  - samples/linux_auth.log [linux]: 41 events, 44 skipped, 2 unparseable
  - samples/macos_unified.ndjson [macos]: 6 events, 4 skipped, 1 unparseable
  - samples/windows_security.json [windows]: 41 events, 4 skipped, 1 unparseable
Time range: 2026-10-13 01:00:04 UTC -> 2026-10-14 16:20:07 UTC
Rules: 7 enabled

SUMMARY
  severity   stories  alerts
  critical         1       0
  high             2       2
  medium           2       6
  low              1       3
  total            6      11

ATTACK STORIES

[S-001] CRITICAL  Password spray from 203.0.113.45 led to a successful login as bob
  When:      2026-10-14 01:58:05 UTC -> 2026-10-14 02:18:42 UTC (20m 37s)
  Users:     bob, admin, test, oracle, postgres, ubuntu, guest, jenkins
  Sources:   203.0.113.45
  Hosts:     web-01
  ATT&CK:    T1078 Valid Accounts, T1110 Brute Force, T1110.003 Brute Force: Password Spraying
  Escalated: high -> critical: a password attack was followed by a successful login from the
             attacking source
  Timeline:
    2026-10-14 01:58:05  T1110.003       203.0.113.45 tried passwords against 8 different accounts
                                         ('admin', 'test', 'oracle', 'postgres', 'ubuntu' and 3
                                         more) on web-01, failing 15 times over 20m 37s.
                                         evidence: samples/linux_auth.log:25, :28, :31, :33,
                                                   samples/macos_unified.ndjson:6 (+10 more)
    2026-10-14 02:14:09  T1110,T1078     203.0.113.45 logged in successfully as 'bob' on web-01 with
                                         password at 02:14:09 UTC, right after 12 failed attempts
                                         from that source.
                                         evidence: samples/linux_auth.log:25, :28, :31, :33, :46 (+8
                                                   more)
    2026-10-14 02:14:09  T1078           'bob' logged in from 203.0.113.45, a network
                                         (203.0.113.0/24) not seen for this account earlier in the
                                         data.
                                         evidence: samples/linux_auth.log:46
  Next steps:
    1. Open an incident and treat 'bob' as compromised until proven otherwise.
    2. Reset bob's credentials and revoke their active sessions and keys.
    3. Review sessions from 203.0.113.45 after 02:14 UTC on 2026-10-14 (commands run, sudo use,
       files changed).
    4. Consider blocking 203.0.113.0/24 at the edge (at minimum 203.0.113.45).
    5. Check the 8 targeted accounts for any successful login from 203.0.113.45, and require MFA or
       key-only SSH for them.
    6. Verify that 203.0.113.45 is an expected source for 'bob'.

[S-002] HIGH  Password spray from 192.0.2.66 caused 4 account lockouts
  When:      2026-10-14 09:20:03 UTC -> 2026-10-14 09:25:27 UTC (5m 24s)
  Users:     administrator, helpdesk, frank, erin, dave, scanner
  Sources:   192.0.2.66
  Hosts:     DC01.corp.example.com
  ATT&CK:    T1110 Brute Force, T1110.003 Brute Force: Password Spraying
  Escalated: medium -> high: the password attack also locked accounts out, so it is disrupting real
             users
  Timeline:
    2026-10-14 09:20:03  T1110.003       192.0.2.66 tried passwords against 6 different accounts
                                         ('administrator', 'helpdesk', 'frank', 'erin', 'dave' and 1
                                         more) on DC01.corp.example.com, failing 18 times over 5m
                                         24s.
                                         evidence: samples/windows_security.json:20, :21, :22, :23,
                                                   :41 (+13 more)
    2026-10-14 09:25:03  T1110           4 account lockouts hit 'administrator', 'helpdesk', 'frank'
                                         and 'erin' on DC01.corp.example.com within 15s.
                                         evidence: samples/windows_security.json:33, :35, :37, :39
  Next steps:
    1. Consider blocking 192.0.2.0/24 at the edge (at minimum 192.0.2.66).
    2. Check the 6 targeted accounts for any successful login from 192.0.2.66, and require MFA for
       them.
    3. Before unlocking 'administrator', 'helpdesk', 'frank' and 'erin', confirm with each user and
       check that the lockouts are explained by the attack.
...
```

The alerts section shows each alert's reason and evidence lines (excerpt):

```
ALERTS
  ID     SEVERITY  RULE                    FIRST SEEN (UTC)      COUNT  ENTITY
  A-001  high      success-after-failures  2026-10-14 01:58:05      13  user=bob ip=203.0.113.45
         Why: Successful password login as 'bob' from 203.0.113.45 at 02:14:09 UTC after 12 failed
              logins from the same source in the preceding 30 minutes (threshold: 5); the failures
              targeted 8 accounts.
           > samples/linux_auth.log:25  Oct 14 01:58:05 web-01 sshd[4102]: Failed password for invalid user admin from 203.0.113.45 port 50122 ssh2
           > samples/linux_auth.log:28  Oct 14 01:59:43 web-01 sshd[4110]: Failed password for invalid user test from 203.0.113.45 port 50388 ssh2
           > samples/linux_auth.log:31  Oct 14 02:01:14 web-01 sshd[4131]: Failed password for invalid user oracle from 203.0.113.45 port 50720 ssh2
           > samples/linux_auth.log:33  Oct 14 02:02:52 web-01 sshd[4140]: Failed password for invalid user postgres from 203.0.113.45 port 51004 ssh2
           > samples/linux_auth.log:46  Oct 14 02:14:09 web-01 sshd[4222]: Accepted password for bob from 203.0.113.45 port 53122 ssh2
...
```

Markdown report (`--format markdown`), beginning:

```markdown
# Authentication incident report

Produced by Authtrail 0.1.0 on 2026-10-19 03:50:29 UTC from 3 log file(s) and 88 authentication events.
Data covers 2026-10-13 01:00:04 UTC to 2026-10-14 16:20:07 UTC.

## Executive summary

- **6 attack stories** (1 critical, 2 high, 2 medium, 1 low) built from **11 alerts**.
- 2 stories were escalated because of how their alerts combine.

| Story | Severity | What happened | Window (UTC) |
|---|---|---|---|
| [S-001](#s-001) | **critical** | Password spray from 203.0.113.45 led to a successful login as bob | 2026-10-14 01:58 - 02:18 |
| [S-002](#s-002) | **high** | Password spray from 192.0.2.66 caused 4 account lockouts | 2026-10-14 09:20 - 09:25 |
| [S-003](#s-003) | **high** | Impossible travel for carol: New York office to Singapore office | 2026-10-14 13:02 - 14:31 |
| [S-004](#s-004) | **medium** | Off-hours privileged activity by deploy | 2026-10-14 03:09 - 03:10 |
| [S-005](#s-005) | **medium** | Brute force from 198.51.100.23 against root and administrator | 2026-10-14 04:40 - 04:52 |
| [S-006](#s-006) | **low** | svc-backup logged in from a new source 198.51.100.77 | 2026-10-14 06:05 - 06:05 |

<a id="s-001"></a>
...
```

## Output formats and exit codes

- **table**: summary counts by severity, then stories (timeline, evidence references, next steps), then alerts (reason + evidence lines). ANSI color is used only when stdout is a terminal and `NO_COLOR` is not set.
- **markdown**: an incident report with an executive summary, one section per story (timeline table, evidence blocks, next-step checklist), an alerts table, inputs, and method notes.
- **json**: a stable document (`schema_version` `1.0`):

```
{
  "schema_version": "1.0",
  "tool": {"name", "version"},
  "generated_at": ISO-8601 UTC,
  "inputs":  [{"path", "format", "events", "skipped", "unparseable"}],
  "filters": {"since", "until"},
  "summary": {"events_analyzed", "first_event", "last_event", "rules_enabled", "alerts",
              "stories", "stories_enabled", "alerts_by_severity", "stories_by_severity",
              "max_severity"},
  "stories": [{"id", "title", "severity", "base_severity", "escalation", "first_seen",
               "last_seen", "users", "ips", "hosts", "alert_ids", "techniques",
               "timeline": [{"time", "alert_id", "severity", "techniques", "narrative",
                             "evidence", "evidence_total"}],
               "next_actions"}],
  "alerts":  [{"id", "rule_id", "rule_type", "title", "severity", "techniques", "entity",
               "first_seen", "last_seen", "count", "reason", "details", "evidence",
               "evidence_total", "evidence_truncated"}]
}
```

`details` holds the rule-type-specific numbers (for example `failures`, `threshold`, `window_minutes`, `distance_km`). Each `evidence` item is `{"ref", "file", "line", "raw"}` with the full raw line.

Real excerpt (`summary` from the sample run):

```json
{
  "events_analyzed": 88,
  "first_event": "2026-10-13T01:00:04Z",
  "last_event": "2026-10-14T16:20:07Z",
  "rules_enabled": [
    "brute-force",
    "impossible-travel",
    "lockout-storm",
    "new-source-for-user",
    "off-hours-privileged",
    "password-spray",
    "success-after-failures"
  ],
  "alerts": 11,
  "stories": 6,
  "stories_enabled": true,
  "alerts_by_severity": {
    "critical": 0,
    "high": 2,
    "medium": 6,
    "low": 3
  },
  "stories_by_severity": {
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 1
  },
  "max_severity": "critical"
}
```

| Exit code | Meaning |
|---|---|
| `0` | Ran successfully; nothing reached `--fail-on` |
| `1` | At least one alert or story is at or above `--fail-on` |
| `2` | Usage, configuration, rule, or input error (one clean error line, no traceback) |

## Testing

```bash
ruff check . && ruff format --check .
pytest -q
```

The suite (118 tests) covers each parser (malformed lines, year rollover, time zones, UTF-16, JSON array line numbers), every rule type firing and not firing at its threshold boundary, story correlation and escalation, config and rule validation errors, CLI exit codes, the JSON schema, output-file safety, Markdown output, and a regression test asserting that the sample data still produces the expected six stories.

Last lines of the local run:

```
........................................................................ [ 61%]
..............................................                           [100%]
118 passed in 0.37s
```

## Limitations

- **Thresholds, not baselines.** Rules are fixed thresholds and windows. There is no per-user statistical baseline, so tune them for your environment (`authtrail rules show`).
- **"New source" means new within the analyzed data.** Authtrail has no memory between runs, so the first login of every account is treated as known, not new.
- **Locations are only what you configure.** Impossible travel works only for networks listed in `ip_locations`; without them the rule never fires. VPNs and shared egress points can cause false positives.
- **Year inference for BSD syslog.** The year comes from `--year` plus Dec -> Jan rollover detection. A file that starts in a different year than `--year`, or spans more than a year, will be misdated.
- **Formats are heuristic.** Linux parsing covers common OpenSSH and sudo messages, not every PAM module or distribution-specific wording. macOS parsing covers sshd and sudo messages only, and `log show` exports carry no host name. Windows parsing expects flat JSON fields (`EventID`/`Id`, `TimeCreated`, `TargetUserName`, `IpAddress`, `LogonType`, `Computer`), not raw EVTX or nested XML-to-JSON layouts.
- **Correlation is entity-based.** Alerts are linked only by shared user names or IPs within the gap. Attacks that rotate both are split into several stories, and very common accounts (for example `administrator`) can join unrelated activity that happens close together.
- **Whole-file reads.** Each file is read into memory (bounded by `limits.max_file_size_mb`); there is no streaming or live tailing.

## Roadmap

- EVTX-to-JSON layouts with nested `EventData`, and journald JSON export
- Optional state file so "new source" can remember earlier runs
- More rule types (MFA fatigue, Kerberos 4768/4771 patterns, sudo abuse)
- SARIF and CSV output

## Ethical use

Authtrail is for authorized, defensive use: incident response, detection engineering, and learning. Analyze only logs you own or have explicit permission to analyze, and handle reports as sensitive, since they contain account names, addresses and raw log lines.

## License

[MIT](LICENSE). Copyright (c) 2026 Authtrail contributors.
