# Sample data

**Everything in this folder is synthetic.** The logs were written by hand for testing and
demonstration. No line comes from a real system, and every name, host, and address is
fictional:

- Public addresses use only the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, and
  `203.0.113.0/24` (RFC 5737). Internal addresses are `10.x`.
- Hosts are `web-01`, `DC01.corp.example.com`, and `FS01.corp.example.com`.
- Accounts (`alice`, `bob`, `carol`, `deploy`, `svc-backup`, ...) are made up.

| File | Format | What it contains |
|---|---|---|
| `linux_auth.log` | BSD syslog (`/var/log/auth.log`), no year in timestamps | Normal publickey logins by `alice` from `10.0.0.x`; a password spray from `203.0.113.45` against 8 accounts that ends in a successful password login as `bob`; a failed `sudo` by `bob` afterwards; a `deploy` login and `sudo` at 03:10 UTC; a brute force against `root` from `198.51.100.23` (including an rsyslog `message repeated 3 times` line); cron and session noise. |
| `macos_unified.ndjson` | `log show --style ndjson` export | More failures from `203.0.113.45` (same spray, different machine), a normal `alice` login and `sudo`, and unrelated daemon messages. |
| `windows_security.json` | JSON array of Security events | Nightly `svc-backup` logons, then one from a new address `198.51.100.77`; 4625 bursts from `198.51.100.23` (brute force) and `192.0.2.66` (spray); a 4740 lockout storm; an impossible-travel pair for `carol` between the New York and Singapore office networks defined in `config.example.yaml`. |

A few malformed lines are included on purpose (a truncated syslog line, a garbage line, a cut-off
JSON record, and a Windows record with no `TimeCreated`) so the unparseable-line counters have
something to count.

Because BSD syslog lines carry no year, run the demo with `--year 2026`:

```bash
authtrail analyze samples/linux_auth.log samples/macos_unified.ndjson \
    samples/windows_security.json --config config.example.yaml --year 2026
```

The expected result is six attack stories (one critical, two high, two medium, one low) built
from eleven alerts. `tests/test_samples.py` checks this.
