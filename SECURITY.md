# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1 | No |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **private vulnerability reporting**:
open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a
public issue for security problems.

Include the Authtrail version, Python version and OS, a minimal input that reproduces the
problem (synthetic data only, please), and what you expected to happen.

## What to expect

- Acknowledgement within 5 business days.
- An initial assessment within 10 business days.
- A fix or mitigation plan for confirmed issues, with credit in the release notes if you
  want it. We ask that you allow a reasonable time for a fix before public disclosure.

## Scope

In scope: anything in this repository that could let crafted log, config, or rule files cause
code execution, writes outside the requested output path, reading files other than the named
inputs, denial of service out of proportion to input size, or misleading results (for
example, an evidence reference that points at the wrong line).

Out of scope: detections that miss an attack (please open a normal issue or pull request for
rule improvements), and problems in third-party dependencies that are already public.

## Security design

- **Read-only and offline.** Authtrail reads only the files named on the command line plus an
  optional config and rules directory. It makes no network connections, performs no GeoIP or
  DNS lookups, and runs no subprocesses. Input files are never modified.
- **Safe parsing.** YAML is loaded with `yaml.safe_load`; JSON with the standard library. No
  `eval`, `exec`, or `pickle`. Bad encodings are replaced rather than fatal; malformed lines
  are counted and skipped.
- **Bounded input.** Files larger than `limits.max_file_size_mb` (default 200 MB) are refused;
  configs are capped at 1 MB and rule files at 256 KB. Directories and non-regular files are
  rejected.
- **Careful output.** Reports may contain log lines, so `--output` files are created with mode
  `0600`, an existing file is never overwritten without `--force`, symlinks are not followed
  when opening the output, and writing over an input file is refused.
- **No secrets.** Authtrail needs no credentials. Diagnostic logs go to stderr and contain
  counts and file paths, not log contents.
