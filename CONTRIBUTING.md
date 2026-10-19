# Contributing to Authtrail

Thanks for helping. Authtrail is a small, defensive, offline tool; contributions that keep it
that way are very welcome.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pip install -e .
```

## Lint and test

```bash
ruff check .
ruff format --check .           # or `ruff format .` to fix
pytest -q
```

CI runs the same commands on Python 3.11 to 3.14, plus a smoke run against `samples/`.

## Style

- Python 3.11+, type hints, dataclasses, `pathlib`; standard library first.
- Ruff settings live in `pyproject.toml` (line length 100). Fix findings rather than adding
  ignores; any ignore needs a one-line reason.
- Comments explain *why*, not *what*. Public functions get docstrings.
- No network calls, subprocesses, `eval`, or `pickle`. YAML is loaded with `yaml.safe_load`.
- Test data uses documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, `2001:db8::/32`), `example.com` domains, and obviously fictional names.

## Adding or tuning a rule

Most changes need only YAML. A rule file picks one of the built-in rule *types*
(`brute_force`, `password_spray`, `success_after_failures`, `impossible_travel`,
`off_hours_privileged`, `new_source_for_user`, `lockout_storm`) and sets its parameters:

```yaml
id: root-guessing             # unique, lower-case
title: Root password guessing
type: brute_force
severity: high
attack:
  - id: T1110.001
    name: "Brute Force: Password Guessing"
description: Three failures for root from one address within five minutes.
params:
  threshold: 3
  window_minutes: 5
```

- To ship it, add the file to `src/authtrail/rules/`. For local use, put it in any folder and
  pass `--rules-dir`.
- `authtrail rules show <id>` lists every parameter with its meaning and default.

A new rule *type* needs Python:

1. Add its parameter specs to `RULE_TYPES` in `src/authtrail/rules.py`.
2. Write a `detect_<type>(rule, events, config) -> list[Alert]` function in
   `src/authtrail/detectors.py` and register it in `DETECTORS`. Put the numbers that explain
   the alert into `facts` and a plain sentence with actual values versus thresholds into
   `reason`.
3. Add a narrative template, title rule, and next actions in `src/authtrail/narrative.py`,
   and, if the type should escalate stories, an entry in `ESCALATIONS` in `stories.py`.
4. Add a YAML rule in `src/authtrail/rules/` and tests that show it firing and not firing at
   the threshold boundary.

A new input format means a parser in `src/authtrail/parsers/` that returns a `ParseResult`
of `AuthEvent`s, a detection hint in `parsers/__init__.py`, and tests for malformed input.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat: ...`, `fix: ...`,
`docs: ...`, `test: ...`, `refactor: ...`, `chore: ...`. Keep the subject under 72 characters
and explain the reason in the body when it is not obvious.

## Pull request checklist

- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `pytest -q` passes, with tests for new behavior (including the non-firing case)
- [ ] README / `config.example.yaml` updated if flags, config keys, or output changed
- [ ] If the JSON output changed, `SCHEMA_VERSION` was bumped and the README schema updated
- [ ] No real log data, hostnames, addresses, or credentials in code, tests, or samples

## Code of conduct

Be respectful and constructive; harassment or personal attacks are not tolerated in issues,
pull requests, or any other project space.
