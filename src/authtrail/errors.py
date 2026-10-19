"""Exception types that end a run with a clean one-line error and exit code 2."""


class AuthtrailError(Exception):
    """Base class for user-facing errors (bad input, bad config, bad rules)."""


class ConfigError(AuthtrailError):
    """The configuration file is missing, unreadable, or invalid."""


class RuleError(AuthtrailError):
    """A rule file is missing, unreadable, or invalid."""


class InputError(AuthtrailError):
    """A log file or output path cannot be used."""
