"""Helpers shared by the text renderers."""

from collections.abc import Sequence

from authtrail.models import EvidenceRef


def compact_refs(refs: Sequence[EvidenceRef], total: int) -> str:
    """``a.log:12, :14, b.json:3 (+9 more)`` - repeat the file name only when it changes."""
    parts = []
    last_file = None
    for ref in refs:
        parts.append(f":{ref.line}" if ref.file == last_file else ref.location)
        last_file = ref.file
    text = ", ".join(parts)
    hidden = total - len(refs)
    return f"{text} (+{hidden} more)" if hidden > 0 else text
