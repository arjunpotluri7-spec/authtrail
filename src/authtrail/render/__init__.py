"""Report renderers: plain-text table, JSON, and Markdown incident report."""

from authtrail.render.jsonout import render_json, report_to_dict
from authtrail.render.markdown import render_markdown
from authtrail.render.table import render_table

__all__ = ["render_json", "render_markdown", "render_table", "report_to_dict"]
