"""Shared Textual theme loading for the NetPal operator UI."""

from __future__ import annotations

from pathlib import Path


def _load_app_css() -> str:
    return Path(__file__).with_name("styles.tcss").read_text(encoding="utf-8")


APP_CSS = _load_app_css()

