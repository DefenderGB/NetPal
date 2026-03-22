"""Shared Textual widgets for the NetPal operator UI."""

from __future__ import annotations

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import DataTable, RichLog, Static


def _should_ignore_table_click(table: DataTable, meta: dict) -> bool:
    """Return True for stale/out-of-bounds table clicks that should be ignored."""
    if "row" not in meta or "column" not in meta:
        return False

    row_index = meta["row"]
    column_index = meta["column"]
    is_header_click = table.show_header and row_index == -1
    is_row_label_click = table.show_row_labels and column_index == -1

    if is_header_click:
        return (
            meta.get("out_of_bounds", False)
            or column_index < 0
            or column_index >= len(table.ordered_columns)
        )

    if is_row_label_click:
        return row_index < 0 or row_index >= len(table.ordered_rows)

    return False


class OperatorDataTable(DataTable):
    """Dense DataTable with safer click handling."""

    DEFAULT_CLASSES = "operator-table"

    async def _on_click(self, event: events.Click) -> None:
        if _should_ignore_table_click(self, event.style.meta):
            return
        await super()._on_click(event)


SafeDataTable = OperatorDataTable


class SectionHeader(Horizontal):
    """Inline title + description used across top-level views."""

    def __init__(self, title: str, description: str) -> None:
        super().__init__(classes="section-intro-row section-header")
        self._title = title
        self._description = description

    def compose(self) -> ComposeResult:
        yield Static(self._title, classes="section-title section-intro-title")
        yield Static(self._description, classes="info-text section-intro-text")


class SectionIntro(SectionHeader):
    """Backward-compatible alias for the older intro header widget."""


class BaseNetPalView(VerticalScroll):
    """Common base for NetPal's scrollable views."""

    DEFAULT_CLASSES = "base-netpal-view"

    def refresh_view(self) -> None:
        """Refresh widget content when the app state changes."""


class TextAction(Static):
    """Compact clickable text control used in place of bulky buttons."""

    DEFAULT_CLASSES = "text-action"
    BINDINGS = [
        Binding("enter", "press", show=False),
        Binding("space", "press", show=False),
    ]
    can_focus = True

    label = reactive("")

    class Pressed(Message):
        """Posted when a text action is pressed."""

        def __init__(self, action: "TextAction") -> None:
            self.action = action
            self.button = action
            super().__init__()

        @property
        def control(self) -> "TextAction":
            return self.button

    def __init__(
        self,
        label: str,
        *,
        variant: str = "default",
        id: str | None = None,
        classes: str | None = None,
        disabled: bool = False,
    ) -> None:
        widget_classes = "text-action"
        if classes:
            widget_classes = f"{widget_classes} {classes}"
        super().__init__(label, id=id, classes=widget_classes, disabled=disabled)
        self.label = label
        self.add_class(f"variant-{variant}")
        self.set_class(disabled, "is-disabled")

    def watch_label(self, label: str) -> None:
        self.update(label)

    def watch_disabled(self, disabled: bool) -> None:
        self.set_class(disabled, "is-disabled")

    def action_press(self) -> None:
        if self.disabled:
            return
        self.post_message(self.Pressed(self))

    async def _on_click(self, event: events.Click) -> None:
        event.stop()
        if self.disabled:
            return
        self.focus()
        self.action_press()


class ActionBar(Horizontal):
    """Shared action row container."""

    DEFAULT_CLASSES = "action-bar"


class MetricStrip(Static):
    """Single-line summary strip for compact metrics."""

    DEFAULT_CLASSES = "metric-strip"


class DetailPane(Vertical):
    """Labeled detail pane with a dedicated body widget."""

    def __init__(self, title: str, body_id: str, *, id: str | None = None) -> None:
        super().__init__(id=id, classes="detail-pane")
        self._title = title
        self._body_id = body_id

    def compose(self) -> ComposeResult:
        yield Static(self._title, classes="detail-title")
        with VerticalScroll(id=f"{self._body_id}-scroll", classes="detail-scroll", can_focus=True):
            yield Static("", id=self._body_id, classes="detail-body", shrink=True)


class DenseFormGrid(Vertical):
    """Compact form wrapper used for dense operator layouts."""

    DEFAULT_CLASSES = "dense-form-grid compact-form"


class LogPanel(Vertical):
    """Shared log panel wrapper with a titled RichLog."""

    def __init__(self, title: str, log_id: str, *, id: str | None = None) -> None:
        super().__init__(id=id, classes="pane-box")
        self._title = title
        self._log_id = log_id

    def compose(self) -> ComposeResult:
        yield Static(self._title, classes="panel-title")
        yield RichLog(id=self._log_id, highlight=True, markup=True, min_width=80, wrap=True)
