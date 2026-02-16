"""Centralized logging configuration for NetPal.

Provides coloured console output via *colorama* and supports ``--verbose``
/ ``--quiet`` flags through log-level selection.

Usage::

    from netpal.utils.logger import get_logger

    log = get_logger(__name__)
    log.info("Scan started")
    log.warning("Retrying connection")
    log.error("Scan failed: %s", err)
    log.debug("Raw output: %s", data)  # only shown with --verbose
"""
import logging
import sys

from colorama import Fore, Style

__all__ = ["get_logger", "setup_logging"]

# ---------------------------------------------------------------------------
# Custom formatter that injects colorama colours per level
# ---------------------------------------------------------------------------

_LEVEL_COLOURS = {
    logging.DEBUG: Fore.WHITE,
    logging.INFO: Fore.CYAN,
    logging.WARNING: Fore.YELLOW,
    logging.ERROR: Fore.RED,
    logging.CRITICAL: Fore.RED + Style.BRIGHT,
}


class ColouredFormatter(logging.Formatter):
    """Formatter that prepends coloured level tags to log messages."""

    def format(self, record: logging.LogRecord) -> str:
        colour = _LEVEL_COLOURS.get(record.levelno, "")
        reset = Style.RESET_ALL
        level_tag = record.levelname

        # Build the formatted line
        msg = super().format(record)
        return f"{colour}[{level_tag}]{reset} {msg}"


# ---------------------------------------------------------------------------
# Module-level setup
# ---------------------------------------------------------------------------

_ROOT_LOGGER_NAME = "netpal"
_configured = False


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure the root *netpal* logger.

    Call once during CLI bootstrap (typically in ``main()``).

    Args:
        verbose: If *True*, set level to ``DEBUG``.
        quiet: If *True*, set level to ``WARNING`` (overrides *verbose*).
    """
    global _configured  # noqa: PLW0603

    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    root = logging.getLogger(_ROOT_LOGGER_NAME)
    root.setLevel(level)

    # Avoid adding duplicate handlers on repeated calls
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(ColouredFormatter("%(message)s"))
        root.addHandler(handler)
    else:
        # Update existing handler level
        for handler in root.handlers:
            handler.setLevel(level)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the *netpal* namespace.

    If :func:`setup_logging` has not been called yet, a default
    ``INFO``-level configuration is applied automatically.

    Args:
        name: Typically ``__name__`` of the calling module.

    Returns:
        A :class:`logging.Logger` instance.
    """
    if not _configured:
        setup_logging()

    # Ensure the name lives under the netpal namespace
    if not name.startswith(_ROOT_LOGGER_NAME):
        name = f"{_ROOT_LOGGER_NAME}.{name}"

    return logging.getLogger(name)
