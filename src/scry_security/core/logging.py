"""UTC console logging owned by the application, without altering the root logger."""

import logging
import time


class UTCFormatter(logging.Formatter):
    converter = time.gmtime


def configure_logging(level: str) -> logging.Logger:
    """Configure once, updating verbosity on subsequent calls."""
    logger = logging.getLogger("scry_security")
    logger.setLevel(level)
    logger.propagate = False
    if not any(getattr(handler, "_scry_console", False) for handler in logger.handlers):
        handler = logging.StreamHandler()
        handler._scry_console = True  # type: ignore[attr-defined]
        handler.setFormatter(
            UTCFormatter("%(asctime)sZ %(levelname)s %(name)s: %(message)s", "%Y-%m-%dT%H:%M:%S")
        )
        logger.addHandler(handler)
    return logger
