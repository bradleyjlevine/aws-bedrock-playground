"""Shared DEBUG file logging for numbered scripts."""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import Any


def configure_script_logging(script_file: str, *, level: int = logging.DEBUG) -> logging.Logger:
    """Write DEBUG logs for one script to logs/<script-stem>.log for the current run."""
    script_path = Path(script_file)
    log_dir = script_path.resolve().parent / "logs"
    log_dir.mkdir(exist_ok=True)
    log_path = log_dir / f"{script_path.stem}.log"

    root = logging.getLogger()
    root.setLevel(level)

    file_handler_exists = any(
        isinstance(handler, logging.FileHandler)
        and Path(getattr(handler, "baseFilename", "")) == log_path
        for handler in root.handlers
    )
    if not file_handler_exists:
        file_handler = logging.FileHandler(log_path, mode="w", encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        root.addHandler(file_handler)

    console_handler_exists = any(
        getattr(handler, "_script_console_handler", False) for handler in root.handlers
    )
    if not console_handler_exists:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        console_handler._script_console_handler = True
        root.addHandler(console_handler)

    # Keep sensitive/noisy internals out of DEBUG logs while preserving useful
    # request lifecycle lines from botocore, urllib3, OpenAI/httpx, and app code.
    for logger_name in ("botocore.auth", "botocore.credentials", "s3transfer"):
        logging.getLogger(logger_name).setLevel(logging.INFO)

    logger = logging.getLogger(script_path.stem)
    logger.debug("Logging initialized at %s", log_path)
    return logger


def install_http_request_logging_middleware(app: Any, logger: logging.Logger) -> None:
    """Register FastAPI middleware that DEBUG-logs each request's timing and status."""

    @app.middleware("http")
    async def _log_http_request(request: Any, call_next: Any) -> Any:
        start = time.perf_counter()
        logger.debug("HTTP request start method=%s path=%s", request.method, request.url.path)
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("HTTP request failed method=%s path=%s", request.method, request.url.path)
            raise

        elapsed_ms = (time.perf_counter() - start) * 1000
        logger.debug(
            "HTTP request complete method=%s path=%s status=%d elapsed_ms=%.1f",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        return response
