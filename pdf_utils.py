"""
Shared PDF text extraction helpers.

Uses Unstructured's open-source partition_pdf first, with pypdf as a lightweight
fallback for environments missing optional OCR/layout dependencies.
"""
import hashlib
import io
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import pypdf

logger = logging.getLogger(__name__)

_CACHE_VERSION = "v1"
_FALSE_VALUES = {"0", "false", "no", "off"}


def _cache_enabled() -> bool:
    return os.getenv("PDF_TEXT_CACHE_ENABLED", "1").strip().lower() not in _FALSE_VALUES


def _cache_dir() -> Path:
    configured = os.getenv("PDF_TEXT_CACHE_DIR")
    if configured:
        return Path(configured).expanduser()

    xdg_cache_home = os.getenv("XDG_CACHE_HOME")
    if xdg_cache_home:
        root = Path(xdg_cache_home).expanduser()
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Caches"
    else:
        root = Path.home() / ".cache"
    return root / "aws-bedrock-playground" / f"pdf-text-{_CACHE_VERSION}"


def _cache_path(pdf_bytes: bytes) -> Path:
    digest = hashlib.sha256(pdf_bytes).hexdigest()
    return _cache_dir() / f"{digest}.txt"


def _read_cached_text(pdf_bytes: bytes) -> str | None:
    if not _cache_enabled():
        return None

    cache_path = _cache_path(pdf_bytes)
    try:
        text = cache_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.debug("PDF text cache miss: %s", cache_path.name)
        return None
    except (OSError, UnicodeError) as exc:
        logger.debug("Ignoring unreadable PDF text cache entry %s: %s", cache_path, exc)
        return None

    if not text:
        return None
    logger.debug("PDF text cache hit: %s", cache_path.name)
    return text


def _write_cached_text(pdf_bytes: bytes, text: str) -> None:
    if not _cache_enabled() or not text:
        return

    cache_path = _cache_path(pdf_bytes)
    cache_dir = cache_path.parent
    temp_path: Path | None = None
    try:
        created_dir = not cache_dir.exists()
        cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if created_dir:
            cache_dir.chmod(0o700)

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=cache_dir,
            prefix=f".{cache_path.stem}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(text)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        temp_path.chmod(0o600)
        os.replace(temp_path, cache_path)
        logger.debug("Stored extracted PDF text in cache: %s", cache_path.name)
    except OSError as exc:
        logger.debug("Could not write PDF text cache entry %s: %s", cache_path, exc)
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def _elements_to_text(elements) -> str:
    parts: list[str] = []
    for element in elements:
        text = str(element).strip()
        if text:
            parts.append(text)
    return "\n\n".join(parts).strip()


def _pypdf_text_from_bytes(pdf_bytes: bytes) -> str:
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    pages = [page.extract_text() or "" for page in reader.pages]
    return "\n\n".join(pages).strip()


def _partition_pdf(**kwargs: Any):
    from unstructured.partition.pdf import partition_pdf

    return partition_pdf(**kwargs)


def _extract_pdf_text(pdf_bytes: bytes, *, filename: str | None = None) -> str:
    cached_text = _read_cached_text(pdf_bytes)
    if cached_text is not None:
        return cached_text

    try:
        partition_args = {"filename": filename} if filename else {"file": io.BytesIO(pdf_bytes)}
        elements = _partition_pdf(**partition_args)
        text = _elements_to_text(elements)
        if text:
            _write_cached_text(pdf_bytes, text)
            return text
    except Exception as exc:
        # Keep examples runnable even when optional OCR/layout dependencies are absent.
        source = f" for {filename}" if filename else ""
        logger.debug(
            "Unstructured PDF extraction failed%s; using pypdf fallback: %s",
            source,
            exc,
        )

    text = _pypdf_text_from_bytes(pdf_bytes)
    _write_cached_text(pdf_bytes, text)
    return text


def extract_pdf_text_from_bytes(pdf_bytes: bytes) -> str:
    """Extract and cache text from PDF bytes, falling back from Unstructured to pypdf."""
    return _extract_pdf_text(pdf_bytes)


def extract_pdf_text_from_path(path: str | Path) -> str:
    """Extract and cache text from a PDF path, falling back from Unstructured to pypdf."""
    pdf_path = Path(path)
    return _extract_pdf_text(pdf_path.read_bytes(), filename=str(pdf_path))
