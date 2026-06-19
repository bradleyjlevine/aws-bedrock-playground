"""
Shared PDF text extraction helpers.

Uses Unstructured's open-source partition_pdf first, with pypdf as a lightweight
fallback for environments missing optional OCR/layout dependencies.
"""
import io
from pathlib import Path

import pypdf
from unstructured.partition.pdf import partition_pdf


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


def extract_pdf_text_from_bytes(pdf_bytes: bytes) -> str:
    """Extract text from PDF bytes with Unstructured, falling back to pypdf."""
    try:
        elements = partition_pdf(file=io.BytesIO(pdf_bytes))
        text = _elements_to_text(elements)
        if text:
            return text
    except Exception:
        # Keep examples runnable even when optional OCR/layout dependencies are absent.
        pass

    return _pypdf_text_from_bytes(pdf_bytes)


def extract_pdf_text_from_path(path: str | Path) -> str:
    """Extract text from a PDF path with Unstructured, falling back to pypdf."""
    pdf_path = Path(path)
    try:
        elements = partition_pdf(filename=str(pdf_path))
        text = _elements_to_text(elements)
        if text:
            return text
    except Exception:
        pass

    return _pypdf_text_from_bytes(pdf_path.read_bytes())
