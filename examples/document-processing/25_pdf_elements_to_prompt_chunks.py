"""Convert Unstructured PDF elements into model-ready prompt chunks.

Run:
    uv run python examples/document-processing/25_pdf_elements_to_prompt_chunks.py ./report.pdf
    uv run python examples/document-processing/25_pdf_elements_to_prompt_chunks.py ./report.pdf --question "Summarize key risks."

This example keeps the source filename, page numbers, and element types beside
the extracted text. Those labels make chunks useful for AI models because the
model can cite where facts came from and downstream code can retrieve or filter
specific document regions.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from logging_utils import configure_script_logging
from unstructured.partition.pdf import partition_pdf

LOGGER = configure_script_logging(__file__)


@dataclass
class DocumentElement:
    source: str
    index: int
    element_type: str
    page_number: int | None
    text: str


@dataclass
class PromptChunk:
    source: str
    chunk_index: int
    element_indexes: list[int]
    element_types: list[str]
    pages: list[int]
    text: str

    def to_prompt_block(self) -> str:
        pages = page_range(self.pages) if self.pages else "unknown"
        element_types = ", ".join(self.element_types)
        indexes = f"{self.element_indexes[0]}-{self.element_indexes[-1]}"
        return (
            f"### Source chunk {self.chunk_index}\n"
            f"source: {self.source}\n"
            f"pages: {pages}\n"
            f"elements: {indexes}\n"
            f"element_types: {element_types}\n"
            f"characters: {len(self.text)}\n\n"
            f"{self.text.strip()}"
        )

    def to_record(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "chunk_index": self.chunk_index,
            "element_indexes": self.element_indexes,
            "element_types": self.element_types,
            "pages": self.pages,
            "text": self.text,
            "text_length": len(self.text),
        }


def element_type(element: Any) -> str:
    return getattr(element, "category", None) or type(element).__name__


def page_number(element: Any) -> int | None:
    metadata = getattr(element, "metadata", None)
    page = getattr(metadata, "page_number", None)
    if isinstance(page, int):
        return page
    try:
        return int(page)
    except (TypeError, ValueError):
        return None


def page_range(pages: list[int]) -> str:
    unique = sorted(set(pages))
    if len(unique) == 1:
        return str(unique[0])
    return f"{unique[0]}-{unique[-1]}"


def ordered_unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def partition_elements(
    pdf_path: Path,
    *,
    strategy: str,
    infer_table_structure: bool,
) -> list[DocumentElement]:
    elements = partition_pdf(
        filename=str(pdf_path),
        strategy=strategy,
        infer_table_structure=infer_table_structure,
    )
    records: list[DocumentElement] = []
    for index, element in enumerate(elements, start=1):
        text = str(element).strip()
        if not text:
            continue
        records.append(
            DocumentElement(
                source=str(pdf_path),
                index=index,
                element_type=element_type(element),
                page_number=page_number(element),
                text=text,
            )
        )
    return records


def build_chunks(elements: list[DocumentElement], *, max_chars: int) -> list[PromptChunk]:
    chunks: list[PromptChunk] = []
    current: list[DocumentElement] = []
    current_chars = 0

    def flush() -> None:
        nonlocal current, current_chars
        if not current:
            return
        chunks.append(
            PromptChunk(
                source=current[0].source,
                chunk_index=len(chunks) + 1,
                element_indexes=[element.index for element in current],
                element_types=ordered_unique([element.element_type for element in current]),
                pages=[
                    element.page_number
                    for element in current
                    if element.page_number is not None
                ],
                text="\n\n".join(element.text for element in current),
            )
        )
        current = []
        current_chars = 0

    for element in elements:
        element_chars = len(element.text)
        if current and current_chars + element_chars + 2 > max_chars:
            flush()
        current.append(element)
        current_chars += element_chars + 2
        if element_chars >= max_chars:
            flush()

    flush()
    return chunks


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Partition a PDF and print source-attributed prompt chunks."
    )
    parser.add_argument("pdf", type=Path, help="PDF file to partition")
    parser.add_argument(
        "--strategy",
        default="auto",
        choices=["auto", "fast", "hi_res", "ocr_only"],
        help="Unstructured PDF partition strategy",
    )
    parser.add_argument(
        "--infer-table-structure",
        action="store_true",
        help="Ask Unstructured to preserve table structure when supported",
    )
    parser.add_argument(
        "--max-chars",
        type=int,
        default=3500,
        help="Approximate maximum characters per prompt chunk",
    )
    parser.add_argument(
        "--max-chunks",
        type=int,
        default=0,
        help="Limit chunks printed; 0 means print every chunk",
    )
    parser.add_argument(
        "--question",
        default="Summarize this source. Include page references when possible.",
        help="Task text to prepend before the chunks",
    )
    parser.add_argument(
        "--jsonl",
        action="store_true",
        help="Print chunks as JSONL records instead of prompt text",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.pdf.exists():
        raise SystemExit(f"PDF not found: {args.pdf}")
    if args.max_chars < 500:
        raise SystemExit("--max-chars must be at least 500")

    try:
        elements = partition_elements(
            args.pdf,
            strategy=args.strategy,
            infer_table_structure=args.infer_table_structure,
        )
    except Exception as exc:
        print(f"Could not partition PDF with Unstructured: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    chunks = build_chunks(elements, max_chars=args.max_chars)
    if args.max_chunks > 0:
        chunks = chunks[: args.max_chunks]

    if args.jsonl:
        for chunk in chunks:
            print(json.dumps(chunk.to_record(), separators=(",", ":")))
        return

    print(f"Task: {args.question}")
    print()
    print(
        "Use only the source chunks below. Cite source, page, and chunk metadata "
        "when making factual claims."
    )
    for chunk in chunks:
        print("\n---\n")
        print(chunk.to_prompt_block())


if __name__ == "__main__":
    main()
