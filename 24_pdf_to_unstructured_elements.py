"""Show how Unstructured turns a PDF into typed document elements.

Run:
    uv run python 24_pdf_to_unstructured_elements.py ./report.pdf
    uv run python 24_pdf_to_unstructured_elements.py ./report.pdf --pretty --max-elements 20

The output is JSONL by default so it can be piped into other tools. Each row is
one extracted element with text plus source metadata that an AI pipeline can use
for citation, filtering, chunking, or retrieval.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from logging_utils import configure_script_logging
from unstructured.partition.pdf import partition_pdf

LOGGER = configure_script_logging(__file__)


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [json_safe(item) for item in value]
    return str(value)


def element_type(element: Any) -> str:
    return getattr(element, "category", None) or type(element).__name__


def element_metadata(element: Any) -> dict[str, Any]:
    metadata = getattr(element, "metadata", None)
    if metadata is None:
        return {}
    if hasattr(metadata, "to_dict"):
        return json_safe(metadata.to_dict())
    return json_safe(vars(metadata))


def element_record(element: Any, *, source: Path, index: int, text_chars: int) -> dict[str, Any]:
    text = str(element).strip()
    truncated = len(text) > text_chars
    return {
        "source": str(source),
        "element_index": index,
        "type": element_type(element),
        "text": text[:text_chars],
        "text_truncated": truncated,
        "text_length": len(text),
        "metadata": element_metadata(element),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Partition a PDF with Unstructured and print typed elements."
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
        "--max-elements",
        type=int,
        default=0,
        help="Limit rows printed; 0 means print every element",
    )
    parser.add_argument(
        "--text-chars",
        type=int,
        default=1200,
        help="Maximum text characters to include per element",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Print indented JSON instead of JSONL",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.pdf.exists():
        raise SystemExit(f"PDF not found: {args.pdf}")

    try:
        elements = partition_pdf(
            filename=str(args.pdf),
            strategy=args.strategy,
            infer_table_structure=args.infer_table_structure,
        )
    except Exception as exc:
        print(f"Could not partition PDF with Unstructured: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    records = [
        element_record(element, source=args.pdf, index=index, text_chars=args.text_chars)
        for index, element in enumerate(elements, start=1)
        if str(element).strip()
    ]
    if args.max_elements > 0:
        records = records[: args.max_elements]

    if args.pretty:
        print(json.dumps(records, indent=2))
        return

    for record in records:
        print(json.dumps(record, separators=(",", ":")))


if __name__ == "__main__":
    main()
