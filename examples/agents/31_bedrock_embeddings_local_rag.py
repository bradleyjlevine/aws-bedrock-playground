"""
Hello World: Bedrock embeddings + local RAG

Reads local Markdown/text files, chunks them, embeds chunks with Amazon Titan Text
Embeddings V2, ranks chunks in memory with cosine similarity, then answers with
Bedrock Converse using source citations.

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python examples/agents/31_bedrock_embeddings_local_rag.py --question "What does this repo demonstrate?"
         uv run python examples/agents/31_bedrock_embeddings_local_rag.py --path README.md --path AGENTS.md --question "How do I run WebUI checks?"

Set BEDROCK_MODEL_ID to change the answer model.
Set BEDROCK_EMBEDDING_MODEL_ID to change the embedding model.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)
import argparse
import json
import math
import os
from dataclasses import dataclass
from typing import Iterable

import boto3
from botocore.config import Config as BotocoreConfig

REGION = "us-east-1"
ANSWER_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
)
EMBEDDING_MODEL_ID = os.environ.get(
    "BEDROCK_EMBEDDING_MODEL_ID",
    "amazon.titan-embed-text-v2:0",
)
DEFAULT_PATHS = [ROOT / "README.md", ROOT / "AGENTS.md"]
SUPPORTED_SUFFIXES = {".md", ".markdown", ".txt"}


@dataclass(frozen=True)
class SourceChunk:
    source_id: str
    path: Path
    index: int
    text: str


@dataclass(frozen=True)
class RankedChunk:
    chunk: SourceChunk
    score: float


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--path",
        action="append",
        type=Path,
        help="Markdown/text file or directory to index. Can be repeated. Defaults to README.md and AGENTS.md.",
    )
    parser.add_argument(
        "--question",
        default="What does this repository demonstrate?",
        help="Question to answer from the local documents.",
    )
    parser.add_argument("--top-k", type=int, default=5, help="Number of chunks to pass to the answer model.")
    parser.add_argument("--chunk-chars", type=int, default=1_200, help="Approximate maximum characters per chunk.")
    parser.add_argument("--max-chunks", type=int, default=80, help="Maximum chunks to embed for the demo run.")
    parser.add_argument("--dimensions", type=int, default=512, choices=[256, 512, 1024])
    parser.add_argument("--dry-run", action="store_true", help="Load and chunk documents without calling Bedrock.")
    return parser.parse_args()


def iter_files(paths: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    for raw_path in paths:
        path = raw_path.expanduser()
        if not path.is_absolute():
            path = ROOT / path
        if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES:
            files.append(path)
        elif path.is_dir():
            files.extend(
                file
                for file in sorted(path.rglob("*"))
                if file.is_file() and file.suffix.lower() in SUPPORTED_SUFFIXES
            )
        else:
            print(f"Skipping unsupported path: {raw_path}", file=sys.stderr)
    return sorted(dict.fromkeys(files))


def split_text(text: str, max_chars: int) -> list[str]:
    paragraphs = [paragraph.strip() for paragraph in text.split("\n\n") if paragraph.strip()]
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0
    for paragraph in paragraphs:
        if current and current_len + len(paragraph) + 2 > max_chars:
            chunks.append("\n\n".join(current))
            current = []
            current_len = 0
        if len(paragraph) > max_chars:
            for start in range(0, len(paragraph), max_chars):
                part = paragraph[start : start + max_chars].strip()
                if part:
                    chunks.append(part)
            continue
        current.append(paragraph)
        current_len += len(paragraph) + 2
    if current:
        chunks.append("\n\n".join(current))
    return chunks


def load_chunks(paths: Iterable[Path], chunk_chars: int, max_chunks: int) -> list[SourceChunk]:
    chunks: list[SourceChunk] = []
    for path in iter_files(paths):
        text = path.read_text(encoding="utf-8", errors="replace")
        for chunk_text in split_text(text, chunk_chars):
            source_id = f"S{len(chunks) + 1}"
            chunks.append(
                SourceChunk(
                    source_id=source_id,
                    path=path.relative_to(ROOT) if path.is_relative_to(ROOT) else path,
                    index=len(chunks),
                    text=chunk_text,
                )
            )
            if len(chunks) >= max_chunks:
                return chunks
    return chunks


def bedrock_client():
    profile = os.environ.get("AWS_PROFILE")
    session = boto3.Session(profile_name=profile, region_name=REGION)
    return session.client(
        "bedrock-runtime",
        config=BotocoreConfig(retries={"max_attempts": 3, "mode": "standard"}),
    )


def embed_text(client, text: str, dimensions: int) -> list[float]:
    body = json.dumps(
        {
            "inputText": text,
            "dimensions": dimensions,
            "normalize": True,
        }
    )
    response = client.invoke_model(
        body=body,
        modelId=EMBEDDING_MODEL_ID,
        accept="application/json",
        contentType="application/json",
    )
    payload = json.loads(response["body"].read())
    return payload["embedding"]


def cosine_similarity(left: list[float], right: list[float]) -> float:
    numerator = sum(a * b for a, b in zip(left, right, strict=False))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if not left_norm or not right_norm:
        return 0.0
    return numerator / (left_norm * right_norm)


def retrieve(client, chunks: list[SourceChunk], question: str, top_k: int, dimensions: int) -> list[RankedChunk]:
    question_embedding = embed_text(client, question, dimensions)
    ranked: list[RankedChunk] = []
    for chunk in chunks:
        chunk_embedding = embed_text(client, chunk.text, dimensions)
        ranked.append(RankedChunk(chunk=chunk, score=cosine_similarity(question_embedding, chunk_embedding)))
    return sorted(ranked, key=lambda item: item.score, reverse=True)[:top_k]


def build_context(ranked_chunks: list[RankedChunk]) -> str:
    blocks = []
    for ranked in ranked_chunks:
        chunk = ranked.chunk
        blocks.append(
            f"[{chunk.source_id}] {chunk.path} chunk {chunk.index + 1} "
            f"(similarity={ranked.score:.3f})\n{chunk.text}"
        )
    return "\n\n---\n\n".join(blocks)


def answer_question(client, question: str, ranked_chunks: list[RankedChunk]) -> str:
    context = build_context(ranked_chunks)
    prompt = (
        "Answer the question using only the source excerpts below. "
        "Cite sources inline with their bracketed source IDs such as [S1]. "
        "If the excerpts do not answer the question, say what is missing.\n\n"
        f"Question: {question}\n\n"
        f"Sources:\n{context}"
    )
    response = client.converse(
        modelId=ANSWER_MODEL_ID,
        messages=[{"role": "user", "content": [{"text": prompt}]}],
        inferenceConfig={"maxTokens": 700, "temperature": 0.2},
    )
    return response["output"]["message"]["content"][0]["text"]


def main() -> None:
    args = parse_args()
    paths = args.path or DEFAULT_PATHS
    chunks = load_chunks(paths, args.chunk_chars, args.max_chunks)
    if not chunks:
        raise SystemExit("No Markdown or text chunks found.")

    print(f"Loaded {len(chunks)} chunks from {len(set(chunk.path for chunk in chunks))} file(s).")
    if args.dry_run:
        for chunk in chunks[: min(args.top_k, len(chunks))]:
            preview = " ".join(chunk.text.split())[:160]
            print(f"[{chunk.source_id}] {chunk.path} chunk {chunk.index + 1}: {preview}...")
        return

    client = bedrock_client()
    ranked = retrieve(client, chunks, args.question, args.top_k, args.dimensions)
    print("\nTop retrieved chunks:")
    for item in ranked:
        print(f"- [{item.chunk.source_id}] {item.chunk.path} chunk {item.chunk.index + 1}: {item.score:.3f}")

    print("\nAnswer:\n")
    print(answer_question(client, args.question, ranked))


if __name__ == "__main__":
    main()
