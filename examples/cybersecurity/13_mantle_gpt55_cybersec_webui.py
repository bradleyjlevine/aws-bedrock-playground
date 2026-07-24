"""
Hello World: Cyber-Security Summary WebUI — OpenAI models via Bedrock Mantle
Upload a PDF or enter a URL; the selected OpenAI model summarizes key changes in
the cyber-security landscape and streams the result back to the browser.

PDF handling:
  Text is extracted from the PDF locally with Unstructured, falling back to pypdf,
  then sent to the selected model as text. This avoids the Bedrock Mantle request-body size
  limit that rejects large base64 payloads.

Webpage handling:
  The URL is fetched through shared SSRF-safe helpers, converted to clean markdown,
  then sent as text.

Architecture:
  GET  /           — self-contained HTML page (file upload + URL input + chat log)
  POST /analyse    — multipart form: file (optional) + url (optional); streams SSE
                       token | status | heartbeat | done | error events

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python examples/cybersecurity/13_mantle_gpt55_cybersec_webui.py
         Then open http://localhost:8001
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from logging_utils import configure_script_logging, install_http_request_logging_middleware

LOGGER = configure_script_logging(__file__)

import asyncio
import json
import os
import random

import uvicorn
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse
from openai import AsyncBedrockOpenAI

from auth import get_mantle_token
from cyber_source_utils import fetch_url_markdown
from pdf_utils import extract_pdf_text_from_bytes
from webui_interactions import WEBUI_INTERACTIONS_JS
from webui_markdown import MARKDOWN_RENDERER_JS
from webui_theme import WEBUI_THEME_CSS

REGION = "us-east-2"  # All picker models are available in us-east-2 (Ohio).
PRIMARY_MODEL = "openai.gpt-5.5"
FALLBACK_MODEL = "openai.gpt-5.4"
MANTLE_MODEL_OPTIONS = (
    ("openai.gpt-5.6-sol", "GPT-5.6 Sol — flagship reasoning"),
    ("openai.gpt-5.6-terra", "GPT-5.6 Terra — balanced"),
    ("openai.gpt-5.6-luna", "GPT-5.6 Luna — fast and economical"),
    ("openai.gpt-5.5", "GPT-5.5 — advanced professional work"),
    ("openai.gpt-5.4", "GPT-5.4 — reliable reasoning"),
)
MANTLE_MODEL_IDS = frozenset(model_id for model_id, _label in MANTLE_MODEL_OPTIONS)
REQUEST_TIMEOUT_SECONDS = float(os.getenv("MANTLE_REQUEST_TIMEOUT_SECONDS", "180"))
PRIMARY_MAX_ATTEMPTS = max(1, int(os.getenv("MANTLE_PRIMARY_MAX_ATTEMPTS", "3")))
FALLBACK_MAX_ATTEMPTS = max(1, int(os.getenv("MANTLE_FALLBACK_MAX_ATTEMPTS", "2")))
RETRY_BASE_SECONDS = max(0.0, float(os.getenv("MANTLE_RETRY_BASE_SECONDS", "1")))
HEARTBEAT_SECONDS = max(1.0, float(os.getenv("MANTLE_HEARTBEAT_SECONDS", "10")))
GRACEFUL_SHUTDOWN_SECONDS = max(
    0.0,
    float(os.getenv("WEBUI_GRACEFUL_SHUTDOWN_SECONDS", "5")),
)
MAX_OUTPUT_TOKENS = max(1, int(os.getenv("MANTLE_MAX_OUTPUT_TOKENS", "4096")))
MANTLE_DEFAULT_HEADERS = {"OpenAI-Project": "default"}


def is_mantle_model_outage(exc: BaseException) -> bool:
    """Match known Bedrock-side model failure modes that allow fallback."""
    msg = str(exc).lower()
    return (
        "internal_server_error" in msg
        or "engine not found" in msg
        or "server had an error" in msg
        or "timed out" in msg
        or "timeout" in msg
    )


def _status_code(exc: BaseException) -> int | None:
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return status
    response = getattr(exc, "response", None)
    response_status = getattr(response, "status_code", None)
    return response_status if isinstance(response_status, int) else None


def _request_id(exc: BaseException) -> str | None:
    request_id = getattr(exc, "request_id", None)
    if request_id:
        return str(request_id)
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None)
    if headers:
        return headers.get("x-request-id") or headers.get("x-amzn-requestid")
    return None


def _is_transient_model_error(exc: BaseException) -> bool:
    """Return whether retrying the same Mantle request is reasonable."""
    status = _status_code(exc)
    if status in {408, 409, 429, 500, 502, 503, 504}:
        return True
    msg = str(exc).lower()
    return any(
        marker in msg
        for marker in (
            "internal_server_error",
            "server had an error",
            "service unavailable",
            "timed out",
            "timeout",
            "connection reset",
        )
    )


async def get_bedrock_token() -> str:
    return get_mantle_token(REGION)


def _make_client() -> AsyncBedrockOpenAI:
    return AsyncBedrockOpenAI(
        aws_region=REGION,
        bedrock_token_provider=get_bedrock_token,
        default_headers=MANTLE_DEFAULT_HEADERS,
        timeout=REQUEST_TIMEOUT_SECONDS,
        max_retries=0,
    )

SYSTEM_PROMPT = (
    "You are a cyber-security analyst. "
    "When given a document or webpage extract, summarize the KEY CHANGES and NOTABLE "
    "DEVELOPMENTS in the cyber-security landscape it describes. "
    "Write clean Markdown with these exact headings:\n"
    "## Executive Summary\n"
    "## Key Threat Trends\n"
    "## Notable Vulnerabilities / Incidents\n"
    "## Defensive Recommendations\n"
    "Use short paragraphs and grouped bullets. Do not number the section headings. "
    "Be concise and use plain language."
)

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI()
install_http_request_logging_middleware(app, LOGGER)


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


class EmptyModelOutput(RuntimeError):
    """Raised when Bedrock returns a valid response without assistant text."""


def _response_text(response) -> str:
    output_text = (getattr(response, "output_text", None) or "").strip()
    if output_text:
        return output_text

    parts: list[str] = []
    for item in getattr(response, "output", []) or []:
        for content in getattr(item, "content", []) or []:
            text = getattr(content, "text", None)
            if text:
                parts.append(str(text))
    return "\n".join(parts).strip()


async def _run_model(model_id: str, content_blocks: list, *, max_attempts: int = 1):
    """Stream a model response and retry transient pre-output failures."""
    input_text = "\n\n".join(block["text"] for block in content_blocks)
    for attempt in range(1, max_attempts + 1):
        streamed_any = False
        output_chars = 0
        LOGGER.info(
            "Calling model=%s attempt=%s/%s input_chars=%s content_blocks=%s "
            "timeout_seconds=%s max_output_tokens=%s",
            model_id,
            attempt,
            max_attempts,
            len(input_text),
            len(content_blocks),
            REQUEST_TIMEOUT_SECONDS,
            MAX_OUTPUT_TOKENS,
        )
        try:
            async with _make_client() as client:
                stream = await client.responses.create(
                    model=model_id,
                    instructions=SYSTEM_PROMPT,
                    input=input_text,
                    max_output_tokens=MAX_OUTPUT_TOKENS,
                    stream=True,
                )
                async for event in stream:
                    if getattr(event, "type", None) != "response.output_text.delta":
                        continue
                    delta = getattr(event, "delta", None)
                    if not delta:
                        continue
                    streamed_any = True
                    output_chars += len(delta)
                    yield delta
            if not streamed_any:
                raise EmptyModelOutput(f"{model_id} returned no assistant text")
            LOGGER.info(
                "Model completed model=%s attempt=%s output_chars=%s",
                model_id,
                attempt,
                output_chars,
            )
            return
        except Exception as exc:
            status = _status_code(exc)
            request_id = _request_id(exc)
            LOGGER.warning(
                "Model request failed model=%s attempt=%s/%s streamed_any=%s "
                "status=%s request_id=%s error_type=%s error=%s",
                model_id,
                attempt,
                max_attempts,
                streamed_any,
                status,
                request_id,
                type(exc).__name__,
                exc,
            )
            if streamed_any or attempt >= max_attempts or not _is_transient_model_error(exc):
                raise
            delay = RETRY_BASE_SECONDS * (2 ** (attempt - 1))
            delay = random.uniform(delay * 0.5, delay * 1.5)
            LOGGER.info(
                "Retrying model=%s after %.2fs attempt=%s/%s",
                model_id,
                delay,
                attempt + 1,
                max_attempts,
            )
            await asyncio.sleep(delay)


async def _with_heartbeats(source):
    """Yield source values and None heartbeats while a model stream is idle."""
    queue: asyncio.Queue[tuple[str, object]] = asyncio.Queue()

    async def produce() -> None:
        try:
            async for value in source:
                await queue.put(("value", value))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await queue.put(("error", exc))
        finally:
            await queue.put(("done", None))

    task = asyncio.create_task(produce())
    try:
        while True:
            try:
                kind, value = await asyncio.wait_for(
                    queue.get(),
                    timeout=HEARTBEAT_SECONDS,
                )
            except TimeoutError:
                yield None
                continue
            if kind == "value":
                yield value
            elif kind == "error":
                raise value
            else:
                return
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def _stream_analysis(content_blocks: list, model_id: str = PRIMARY_MODEL):
    """Run the selected model; fall back to GPT-5.4 after pre-output failures."""
    streamed_any = False
    fallback_reason: str | None = None
    try:
        primary_stream = _run_model(
            model_id,
            content_blocks,
            max_attempts=PRIMARY_MAX_ATTEMPTS,
        )
        async for text in _with_heartbeats(primary_stream):
            if text is None:
                yield _sse({"type": "heartbeat"})
                continue
            streamed_any = True
            yield _sse({"type": "token", "text": text})
    except Exception as exc:
        can_fallback = (
            model_id != FALLBACK_MODEL
            and (isinstance(exc, EmptyModelOutput) or is_mantle_model_outage(exc))
        )
        if streamed_any or not can_fallback:
            yield _sse({"type": "error", "text": str(exc)})
            return
        fallback_reason = str(exc)

    if not streamed_any and fallback_reason is None:
        fallback_reason = f"{model_id} returned an empty stream"

    if fallback_reason is not None:
        yield _sse(
            {
                "type": "token",
                "text": (
                    f"[notice] {model_id} unavailable ({fallback_reason}); "
                    f"retrying with {FALLBACK_MODEL}.\n\n"
                ),
            }
        )
        try:
            fallback_streamed = False
            fallback_stream = _run_model(
                FALLBACK_MODEL,
                content_blocks,
                max_attempts=FALLBACK_MAX_ATTEMPTS,
            )
            async for text in _with_heartbeats(fallback_stream):
                if text is None:
                    yield _sse({"type": "heartbeat"})
                    continue
                fallback_streamed = True
                yield _sse({"type": "token", "text": text})
            if not fallback_streamed:
                yield _sse({"type": "error", "text": f"{FALLBACK_MODEL} returned no assistant text"})
                return
        except Exception as exc2:
            yield _sse({"type": "error", "text": str(exc2)})
            return
    yield _sse({"type": "done"})


async def _stream_request_analysis(
    files: list[UploadFile],
    url: str,
    model_id: str = PRIMARY_MODEL,
):
    """Extract all requested sources inside the SSE stream so progress is visible."""
    content_blocks: list = []
    source_count = 0
    named_files = [file for file in files if file.filename]
    urls = [line.strip() for line in url.splitlines() if line.strip()]
    total_sources = len(named_files) + len(urls)

    if total_sources == 0:
        yield _sse({"type": "error", "text": "Please upload at least one PDF or enter at least one URL."})
        return

    yield _sse({"type": "status", "text": f"Preparing {total_sources} source(s)."})

    for index, file in enumerate(named_files, start=1):
        yield _sse({"type": "status", "text": f"Reading PDF {index}/{len(named_files)}: {file.filename}"})
        pdf_bytes = await file.read()
        if not pdf_bytes:
            yield _sse({"type": "error", "text": f"Uploaded file is empty: {file.filename}"})
            return

        yield _sse({"type": "status", "text": f"Extracting PDF {index}/{len(named_files)}: {file.filename}"})
        try:
            pdf_text = await asyncio.to_thread(extract_pdf_text_from_bytes, pdf_bytes)
        except Exception as exc:
            yield _sse({"type": "error", "text": f"Could not read PDF '{file.filename}': {exc}"})
            return

        if not pdf_text:
            yield _sse({"type": "error", "text": f"No text could be extracted from '{file.filename}'."})
            return

        pdf_text = pdf_text[:120_000]
        source_count += 1
        content_blocks.append(
            {
                "text": (
                    f"## Source {source_count}: PDF - {file.filename}\n\n"
                    f"{pdf_text}\n\n"
                )
            }
        )
        yield _sse({"type": "status", "text": f"Extracted PDF {index}/{len(named_files)}: {file.filename}"})

    for index, source_url in enumerate(urls, start=1):
        yield _sse({"type": "status", "text": f"Fetching URL {index}/{len(urls)}: {source_url}"})

        def fetch_markdown() -> str:
            return fetch_url_markdown(source_url, timeout=25)

        try:
            md_text = await asyncio.to_thread(fetch_markdown)
            md_text = md_text[:100_000]
        except ValueError as exc:
            message = f"Could not fetch URL: {exc}"
            yield _sse({"type": "error", "text": message})
            return
        except Exception as exc:
            message = f"Could not fetch URL: {exc}"
            yield _sse({"type": "error", "text": message})
            return

        source_count += 1
        content_blocks.append(
            {
                "text": (
                    f"## Source {source_count}: URL - {source_url}\n\n"
                    f"{md_text}\n\n"
                )
            }
        )

    content_blocks.append(
        {
            "text": (
                "Analyze all sources together. Keep source attribution clear by referring "
                "to source names or URLs when discussing specific facts."
            )
        }
    )

    yield _sse({"type": "status", "text": f"Running analysis with {model_id}."})
    async for event in _stream_analysis(content_blocks, model_id):
        yield event


async def _safe_stream_request_analysis(
    files: list[UploadFile],
    url: str,
    model_id: str = PRIMARY_MODEL,
):
    sent_done = False
    try:
        async for event in _stream_request_analysis(files, url, model_id):
            if '"type": "done"' in event:
                sent_done = True
            yield event
    except asyncio.CancelledError:
        LOGGER.info("Analysis stream cancelled during server shutdown or client disconnect")
        raise
    except Exception as exc:
        yield _sse({"type": "error", "text": f"Unexpected server error: {exc}"})
    if not sent_done:
        yield _sse({"type": "done"})


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return HTML_PAGE


@app.post("/analyse")
async def analyse(
    files: list[UploadFile] | None = File(default=None),
    url: str = Form(default=""),
    model: str = Form(default=PRIMARY_MODEL),
) -> StreamingResponse:
    if model not in MANTLE_MODEL_IDS:
        raise HTTPException(status_code=400, detail="Unsupported Mantle model")
    return StreamingResponse(
        _safe_stream_request_analysis(files or [], url, model),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Self-contained HTML page
# ---------------------------------------------------------------------------

HTML_PAGE = """\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='14' fill='%230066cc'/><path d='M18 43h28M22 35l7-8 7 5 8-12' fill='none' stroke='white' stroke-width='5' stroke-linecap='round' stroke-linejoin='round'/></svg>">
  <title>Cyber-Security Summary — OpenAI models on Bedrock</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      max-width: 980px; margin: 2rem auto; padding: 0 1.25rem; color: #1d1d1f;
      background: #f5f5f7;
    }
    h1 { font-size: 1.5rem; margin-bottom: 0.25rem; letter-spacing: 0; }
    .subtitle { color: #6e6e73; font-size: 0.9rem; margin-bottom: 1.5rem; }
    .card {
      background: #fff; border: 1px solid #d2d2d7; border-radius: 8px;
      padding: 1.25rem; margin-bottom: 1rem;
    }
    .input-grid { display: grid; gap: 1rem; }
    label, .field-label { display: block; font-weight: 700; margin-bottom: 0.4rem; font-size: 0.9rem; }
    input[type="file"], textarea {
      width: 100%; padding: 0.55rem 0.75rem; border: 1px solid #d2d2d7;
      border-radius: 8px; font: inherit; background: #fafafa;
    }
    textarea {
      min-height: 5rem; resize: vertical;
    }
    .divider { text-align: center; color: #8e8e93; font-size: 0.8rem; }
    .actions { display: flex; align-items: center; gap: 0.75rem; margin-top: 1rem; }
    .model-picker {
      position: relative;
      margin: 0;
    }
    .model-picker summary {
      display: flex;
      min-height: 42px;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      width: 100%;
      padding: 0.62rem 0.78rem;
      border: 1px solid #d1d1d6;
      border-radius: 10px;
      background: #fafafa;
      color: #1d1d1f;
      cursor: pointer;
      font-size: 1rem;
      line-height: 1.25;
      list-style: none;
    }
    .model-picker summary::-webkit-details-marker { display: none; }
    .model-picker summary::after {
      content: "⌄";
      color: #56647a;
      font-size: 1.15rem;
      line-height: 1;
      transform: translateY(-0.12rem);
      transition: transform 140ms ease;
    }
    .model-picker[open] summary::after {
      transform: rotate(180deg) translateY(0.12rem);
    }
    .model-picker summary:focus-visible {
      outline: 3px solid rgba(23, 107, 135, 0.28);
      outline-offset: 2px;
    }
    .model-menu {
      position: absolute;
      z-index: 20;
      top: calc(100% + 6px);
      left: 0;
      width: 100%;
      padding: 6px;
      border: 1px solid #cbd6e4;
      border-radius: 12px;
      background: #fff;
      box-shadow: 0 18px 42px rgba(22, 35, 58, 0.18);
    }
    .webui-shell button.model-option {
      display: grid;
      grid-template-columns: 1.25rem minmax(0, 1fr);
      gap: 0.5rem;
      width: 100%;
      min-height: 42px;
      padding: 0.62rem 0.7rem;
      border: 0;
      border-radius: 8px;
      background: transparent !important;
      color: #314158;
      cursor: pointer;
      font-size: 0.94rem;
      font-weight: 650;
      line-height: 1.3;
      text-align: left;
    }
    .webui-shell button.model-option::before {
      content: "";
      color: var(--ui-accent-deep);
      font-weight: 800;
    }
    .webui-shell button.model-option[aria-selected="true"]::before {
      content: "✓";
    }
    .webui-shell button.model-option:hover,
    .webui-shell button.model-option:focus-visible,
    .webui-shell button.model-option[aria-selected="true"] {
      background: #e8f1f6 !important;
      color: #16233a;
    }
    .model-picker[data-disabled="true"] summary {
      cursor: wait;
      opacity: 0.58;
    }
    button {
      padding: 0.6rem 1.2rem; border: 0; border-radius: 8px;
      background: #0066cc; color: #fff; font: inherit; font-weight: 600;
      cursor: pointer; flex-shrink: 0;
    }
    button:disabled { background: #aaa; cursor: not-allowed; }
    button.secondary {
      background: #f2f2f7; color: #1d1d1f; border: 1px solid #d2d2d7;
    }
    .result-card { padding: 0; overflow: hidden; }
    .result-header {
      display: flex; align-items: center; justify-content: space-between; gap: 1rem;
      padding: 0.9rem 1.25rem; border-bottom: 1px solid #e5e5ea; background: #fbfbfd;
    }
    .result-title { font-weight: 700; }
    #source-meta { color: #6e6e73; font-size: 0.85rem; overflow-wrap: anywhere; }
    #output {
      min-height: 120px; line-height: 1.6; padding: 1.25rem;
      font-size: 0.95rem;
    }
    #output:empty::before { content: "Result will appear here…"; color: #8e8e93; }
    #output h1, #output h2, #output h3, #output h4, #output h5, #output h6 {
      margin: 1.4rem 0 0.55rem; line-height: 1.25; letter-spacing: 0;
      padding-top: 0.85rem; border-top: 1px solid #ececf1;
    }
    #output h1:first-child, #output h2:first-child, #output h3:first-child,
    #output h4:first-child, #output h5:first-child, #output h6:first-child { margin-top: 0; padding-top: 0; border-top: 0; }
    #output h1 { font-size: 1.35rem; }
    #output h2 { font-size: 1.12rem; }
    #output h3 { font-size: 1rem; }
    #output h4 { font-size: 0.96rem; }
    #output h5 { font-size: 0.92rem; }
    #output h6 { font-size: 0.9rem; color: #6e6e73; }
    #output p { margin: 0.45rem 0 0.85rem; }
    #output ul, #output ol { margin: 0.35rem 0 1rem; padding-left: 1.5rem; }
    #output li { margin: 0.35rem 0; }
    #output code {
      background: #f2f2f7; border: 1px solid #e5e5ea; border-radius: 4px;
      padding: 0.05rem 0.25rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.9em;
    }
    #output pre {
      overflow-x: auto; background: #f2f2f7; border: 1px solid #e5e5ea;
      border-radius: 8px; padding: 0.75rem;
    }
    #output pre code { background: transparent; border: 0; padding: 0; }
    #output table {
      width: 100%;
      border-collapse: collapse;
      margin: 0.75rem 0;
      font-size: 0.92rem;
      display: block;
      overflow-x: auto;
    }
    #output th, #output td {
      border: 1px solid #d2d2d7;
      padding: 0.45rem 0.55rem;
      text-align: left;
      vertical-align: top;
    }
    #output th { background: #f2f2f7; }
    #output hr { border: 0; border-top: 1px solid #d2d2d7; margin: 1rem 0; }
    #output blockquote {
      margin: 0.7rem 0; padding: 0.25rem 0 0.25rem 0.85rem;
      border-left: 3px solid #d2d2d7; color: #5f6b7a;
    }
    #output del { color: #6e6e73; }
    #output input[type="checkbox"] { margin-right: 0.35rem; vertical-align: -0.1rem; }
    .spinner { display: inline-block; margin-right: 0.5rem; }
    #status { color: #6e6e73; font-size: 0.85rem; min-height: 1.2em; }
    @media (max-width: 640px) {
      body { margin: 1rem auto; padding: 0 0.75rem; }
      .actions, .result-header { align-items: stretch; flex-direction: column; }
      button { width: 100%; }
    }
""" + WEBUI_THEME_CSS + """
  </style>
</head>
<body class="webui-shell">
<main class="ui-shell">
  <header class="ui-header">
    <div>
      <p class="ui-eyebrow">Security analysis / Bedrock Mantle</p>
      <h1>Cyber-security landscape summariser</h1>
      <p class="subtitle ui-subtitle">Turn PDFs and public reports into a structured security briefing with your choice of OpenAI model on Bedrock Mantle.</p>
    </div>
  </header>

  <div class="card ui-panel">
        <div class="field-label" id="model-label">OpenAI model</div>
        <details class="model-picker" id="model-picker">
          <summary aria-labelledby="model-label model-summary">
            <span id="model-summary">GPT-5.5 — advanced professional work</span>
          </summary>
          <div class="model-menu" role="listbox" aria-labelledby="model-label">
            <button type="button" class="model-option" role="option" aria-selected="false" data-model="openai.gpt-5.6-sol">GPT-5.6 Sol — flagship reasoning</button>
            <button type="button" class="model-option" role="option" aria-selected="false" data-model="openai.gpt-5.6-terra">GPT-5.6 Terra — balanced</button>
            <button type="button" class="model-option" role="option" aria-selected="false" data-model="openai.gpt-5.6-luna">GPT-5.6 Luna — fast and economical</button>
            <button type="button" class="model-option" role="option" aria-selected="true" data-model="openai.gpt-5.5">GPT-5.5 — advanced professional work</button>
            <button type="button" class="model-option" role="option" aria-selected="false" data-model="openai.gpt-5.4">GPT-5.4 — reliable reasoning</button>
          </div>
        </details>
        <input type="hidden" id="model-input" value="openai.gpt-5.5">
        <div class="hint">All choices use the Bedrock Mantle Responses API in us-east-2.</div>
    <div class="input-grid">
      <div>
        <label for="file-input">Upload PDFs</label>
        <input type="file" id="file-input" accept=".pdf" multiple>
      </div>
      <div class="divider">— or —</div>
      <div>
        <label for="url-input">Enter webpage URLs</label>
        <textarea id="url-input" placeholder="https://nvd.nist.gov/…&#10;https://example.com/report"></textarea>
      </div>
    </div>
    <div class="actions">
      <button id="analyse-btn">Analyse</button>
      <button id="clear-btn" class="secondary">Clear</button>
      <div id="status"></div>
    </div>
  </div>

  <div class="card result-card ui-panel">
    <div class="result-header">
      <div class="result-title">Analysis</div>
      <div id="source-meta"></div>
    </div>
    <div id="output"></div>
  </div>
</main>

<script>
""" + MARKDOWN_RENDERER_JS + """
""" + WEBUI_INTERACTIONS_JS + """
const fileInput    = document.getElementById("file-input");
const urlInput     = document.getElementById("url-input");
const modelInput   = document.getElementById("model-input");
const modelPicker  = document.getElementById("model-picker");
const modelSummary = document.getElementById("model-summary");
const modelOptions = [...document.querySelectorAll(".model-option")];
const analyseBtn   = document.getElementById("analyse-btn");
const clearBtn     = document.getElementById("clear-btn");
const output       = document.getElementById("output");
const status       = document.getElementById("status");
const sourceMeta   = document.getElementById("source-meta");
let markdownBuffer = "";

function setStatus(msg) { status.textContent = msg; }
function setEnabled(v)  {
  analyseBtn.disabled = !v;
  modelPicker.dataset.disabled = String(!v);
  modelPicker.querySelector("summary").setAttribute("aria-disabled", String(!v));
  modelOptions.forEach(option => { option.disabled = !v; });
  if (!v) modelPicker.open = false;
}

modelOptions.forEach(option => {
  option.addEventListener("click", event => {
    event.preventDefault();
    event.stopPropagation();
    modelInput.value = option.dataset.model;
    modelSummary.textContent = option.textContent.trim();
    modelOptions.forEach(candidate => {
      candidate.setAttribute("aria-selected", String(candidate === option));
    });
    setTimeout(() => { modelPicker.open = false; }, 0);
  });
});

modelPicker.addEventListener("toggle", () => {
  if (modelPicker.dataset.disabled === "true") modelPicker.open = false;
});

document.addEventListener("click", event => {
  if (!modelPicker.contains(event.target)) modelPicker.open = false;
});

document.addEventListener("keydown", event => {
  if (event.key === "Escape") modelPicker.open = false;
});

function setMarkdown(markdown) {
  markdownBuffer = markdown;
  WebUI.renderMarkdown(null, output, markdownBuffer);
}

function setSourceMeta(files, urls) {
  const names = [];
  for (const file of files || []) names.push(file.name);
  for (const item of urls || []) names.push(item);
  if (names.length) {
    sourceMeta.textContent = names.join(" · ");
  } else {
    sourceMeta.textContent = "";
  }
}

clearBtn.addEventListener("click", () => {
  fileInput.value = "";
  urlInput.value  = "";
  setMarkdown("");
  setSourceMeta([], []);
  setStatus("");
});

analyseBtn.addEventListener("click", async () => {
  if (window.location.protocol === "file:") {
    setStatus("Open this app from http://localhost:8001, not as a local file.");
    return;
  }

  const files = Array.from(fileInput.files || []);
  const urls  = urlInput.value.split(/\\r?\\n/).map(v => v.trim()).filter(Boolean);

  if (!files.length && !urls.length) {
    setStatus("Please upload at least one PDF or enter at least one URL.");
    return;
  }

  setMarkdown("");
  setSourceMeta(files, urls);
  setEnabled(false);
  setStatus("Analysing…");

  const form = new FormData();
  for (const file of files) form.append("files", file);
  if (urls.length) form.append("url", urls.join("\\n"));
  form.append("model", modelInput.value);

  try {
    let resp;
    try {
      resp = await fetch("/analyse", {
        method: "POST",
        body: form,
        headers: { "Accept": "text/event-stream" },
      });
    } catch (err) {
      setStatus("Could not reach the FastAPI server. Make sure examples/cybersecurity/13_mantle_gpt55_cybersec_webui.py is still running on http://localhost:8001.");
      return;
    }

    if (!resp.ok) {
      setStatus("Server error: " + resp.status);
      setEnabled(true);
      return;
    }
    if (!resp.body) {
      setStatus("Server did not return a readable response stream.");
      return;
    }

    let sawOutput = false;
    let sawError = false;

    for await (const evt of WebUI.events(resp)) {
        if (evt.type === "token") {
          setMarkdown(markdownBuffer + evt.text);
          if ((evt.text || "").trim()) sawOutput = true;
        } else if (evt.type === "status") {
          if (!sawError) setStatus(evt.text);
        } else if (evt.type === "error") {
          sawError = true;
          setStatus("Error: " + evt.text);
        } else if (evt.type === "done") {
          if (!sawError && sawOutput) {
            setStatus("Done.");
          } else if (!sawError) {
            setStatus("Done, but the model returned no visible output. Check logs/13_mantle_gpt55_cybersec_webui.log.");
          }
        }
    }
  } catch (err) {
    setStatus("Browser error: " + err.message);
  } finally {
    setEnabled(true);
  }
});
</script>
</body>
</html>
"""


if __name__ == "__main__":
    print("Open http://localhost:8001 in your browser.")
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8001,
        log_level="debug",
        log_config=None,
        access_log=True,
        timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS,
    )
