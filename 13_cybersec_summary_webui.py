"""
Hello World: Cyber-Security Summary WebUI — GPT-5.5 via Bedrock Mantle
Upload a PDF or enter a URL; GPT-5.5 summarizes key changes in the cyber-security
landscape and streams the result back to the browser.

PDF handling:
  Text is extracted from the PDF locally with Unstructured, falling back to pypdf,
  then sent to GPT-5.5 as text. This avoids the Bedrock Mantle request-body size
  limit that rejects large base64 payloads.

Webpage handling:
  The URL is fetched with requests and converted to clean markdown with markdownify,
  then sent as text.

Architecture:
  GET  /           — self-contained HTML page (file upload + URL input + chat log)
  POST /analyse    — multipart form: file (optional) + url (optional); streams SSE
                       token | done | error events

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python 13_cybersec_summary_webui.py
         Then open http://localhost:8001
"""

import asyncio
import json
from urllib.parse import urlparse

import markdownify
import requests as _requests
import uvicorn
from bs4 import BeautifulSoup
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse
from openai import AsyncBedrockOpenAI

from auth import get_mantle_token
from pdf_utils import extract_pdf_text_from_bytes

REGION = "us-east-2"  # GPT-5.5 / GPT-5.4 both available in us-east-2 (Ohio)
PRIMARY_MODEL = "openai.gpt-5.5"
FALLBACK_MODEL = "openai.gpt-5.4"
REQUEST_TIMEOUT_SECONDS = 45.0
MANTLE_DEFAULT_HEADERS = {"OpenAI-Project": "default"}
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Upgrade-Insecure-Requests": "1",
}


def _url_fetch_headers(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}/" if parsed.scheme and parsed.netloc else url
    return {**BROWSER_HEADERS, "Referer": origin}


def _html_to_markdown(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg"]):
        tag.decompose()
    return markdownify.markdownify(str(soup), heading_style="ATX").strip()


def is_gpt55_outage(exc: BaseException) -> bool:
    """Match the known intermittent Bedrock-side failure mode for GPT-5.5."""
    msg = str(exc).lower()
    return (
        "internal_server_error" in msg
        or "engine not found" in msg
        or "server had an error" in msg
        or "timed out" in msg
        or "timeout" in msg
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


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


async def _run_model(model_id: str, content_blocks: list):
    """Run the summary request, raising on error so the caller can fall back."""
    input_text = "\n\n".join(block["text"] for block in content_blocks)
    async with _make_client() as client:
        response = await client.responses.create(
            model=model_id,
            instructions=SYSTEM_PROMPT,
            input=input_text,
        )
    if response.output_text:
        yield response.output_text


async def _stream_analysis(content_blocks: list):
    """Try GPT-5.5; fall back to GPT-5.4 on known intermittent Bedrock errors."""
    streamed_any = False
    fallback_reason: str | None = None
    try:
        async for text in _run_model(PRIMARY_MODEL, content_blocks):
            streamed_any = True
            yield _sse({"type": "token", "text": text})
    except Exception as exc:
        if streamed_any or not is_gpt55_outage(exc):
            yield _sse({"type": "error", "text": str(exc)})
            return
        fallback_reason = str(exc)

    if not streamed_any and fallback_reason is None:
        fallback_reason = f"{PRIMARY_MODEL} returned an empty stream"

    if fallback_reason is not None:
        yield _sse({"type": "token", "text": f"[notice] {PRIMARY_MODEL} unavailable ({fallback_reason}); retrying with {FALLBACK_MODEL}.\n\n"})
        try:
            async for text in _run_model(FALLBACK_MODEL, content_blocks):
                yield _sse({"type": "token", "text": text})
        except Exception as exc2:
            yield _sse({"type": "error", "text": str(exc2)})
            return
    yield _sse({"type": "done"})


async def _stream_request_analysis(files: list[UploadFile], url: str):
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
            resp = _requests.get(source_url, timeout=25, headers=_url_fetch_headers(source_url))
            resp.raise_for_status()
            return _html_to_markdown(resp.text)

        try:
            md_text = await asyncio.to_thread(fetch_markdown)
            md_text = md_text[:100_000]
        except _requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 403:
                message = (
                    "Could not fetch URL: the site returned HTTP 403 Forbidden. "
                    "It is likely blocking automated fetches. Open the page in a "
                    "browser, save it as PDF, then upload that file instead."
                )
            else:
                message = f"Could not fetch URL: {exc}"
            yield _sse({"type": "error", "text": message})
            return
        except Exception as exc:
            yield _sse({"type": "error", "text": f"Could not fetch URL: {exc}"})
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

    yield _sse({"type": "status", "text": "Running model analysis."})
    async for event in _stream_analysis(content_blocks):
        yield event


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return HTML_PAGE


@app.post("/analyse")
async def analyse(
    files: list[UploadFile] | None = File(default=None),
    url: str = Form(default=""),
) -> StreamingResponse:
    return StreamingResponse(
        _stream_request_analysis(files or [], url),
        media_type="text/event-stream",
    )


# ---------------------------------------------------------------------------
# Self-contained HTML page
# ---------------------------------------------------------------------------

HTML_PAGE = """\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Cyber-Security Summary — GPT-5.5 / 5.4 on Bedrock</title>
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
    label { display: block; font-weight: 700; margin-bottom: 0.4rem; font-size: 0.9rem; }
    input[type="file"], textarea {
      width: 100%; padding: 0.55rem 0.75rem; border: 1px solid #d2d2d7;
      border-radius: 8px; font: inherit; background: #fafafa;
    }
    textarea {
      min-height: 5rem; resize: vertical;
    }
    .divider { text-align: center; color: #8e8e93; font-size: 0.8rem; }
    .actions { display: flex; align-items: center; gap: 0.75rem; margin-top: 1rem; }
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
    #output h1:first-child, #output h2:first-child, #output h3:first-child { margin-top: 0; padding-top: 0; border-top: 0; }
    #output h1 { font-size: 1.35rem; }
    #output h2 { font-size: 1.12rem; }
    #output h3 { font-size: 1rem; }
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
    .spinner { display: inline-block; margin-right: 0.5rem; }
    #status { color: #6e6e73; font-size: 0.85rem; min-height: 1.2em; }
    @media (max-width: 640px) {
      body { margin: 1rem auto; padding: 0 0.75rem; }
      .actions, .result-header { align-items: stretch; flex-direction: column; }
      button { width: 100%; }
    }
  </style>
</head>
<body>
  <h1>Cyber-Security Landscape Summariser</h1>
  <p class="subtitle">Powered by GPT-5.5 (with GPT-5.4 fallback) on AWS Bedrock Mantle</p>

  <div class="card">
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

  <div class="card result-card">
    <div class="result-header">
      <div class="result-title">Analysis</div>
      <div id="source-meta"></div>
    </div>
    <div id="output"></div>
  </div>

<script>
const fileInput    = document.getElementById("file-input");
const urlInput     = document.getElementById("url-input");
const analyseBtn   = document.getElementById("analyse-btn");
const clearBtn     = document.getElementById("clear-btn");
const output       = document.getElementById("output");
const status       = document.getElementById("status");
const sourceMeta   = document.getElementById("source-meta");
let markdownBuffer = "";

function setStatus(msg) { status.textContent = msg; }
function setEnabled(v)  { analyseBtn.disabled = !v; }

function escapeHTML(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderInline(markdown) {
  let html = escapeHTML(markdown);
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  html = html.replace(/\\*\\*([^*]+)\\*\\*/g, "<strong>$1</strong>");
  html = html.replace(/\\[([^\\]]+)\\]\\((https?:\\/\\/[^\\s)]+)\\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  return html;
}

function renderMarkdown(markdown) {
  const lines = markdown.replace(/\\r\\n?/g, "\\n").split("\\n");
  const html = [];
  let paragraph = [];
  let listType = null;
  let inFence = false;
  let fenceLines = [];

  function flushParagraph() {
    if (!paragraph.length) return;
    html.push("<p>" + renderInline(paragraph.join(" ")) + "</p>");
    paragraph = [];
  }

  function closeList() {
    if (!listType) return;
    html.push("</" + listType + ">");
    listType = null;
  }

  function ensureList(type) {
    if (listType === type) return;
    closeList();
    html.push("<" + type + ">");
    listType = type;
  }

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed.startsWith("```")) {
      flushParagraph();
      closeList();
      if (inFence) {
        html.push("<pre><code>" + escapeHTML(fenceLines.join("\\n")) + "</code></pre>");
        fenceLines = [];
      }
      inFence = !inFence;
      continue;
    }

    if (inFence) {
      fenceLines.push(line);
      continue;
    }

    if (!trimmed) {
      flushParagraph();
      closeList();
      continue;
    }

    const heading = trimmed.match(/^(#{1,6})\\s+(.+)$/);
    if (heading) {
      flushParagraph();
      closeList();
      const level = heading[1].length;
      html.push("<h" + level + ">" + renderInline(heading[2]) + "</h" + level + ">");
      continue;
    }

    const ordered = trimmed.match(/^\\d+\\.\\s+(.+)$/);
    if (ordered) {
      flushParagraph();
      ensureList("ol");
      html.push("<li>" + renderInline(ordered[1]) + "</li>");
      continue;
    }

    const unordered = trimmed.match(/^[-*+]\\s+(.+)$/);
    if (unordered) {
      flushParagraph();
      ensureList("ul");
      html.push("<li>" + renderInline(unordered[1]) + "</li>");
      continue;
    }

    closeList();
    paragraph.push(trimmed);
  }

  if (inFence) {
    html.push("<pre><code>" + escapeHTML(fenceLines.join("\\n")) + "</code></pre>");
  }
  flushParagraph();
  closeList();
  return html.join("");
}

function setMarkdown(markdown) {
  markdownBuffer = markdown;
  output.innerHTML = renderMarkdown(markdownBuffer);
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

  try {
    const resp = await fetch("/analyse", { method: "POST", body: form });
    if (!resp.ok) {
      setStatus("Server error: " + resp.status);
      setEnabled(true);
      return;
    }

    const reader  = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\\n\\n");
      buffer = parts.pop();
      for (const part of parts) {
        if (!part.startsWith("data: ")) continue;
        const evt = JSON.parse(part.slice(6));
        if (evt.type === "token") {
          setMarkdown(markdownBuffer + evt.text);
        } else if (evt.type === "status") {
          setStatus(evt.text);
        } else if (evt.type === "error") {
          setStatus("Error: " + evt.text);
        } else if (evt.type === "done") {
          setStatus("Done.");
        }
      }
    }
  } catch (err) {
    setStatus("Network error: " + err.message);
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
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info")
