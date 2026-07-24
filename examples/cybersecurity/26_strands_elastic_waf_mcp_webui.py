"""
Hello World: Strands + Elastic Agent Builder MCP WAF WebUI
FastAPI + SSE browser chat for WAF / web-attack questions. The Strands agent
uses AWS Bedrock for reasoning and Elastic Agent Builder's MCP server for WAF
log search, attack-pattern discovery, and attack timeline reconstruction.

Elastic setup:
  1. Create Agent Builder tools in Kibana for your WAF logs, or expose the
     built-in tools through the Agent Builder MCP server.
  2. Create an API key with Kibana privileges:
       feature_agentBuilder.read, feature_actions.read
     and read/view_index_metadata privileges for the WAF log indices.
  3. Export either:
       ELASTIC_AGENT_BUILDER_MCP_URL=https://.../api/agent_builder/mcp
     or:
       ELASTIC_KIBANA_URL=https://...
       ELASTIC_KIBANA_SPACE=default        # optional
     plus one of:
       ELASTIC_API_KEY=...
       ELASTIC_AUTH_HEADER="ApiKey ..."

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python examples/cybersecurity/26_strands_elastic_waf_mcp_webui.py
         Then open http://localhost:8002
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
from contextlib import asynccontextmanager
from contextlib import ExitStack

import boto3
import uvicorn
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client
from strands import Agent
from strands.models import BedrockModel
from strands.tools.mcp import MCPClient

from cyber_source_utils import fetch_url_markdown
from pdf_utils import extract_pdf_text_from_bytes
from webui_interactions import WEBUI_INTERACTIONS_JS
from webui_markdown import MARKDOWN_RENDERER_JS
from webui_theme import WEBUI_THEME_CSS

REGION = os.environ.get("AWS_REGION", "us-east-1")
MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
)
REQUEST_TIMEOUT_SECONDS = 30
MAX_SOURCE_CHARS = 120_000
MAX_HISTORY_TURNS = 6
MAX_HISTORY_CHARS = 12_000
WAF_DATA_CONTEXT = os.environ.get(
    "ELASTIC_WAF_DATA_CONTEXT",
    (
        "For this demo, AWS WAF logs are the expected starting point, but real "
        "Elastic environments may contain related datasets such as CDN, ALB, "
        "CloudFront, ingress, application, endpoint, or threat intelligence data. "
        "Start by looking for AWS WAF indices or data streams such as aws.waf*, "
        "logs-aws.waf*, logs-aws_waf*, filebeat-*, or indices whose mappings "
        "include fields like aws.waf.*, cloud.account.id, source.ip, "
        "http.request.*, url.path, user_agent.original, rule.id, rule.name, "
        "aws.waf.labels.name, labels, event.action, event.outcome, action, "
        "terminatingRuleId, or webacl. For attack type classification, first check "
        "aws.waf.labels.name because AWS WAF labels usually carry the clearest "
        "managed-rule attack category or signature context; fall back to rule.id "
        "and rule.name when labels are missing, sparse, or too generic. For "
        "allowed/blocked disposition, first check ECS fields event.action and "
        "event.outcome, then confirm or enrich with WAF-specific fields such as "
        "action or terminatingRuleId when those fields exist. If the user's "
        "question requires context beyond WAF events, discover and use the "
        "relevant related datasets as supporting evidence."
    ),
)

SYSTEM_PROMPT = """
You are a senior web-application security analyst investigating WAF and web
attack telemetry in Elastic Cloud.

You have access to Elastic Agent Builder MCP tools. Prefer those tools for WAF
log questions. Useful tool families may include:
- platform.core.index_explorer and platform.core.list_indices for finding WAF
  indices and mappings.
- platform.core.get_index_mapping for confirming AWS WAF fields before writing
  queries.
- platform.core.generate_esql for drafting ES|QL after you know the likely
  AWS WAF index/data stream and field names.
- platform.core.execute_esql for precise aggregations such as top attackers,
  top paths, top terminating rules, top labels, action counts, country counts,
  time-series spikes, repeated attack-pattern clusters, and timeline buckets.
- platform.core.search for exploratory natural-language search over AWS WAF
  logs when the user asks a broad question.
- platform.core.integration_knowledge and platform.core.product_documentation
  when AWS WAF integration field semantics or Elastic query syntax are unclear.
- Any custom Agent Builder tools the user configured for WAF, CDN, ALB, CloudFront,
  or application security logs.

Work in this order:
1. Understand the user's WAF / web-attack question.
2. Discover candidate AWS WAF indices/data streams with platform.core.list_indices
   or platform.core.index_explorer. Do not assume the index name.
3. Inspect mappings with platform.core.get_index_mapping when field names are
   needed for an aggregation.
4. Use platform.core.generate_esql or platform.core.execute_esql for the actual
   WAF log analysis. Give generate_esql the discovered index and relevant field
   context; do not rely on it to infer everything from scratch.
5. For attack-pattern or timeline questions, run grouped/time-bucketed analysis
   that can reveal repeated source IPs/networks, countries, user agents, URI
   paths, HTTP methods, payload keywords, WAF labels, terminating rules, actions,
   response statuses, and spike windows. Prefer ES|QL STATS by time bucket and
   by attacker/path/rule dimensions when the mapped fields support it.
6. Summarize what indices, fields, and time range you searched, then explain the
   high-level evidence and what it means.

For attack type classification, check `aws.waf.labels.name` first and group by
that field when it is present. Use it as the primary source for categories such
as SQL injection, XSS, command injection, scanner/probe, known bad input, bot,
or managed-rule signature families. If `aws.waf.labels.name` is absent,
unmapped, or too generic, fall back to `rule.id` and then `rule.name` for the
best available attack-type signal. If you fall back, say so explicitly.

For allow/block status, treat ECS `event.action` and `event.outcome` as the
general normalized fields to check first. Use them for allowed vs blocked counts
when mappings show they are populated. If WAF-specific fields are present, such
as `action`, `terminatingRuleId`, `aws.waf.action`, or `aws.waf.terminating_rule_id`,
use them to confirm the ECS interpretation and add rule-level detail. If these
fields disagree or one family is missing, say exactly which fields were available
and which one drove the conclusion.

When the user asks broad questions such as "what attacks are happening",
"find patterns", "build a timeline", "what happened", "are we being probed",
or "is this a campaign", proactively look for:
- Attack patterns: repeated indicators or behavior clusters across source IP,
  ASN/network if available, country, user agent, URI/path, method, query/payload
  fragments, `aws.waf.labels.name`, `rule.id`, terminating rule, ECS event
  action/outcome, WAF action, and target host/application.
- Timeline: first seen, last seen, volume by time bucket, notable spikes, changes
  in targets or techniques, and whether events appear to progress from scanning
  to exploit attempts to blocked/allowed requests.
- Evidence quality: exact fields used, row counts or aggregate counts, time
  range searched, and missing fields that limit attribution.

For attack-pattern or timeline answers, use these sections when they fit:
## Scope Checked
## Attack Patterns
## Attack Timeline
## Notable Attackers or Targets
## Evidence Gaps
## Defensive Actions

For requests involving a threat report PDF or web page, compare the report's
indicators, paths, payload patterns, CVEs, user agents, source networks, and
TTPs against WAF logs. If the user asks for new WAF rules, propose concrete
rule ideas and explain which observed evidence or report behavior motivates
each rule. Do not claim that a rule is deployed unless the tools show it.

Be explicit when data is missing or when index/field names are assumptions.
Keep the answer concise and operational.

During tool use, write short progress updates as separate paragraphs, for example
"I found candidate WAF indices and will inspect mappings next." Do not expose
private chain-of-thought. Report only observable actions, tool results, and
high-level reasoning that helps the user follow the investigation.
"""

@asynccontextmanager
async def lifespan(_app: FastAPI):
    LOGGER.info(
        "FastAPI startup complete model_id=%s region=%s elastic_mcp_url_configured=%s",
        MODEL_ID,
        REGION,
        bool(_elastic_mcp_url()),
    )
    yield


app = FastAPI(lifespan=lifespan)


install_http_request_logging_middleware(app, LOGGER)


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


def _parse_history(raw_history: str) -> list[dict[str, str]]:
    if not raw_history.strip():
        return []
    try:
        records = json.loads(raw_history)
    except json.JSONDecodeError:
        return []
    if not isinstance(records, list):
        return []

    history: list[dict[str, str]] = []
    total_chars = 0
    for record in records[-MAX_HISTORY_TURNS * 2:]:
        if not isinstance(record, dict):
            continue
        role = str(record.get("role", "")).strip().lower()
        if role not in {"user", "assistant"}:
            continue
        content = str(record.get("content", "")).strip()
        if not content:
            continue
        remaining = MAX_HISTORY_CHARS - total_chars
        if remaining <= 0:
            break
        content = content[:remaining]
        total_chars += len(content)
        history.append({"role": role, "content": content})
    return history


def _format_history(history: list[dict[str, str]]) -> str:
    sections = []
    for item in history:
        label = "User" if item["role"] == "user" else "Assistant"
        sections.append(f"{label}:\n{item['content']}")
    return "\n\n---\n\n".join(sections)


def _tool_use_name_from_stream_event(event: dict) -> str:
    """Return the tool name from known Strands stream event shapes."""
    raw = event.get("event", {}) if isinstance(event, dict) else {}
    candidates = [
        raw.get("contentBlockStart", {}).get("start", {}).get("toolUse", {}),
        raw.get("contentBlockDelta", {}).get("delta", {}).get("toolUse", {}),
        raw.get("toolUse", {}),
        raw.get("tool_use", {}),
        event.get("toolUse", {}) if isinstance(event, dict) else {},
        event.get("tool_use", {}) if isinstance(event, dict) else {},
    ]
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        name = candidate.get("name") or candidate.get("toolName") or candidate.get("tool_name")
        if name:
            return str(name)

    for key in ("tool_name", "toolName", "name"):
        value = event.get(key) if isinstance(event, dict) else None
        if isinstance(value, str) and value.startswith("platform."):
            return value
    return ""


def _elastic_mcp_url() -> str:
    explicit = os.environ.get("ELASTIC_AGENT_BUILDER_MCP_URL", "").strip()
    if explicit:
        return explicit

    kibana_url = os.environ.get("ELASTIC_KIBANA_URL", "").strip().rstrip("/")
    if not kibana_url:
        return ""

    space = os.environ.get("ELASTIC_KIBANA_SPACE", "").strip()
    if space and space != "default":
        return f"{kibana_url}/s/{space}/api/agent_builder/mcp"
    return f"{kibana_url}/api/agent_builder/mcp"


def _elastic_auth_header() -> str:
    explicit = os.environ.get("ELASTIC_AUTH_HEADER", "").strip()
    if explicit:
        return explicit

    api_key = os.environ.get("ELASTIC_API_KEY", "").strip()
    if api_key:
        return f"ApiKey {api_key}"
    return ""


def _make_elastic_mcp_client() -> MCPClient:
    url = _elastic_mcp_url()
    auth_header = _elastic_auth_header()
    if not url:
        raise RuntimeError(
            "Set ELASTIC_AGENT_BUILDER_MCP_URL or ELASTIC_KIBANA_URL before running this app."
        )
    if not auth_header:
        raise RuntimeError("Set ELASTIC_API_KEY or ELASTIC_AUTH_HEADER before running this app.")

    @asynccontextmanager
    async def elastic_transport():
        async with create_mcp_http_client(headers={"Authorization": auth_header}) as http_client:
            async with streamable_http_client(url=url, http_client=http_client) as streams:
                yield streams

    LOGGER.debug("Configuring Elastic Agent Builder MCP client for %s", url)
    return MCPClient(elastic_transport, startup_timeout=REQUEST_TIMEOUT_SECONDS)


def _make_agent(tools) -> Agent:
    profile = os.environ.get("AWS_PROFILE")
    LOGGER.debug(
        "Creating Strands Bedrock agent model_id=%s region=%s aws_profile=%s tools=%d",
        MODEL_ID,
        REGION,
        profile or "<default>",
        len(tools),
    )
    session = boto3.Session(profile_name=profile, region_name=REGION)
    model = BedrockModel(model_id=MODEL_ID, boto_session=session)
    return Agent(
        model=model,
        system_prompt=SYSTEM_PROMPT,
        tools=tools,
        callback_handler=None,
    )


async def _load_source_blocks(files: list[UploadFile], urls: list[str], source_blocks: list[str]):
    for index, file in enumerate(files, start=1):
        LOGGER.debug("Reading uploaded PDF source %d/%d: %s", index, len(files), file.filename)
        yield _sse({"type": "stage", "stage": "sources", "text": f"Reading PDF {index}: {file.filename}"})
        pdf_bytes = await file.read()
        if not pdf_bytes:
            raise ValueError(f"Uploaded file is empty: {file.filename}")

        yield _sse({"type": "stage", "stage": "sources", "text": f"Extracting PDF text: {file.filename}"})
        pdf_text = await asyncio.to_thread(extract_pdf_text_from_bytes, pdf_bytes)
        if not pdf_text:
            raise ValueError(f"No text could be extracted from: {file.filename}")
        LOGGER.debug("Extracted %d characters from PDF source: %s", len(pdf_text), file.filename)
        source_blocks.append(
            f"## Uploaded threat report PDF: {file.filename}\n\n{pdf_text[:MAX_SOURCE_CHARS]}"
        )

    for index, source_url in enumerate(urls, start=1):
        LOGGER.debug("Fetching URL source %d/%d: %s", index, len(urls), source_url)
        yield _sse({"type": "stage", "stage": "sources", "text": f"Fetching report URL {index}: {source_url}"})

        def fetch_markdown() -> str:
            return fetch_url_markdown(source_url, timeout=REQUEST_TIMEOUT_SECONDS)

        md_text = await asyncio.to_thread(fetch_markdown)
        if not md_text:
            raise ValueError(f"No text could be extracted from URL: {source_url}")
        LOGGER.debug("Fetched and converted %d markdown characters from URL: %s", len(md_text), source_url)
        source_blocks.append(
            f"## Threat report web page: {source_url}\n\n{md_text[:MAX_SOURCE_CHARS]}"
        )


async def _stream_waf_analysis(
    question: str,
    files: list[UploadFile],
    urls: list[str],
    history: list[dict[str, str]],
):
    if not question.strip():
        yield _sse({"type": "error", "text": "Ask a WAF or web-attack question first."})
        return

    try:
        LOGGER.debug(
            "Starting WAF analysis question_chars=%d pdf_sources=%d url_sources=%d history_turns=%d",
            len(question),
            len(files),
            len(urls),
            len(history),
        )
        yield _sse({"type": "stage", "stage": "sources", "text": "Preparing optional threat-report sources."})
        source_blocks = []
        async for event in _load_source_blocks(files, urls, source_blocks):
            yield event
        if source_blocks:
            yield _sse(
                {
                    "type": "stage",
                    "stage": "sources",
                    "text": f"Prepared {len(source_blocks)} threat-report source(s).",
                }
            )

        prompt_parts = [
            f"User request:\n{question.strip()}",
            (
                "Elastic search target context:\n"
                f"{WAF_DATA_CONTEXT}\n"
                "Use Elastic Agent Builder MCP tools to discover the actual relevant "
                "index/data stream names and mappings before writing aggregations. "
                "Prefer AWS WAF logs for direct WAF questions, but include other "
                "datasets when they are needed to answer the question accurately. "
                "If multiple candidate indices exist, inspect mappings before choosing. "
                "Prefer ES|QL for grouped counts, top-N analysis, time buckets, and "
                "attack timeline reconstruction after discovery. For broad attack "
                "questions, look for repeated attacker/path/rule/user-agent/label "
                "clusters and explain whether the evidence suggests scanning, exploit "
                "attempts, credential abuse, bot activity, or another pattern. For "
                "allowed vs blocked disposition, check ECS event.action and "
                "event.outcome first, then use WAF-specific action or terminating "
                "rule fields for confirmation and detail when mappings show them. "
                "For attack type, check aws.waf.labels.name first and fall back to "
                "rule.id or rule.name when labels are missing or not useful."
            ),
        ]
        if history:
            prompt_parts.append(
                "Recent conversation context from this browser session:\n"
                f"{_format_history(history)}\n\n"
                "Use this history only to resolve follow-up references such as "
                "'those IPs', 'that spike', 'the second pattern', or 'same time range'. "
                "The current user request is authoritative. Re-query Elastic logs for "
                "claims that need current evidence; do not treat prior assistant text "
                "as fresh evidence by itself."
            )
        if source_blocks:
            prompt_parts.append(
                "Threat-report source material supplied by the user:\n\n"
                + "\n\n---\n\n".join(source_blocks)
            )
        prompt = "\n\n".join(prompt_parts)

        yield _sse({"type": "stage", "stage": "elastic", "text": "Connecting to Elastic Agent Builder MCP."})
        with ExitStack() as stack:
            try:
                elastic_client = stack.enter_context(_make_elastic_mcp_client())
                yield _sse({"type": "stage", "stage": "elastic", "text": "Discovering Elastic MCP tools."})
                tools = elastic_client.list_tools_sync()
            except Exception as exc:
                LOGGER.exception("Elastic Agent Builder MCP connection/tool discovery failed")
                raise RuntimeError(
                    "Could not connect to Elastic Agent Builder MCP. Check "
                    "ELASTIC_AGENT_BUILDER_MCP_URL or ELASTIC_KIBANA_URL, the "
                    "Authorization header/API key, and Kibana application privileges "
                    "feature_agentBuilder.read and feature_actions.read. "
                    f"Underlying error: {exc}"
                ) from exc
            tool_names = [getattr(tool, "tool_name", getattr(tool, "name", "unknown")) for tool in tools]
            LOGGER.debug(
                "Loaded %d Elastic Agent Builder MCP tools: %s",
                len(tools),
                ", ".join(tool_names[:50]),
            )
            yield _sse(
                {
                    "type": "tools",
                    "count": len(tools),
                    "names": tool_names[:20],
                    "text": f"Loaded {len(tools)} Elastic Agent Builder tool(s).",
                }
            )

            yield _sse({"type": "stage", "stage": "agent", "text": "Running Strands agent with AWS Bedrock."})
            agent = _make_agent(tools)
            LOGGER.debug("Starting Strands stream_async turn")
            async for event in agent.stream_async(prompt):
                data = event.get("data")
                if data:
                    yield _sse({"type": "token", "text": data})
                    continue

                name = _tool_use_name_from_stream_event(event)
                if name:
                    LOGGER.debug("Strands requested tool: %s", name)
                    yield _sse({"type": "tool", "name": name, "text": f"Called {name}"})

                if "result" in event:
                    LOGGER.debug("Strands agent returned final result")
                    yield _sse({"type": "stage", "stage": "done", "text": "Agent finished."})

        yield _sse({"type": "done"})
        LOGGER.debug("Completed WAF analysis turn")
    except Exception as exc:
        LOGGER.exception("WAF analysis failed")
        yield _sse({"type": "error", "text": str(exc)})


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    LOGGER.debug("Serving WAF WebUI index page")
    return HTML_PAGE


@app.post("/ask")
async def ask(
    question: str = Form(default=""),
    files: list[UploadFile] | None = File(default=None),
    urls: str = Form(default=""),
    history: str = Form(default=""),
) -> StreamingResponse:
    named_files = [file for file in (files or []) if file.filename]
    url_list = [line.strip() for line in urls.splitlines() if line.strip()]
    history_records = _parse_history(history)
    LOGGER.debug(
        "Received /ask request question_chars=%d pdf_sources=%d url_sources=%d history_turns=%d",
        len(question),
        len(named_files),
        len(url_list),
        len(history_records),
    )
    return StreamingResponse(
        _stream_waf_analysis(question, named_files, url_list, history_records),
        media_type="text/event-stream",
    )


HTML_PAGE = """\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='14' fill='%230077cc'/><path d='M16 21h32M16 32h24M16 43h17' fill='none' stroke='white' stroke-width='5' stroke-linecap='round'/></svg>">
  <title>WAF Search — Strands + Elastic MCP</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      margin: 0; background: #f6f7f9; color: #17202a;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main { max-width: 1180px; margin: 0 auto; padding: 1.25rem; }
    header { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; margin-bottom: 1rem; }
    h1 { font-size: 1.35rem; margin: 0; letter-spacing: 0; }
    .subtitle { color: #5f6b7a; font-size: 0.9rem; }
    .layout { display: grid; grid-template-columns: minmax(300px, 420px) 1fr; gap: 1rem; align-items: start; }
    section { background: #fff; border: 1px solid #d9dee7; border-radius: 8px; }
    .panel { padding: 1rem; }
    label { display: block; font-size: 0.82rem; font-weight: 700; margin: 0 0 0.4rem; }
    textarea, input[type="file"] {
      width: 100%; border: 1px solid #c9d0dc; border-radius: 6px; background: #fbfcfe;
      font: inherit; padding: 0.65rem; color: #17202a;
    }
    textarea { min-height: 9rem; resize: vertical; line-height: 1.4; }
    .field { margin-bottom: 0.9rem; }
    .hint { color: #687789; font-size: 0.8rem; line-height: 1.4; margin-top: 0.35rem; }
    .examples { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.5rem; }
    .chip {
      border: 1px solid #c9d0dc; background: #eef2f7; color: #27384a;
      border-radius: 999px; padding: 0.35rem 0.6rem; font-size: 0.78rem; cursor: pointer;
    }
    .actions { display: flex; gap: 0.6rem; align-items: center; margin-top: 1rem; }
    button {
      border: 0; border-radius: 6px; padding: 0.65rem 1rem; font: inherit;
      font-weight: 700; background: #0077cc; color: #fff; cursor: pointer;
    }
    button.secondary { background: #eef2f7; color: #27384a; border: 1px solid #c9d0dc; }
    button:disabled { background: #9ba8b7; cursor: not-allowed; }
    .stage-list { display: grid; gap: 0.45rem; }
    .stage {
      display: grid; grid-template-columns: 1.2rem 1fr; gap: 0.5rem; align-items: start;
      color: #5f6b7a; font-size: 0.86rem;
    }
    .dot {
      width: 0.62rem; height: 0.62rem; margin-top: 0.25rem; border-radius: 50%;
      background: #c9d0dc;
    }
    .stage.active .dot { background: #0077cc; }
    .stage.done .dot { background: #28a745; }
    .stage.error .dot { background: #d93025; }
    .stage strong { color: #27384a; display: block; }
    .result-head {
      border-bottom: 1px solid #e6e9ef; padding: 0.9rem 1rem;
      display: flex; justify-content: space-between; gap: 1rem; align-items: center;
    }
    .result-title { font-weight: 800; }
    .result-tools { display: flex; align-items: center; justify-content: flex-end; gap: 0.8rem; flex-wrap: wrap; }
    .activity-toggle { display: inline-flex; align-items: center; gap: 0.35rem; color: #405064; font-size: 0.82rem; font-weight: 700; margin: 0; white-space: nowrap; }
    .activity-toggle input { margin: 0; }
    #tool-summary { color: #687789; font-size: 0.82rem; overflow-wrap: anywhere; text-align: right; }
    #answer { padding: 1rem; min-height: 28rem; line-height: 1.55; font-size: 0.95rem; display: grid; gap: 0.75rem; align-content: start; }
    #answer:empty::before { content: "Ask a WAF question to search Elastic logs."; color: #8b98a8; }
    #answer.hide-activity .bubble.tool,
    #answer.hide-activity .bubble.meta { display: none; }
    .bubble { border: 1px solid #e0e5ee; border-radius: 8px; padding: 0.75rem 0.85rem; background: #fff; overflow-x: auto; }
    .bubble.user { background: #eef6ff; border-left: 4px solid #4d95d9; }
    .bubble.assistant { border-left: 4px solid #0077cc; }
    .bubble.tool { background: #f7f9fc; color: #405064; border-left: 4px solid #7b8794; font-size: 0.88rem; }
    .bubble.meta { background: #f2f7f3; color: #244b2f; border-left: 4px solid #28a745; font-size: 0.88rem; }
    .bubble.error { background: #fff5f5; color: #7d1f1f; border-left: 4px solid #d93025; }
    .bubble-label { color: #687789; font-size: 0.74rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 0.35rem; }
    .bubble-body { overflow-wrap: anywhere; }
    #answer h1, #answer h2, #answer h3, #answer h4, #answer h5, #answer h6 { letter-spacing: 0; line-height: 1.25; margin: 1.2rem 0 0.45rem; }
    #answer .bubble-body > h1:first-child,
    #answer .bubble-body > h2:first-child,
    #answer .bubble-body > h3:first-child,
    #answer .bubble-body > h4:first-child,
    #answer .bubble-body > h5:first-child,
    #answer .bubble-body > h6:first-child,
    #answer .bubble-body > p:first-child { margin-top: 0; }
    #answer h1 { font-size: 1.25rem; }
    #answer h2 { font-size: 1.1rem; }
    #answer h3 { font-size: 1rem; }
    #answer h4 { font-size: 0.96rem; }
    #answer h5 { font-size: 0.92rem; }
    #answer h6 { font-size: 0.9rem; color: #405064; }
    #answer p { margin: 0.45rem 0 0.8rem; }
    #answer ul, #answer ol { padding-left: 1.45rem; }
    #answer li { margin: 0.3rem 0; }
    #answer code { background: #eef2f7; border: 1px solid #d9dee7; border-radius: 4px; padding: 0.05rem 0.25rem; }
    #answer pre { overflow-x: auto; background: #f1f4f8; border: 1px solid #d9dee7; border-radius: 6px; padding: 0.7rem; }
    #answer pre code { background: transparent; border: 0; padding: 0; }
    #answer hr { border: 0; border-top: 1px solid #d9dee7; margin: 0.9rem 0; }
    #answer table { width: 100%; border-collapse: collapse; margin: 0.7rem 0 1rem; font-size: 0.88rem; }
    #answer th, #answer td { border: 1px solid #d9dee7; padding: 0.45rem 0.55rem; text-align: left; vertical-align: top; }
    #answer th { background: #eef2f7; font-weight: 800; color: #27384a; }
    #answer blockquote {
      margin: 0.65rem 0; padding: 0.25rem 0 0.25rem 0.85rem;
      border-left: 3px solid #c9d0dc; color: #405064;
    }
    #answer del { color: #687789; }
    #answer input[type="checkbox"] { margin-right: 0.35rem; vertical-align: -0.1rem; }
    @media (max-width: 840px) {
      .layout { grid-template-columns: 1fr; }
      header { display: block; }
    }
""" + WEBUI_THEME_CSS + """
  </style>
</head>
<body class="webui-shell">
<main class="ui-shell">
  <header class="ui-header">
    <div>
      <p class="ui-eyebrow">Investigation desk / Elastic MCP</p>
      <h1>WAF search</h1>
      <div class="subtitle ui-subtitle">Search attack patterns, reconstruct timelines, and turn evidence into response actions with Strands on Bedrock.</div>
    </div>
  </header>

  <div class="layout">
    <section class="panel ui-panel">
      <div class="field">
        <label for="question">Question</label>
        <textarea id="question" placeholder="Find attack patterns and build a timeline for the last 24 hours."></textarea>
        <div class="hint">Follow-up questions use the recent conversation from this browser tab. Files and URLs remain attached until you clear them.</div>
        <div class="examples">
          <button class="chip" type="button">Find attack patterns and build a timeline for the last 24 hours.</button>
          <button class="chip" type="button">Are there signs of a coordinated campaign? Group related attacks and explain the evidence.</button>
          <button class="chip" type="button">Who are the top attackers and what are they doing?</button>
          <button class="chip" type="button">Show the sequence of scanning, exploit attempts, blocks, and allowed requests if the data supports it.</button>
          <button class="chip" type="button">Based on this threat report, have we had matching attacks?</button>
          <button class="chip" type="button">Suggest WAF rules from this report.</button>
        </div>
      </div>
      <div class="field">
        <label for="files">Threat report PDFs</label>
        <input id="files" type="file" accept=".pdf" multiple>
        <div class="hint">Optional. Use when asking about a PDF threat report or rule ideas from a report.</div>
      </div>
      <div class="field">
        <label for="urls">Threat report URLs</label>
        <textarea id="urls" placeholder="https://example.com/threat-report"></textarea>
        <div class="hint">Optional. One URL per line. Sites that block automated fetches can be saved as PDF and uploaded.</div>
      </div>
      <div class="actions">
        <button id="ask" type="button">Search WAF Logs</button>
        <button id="clear" class="secondary" type="button">Clear</button>
      </div>
      <hr style="border:0;border-top:1px solid #e6e9ef;margin:1rem 0;">
      <div class="stage-list" id="stages"></div>
    </section>

    <section class="ui-panel">
      <div class="result-head">
        <div class="result-title">Conversation</div>
        <div class="result-tools">
          <label class="activity-toggle" for="show-activity">
            <input id="show-activity" type="checkbox">
            Show tool activity
          </label>
          <div id="tool-summary"></div>
        </div>
      </div>
      <div id="answer" class="hide-activity"></div>
    </section>
  </div>
</main>

<script>
""" + MARKDOWN_RENDERER_JS + """
""" + WEBUI_INTERACTIONS_JS + """
const question = document.getElementById("question");
const files = document.getElementById("files");
const urls = document.getElementById("urls");
const ask = document.getElementById("ask");
const clear = document.getElementById("clear");
const stages = document.getElementById("stages");
const answer = document.getElementById("answer");
const showActivity = document.getElementById("show-activity");
const toolSummary = document.getElementById("tool-summary");
let currentAssistantBubble = null;
let currentAssistantMarkdown = "";
let conversationHistory = [];
const maxHistoryItems = 12;

const stageOrder = [
  ["sources", "Prepare sources"],
  ["elastic", "Connect Elastic MCP"],
  ["agent", "Run Bedrock agent"],
  ["done", "Finish"]
];

function resetStages() {
  stages.innerHTML = "";
  for (const [id, label] of stageOrder) {
    const row = document.createElement("div");
    row.className = "stage";
    row.dataset.stage = id;
    row.innerHTML = '<div class="dot"></div><div><strong>' + label + '</strong><span>Waiting</span></div>';
    stages.appendChild(row);
  }
}

function setStage(id, text, state = "active") {
  const row = stages.querySelector('[data-stage="' + id + '"]');
  if (!row) return;
  row.className = "stage " + state;
  row.querySelector("span").textContent = text;
}

function makeBubble(kind, label, html = "") {
  const bubble = document.createElement("div");
  bubble.className = "bubble " + kind;
  const labelEl = document.createElement("div");
  labelEl.className = "bubble-label";
  labelEl.textContent = label;
  const body = document.createElement("div");
  body.className = "bubble-body";
  body.innerHTML = html;
  bubble.appendChild(labelEl);
  bubble.appendChild(body);
  answer.appendChild(bubble);
  answer.scrollTop = answer.scrollHeight;
  return { bubble, body };
}

function addBubble(kind, label, text) {
  makeBubble(kind, label, renderMarkdown(text));
}

function syncActivityVisibility() {
  answer.classList.toggle("hide-activity", !showActivity.checked);
}

function appendMarkdown(text) {
  if (!currentAssistantBubble) {
    currentAssistantMarkdown = "";
    currentAssistantBubble = makeBubble("assistant", "Agent").body;
  }
  currentAssistantMarkdown += text;
  currentAssistantBubble.innerHTML = renderMarkdown(currentAssistantMarkdown);
  answer.scrollTop = answer.scrollHeight;
}

function breakAssistantBubble() {
  currentAssistantBubble = null;
  currentAssistantMarkdown = "";
}

async function streamResponse(resp) {
  let assistantText = "";
  let failed = false;
  for await (const evt of WebUI.events(resp)) {
      if (evt.type === "stage") {
        setStage(evt.stage, evt.text, evt.stage === "done" ? "done" : "active");
      } else if (evt.type === "tools") {
        setStage("elastic", evt.text, "done");
        toolSummary.textContent = evt.text;
        toolSummary.title = evt.names.length ? evt.names.join(", ") : evt.text;
        addBubble("meta", "Elastic MCP", evt.names.length ? evt.text + "\\n\\nTools: `" + evt.names.join("`, `") + "`" : evt.text);
        breakAssistantBubble();
      } else if (evt.type === "tool") {
        setStage("agent", evt.text, "active");
        addBubble("tool", "Tool Call", evt.text);
        breakAssistantBubble();
      } else if (evt.type === "token") {
        assistantText += evt.text;
        appendMarkdown(evt.text);
      } else if (evt.type === "error") {
        failed = true;
        setStage("done", evt.text, "error");
        addBubble("error", "Error", evt.text);
        breakAssistantBubble();
      } else if (evt.type === "done") {
        setStage("done", "Done", "done");
      }
  }
  return { assistantText, failed };
}

WebUI.bindPromptChips(question);

showActivity.addEventListener("change", syncActivityVisibility);

clear.addEventListener("click", () => {
  question.value = "";
  urls.value = "";
  files.value = "";
  conversationHistory = [];
  breakAssistantBubble();
  answer.innerHTML = "";
  toolSummary.textContent = "";
  toolSummary.title = "";
  ask.textContent = "Search WAF Logs";
  resetStages();
});

ask.addEventListener("click", async () => {
  const text = question.value.trim();
  if (!text) { setStage("sources", "Ask a WAF question first.", "error"); return; }
  const historyForRequest = conversationHistory.slice(-maxHistoryItems);
  breakAssistantBubble();
  toolSummary.textContent = "";
  toolSummary.title = "";
  resetStages();
  addBubble("user", "You", text);
  ask.disabled = true;

  const form = new FormData();
  form.append("question", text);
  form.append("urls", urls.value);
  form.append("history", JSON.stringify(historyForRequest));
  for (const file of Array.from(files.files || [])) form.append("files", file);

  try {
    const resp = await fetch("/ask", { method: "POST", body: form, headers: { "Accept": "text/event-stream" } });
    if (!resp.ok || !resp.body) {
      setStage("done", "Server error: " + resp.status, "error");
      return;
    }
    const result = await streamResponse(resp);
    if (!result.failed) {
      conversationHistory.push({ role: "user", content: text });
      if (result.assistantText.trim()) {
        conversationHistory.push({ role: "assistant", content: result.assistantText.trim() });
      }
      conversationHistory = conversationHistory.slice(-maxHistoryItems);
      question.value = "";
      ask.textContent = "Ask Follow-up";
    }
  } catch (err) {
    setStage("done", "Browser error: " + err.message, "error");
  } finally {
    ask.disabled = false;
  }
});

resetStages();
syncActivityVisibility();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    print("Open http://localhost:8002 in your browser.")
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8002,
        log_level="debug",
        log_config=None,
        access_log=True,
    )
