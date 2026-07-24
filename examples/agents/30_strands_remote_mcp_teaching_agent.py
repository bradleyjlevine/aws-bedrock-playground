"""
Hello World: Strands remote MCP tech teaching agent

Creates a documentation-grounded teaching agent that connects to remote MCP
servers for AWS Knowledge, Cloudflare Docs, Microsoft Learn, and optionally
Google Developer Knowledge. The agent is prompted to teach how to do practical
tasks across platforms, using the provider docs tools before making
platform-specific claims.

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python examples/agents/30_strands_remote_mcp_teaching_agent.py
         uv run python examples/agents/30_strands_remote_mcp_teaching_agent.py --interactive
         uv run python examples/agents/30_strands_remote_mcp_teaching_agent.py --web
         uv run python examples/agents/30_strands_remote_mcp_teaching_agent.py --prompt "Teach me how to deploy a static site on Cloudflare and AWS."
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from logging_utils import configure_script_logging, install_http_request_logging_middleware
from webui_interactions import WEBUI_INTERACTIONS_JS
from webui_markdown import MARKDOWN_RENDERER_JS
from webui_theme import WEBUI_THEME_CSS

import argparse
import asyncio
import json
import logging
import os
from contextlib import ExitStack
from typing import Any

LOGGER = configure_script_logging(__file__)
for noisy_logger in (
    "botocore.parsers",
    "botocore.endpoint",
    "httpcore",
    "mcp.client.streamable_http",
):
    logging.getLogger(noisy_logger).setLevel(logging.INFO)

import boto3
import uvicorn
from botocore.config import Config as BotocoreConfig
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client
from mcp.types import Tool as MCPTool
from pydantic import BaseModel, Field
from strands import Agent, tool
from strands.models import BedrockModel
from strands.types._events import ToolResultEvent
from strands.types.tools import AgentTool, ToolGenerator, ToolSpec, ToolUse
from strands.tools.mcp import MCPClient
from strands.vended_plugins.context_offloader import ContextOffloader, InMemoryStorage
from strands_tools import current_time


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name, "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc


REGION = os.environ.get("AWS_REGION", "us-east-1")
MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
)
DEFAULT_MAX_TOKENS = env_int("BEDROCK_MAX_TOKENS", 8_192)
DEFAULT_BEDROCK_READ_TIMEOUT = 300
DEFAULT_BEDROCK_CONNECT_TIMEOUT = 10
DEFAULT_MCP_STARTUP_TIMEOUT = 30
DEFAULT_OFFLOAD_MAX_RESULT_TOKENS = 1_500
DEFAULT_OFFLOAD_PREVIEW_TOKENS = 500
MAX_WEB_HISTORY_MESSAGES = 12
MAX_WEB_HISTORY_CHARS = 8_000
DEFAULT_PROMPT = (
    "Teach me how to design a small serverless API and explain how I would do "
    "it on AWS, Cloudflare, and Microsoft platforms. Include a practical path, "
    "tradeoffs, common mistakes, and a short knowledge check."
)

SOURCE_ENDPOINTS = {
    "aws": {
        "label": "AWS Knowledge MCP",
        "env": "AWS_KNOWLEDGE_MCP_URL",
        "url": "https://knowledge-mcp.global.api.aws",
    },
    "cloudflare": {
        "label": "Cloudflare Docs MCP",
        "env": "CLOUDFLARE_DOCS_MCP_URL",
        "url": "https://docs.mcp.cloudflare.com/mcp",
    },
    "microsoft": {
        "label": "Microsoft Learn MCP",
        "env": "MICROSOFT_LEARN_MCP_URL",
        "url": "https://learn.microsoft.com/api/mcp",
    },
    "gcp": {
        "label": "Google Developer Knowledge",
        "env": "GCP_DK_MCP_URL",
        "url": "https://developerknowledge.googleapis.com/mcp",
        "api_key_env": "GCP_DK_MCP_API_KEY",
    },
}


@tool
def lesson_scaffold(topic: str, learner_level: str = "intermediate") -> dict[str, Any]:
    """Create a compact teaching scaffold for a technical topic.

    Args:
        topic: The topic or task the learner wants to understand.
        learner_level: Learner level such as beginner, intermediate, or advanced.

    Returns:
        A lesson scaffold with sections the agent can fill using documentation.
    """
    level = learner_level.strip().lower() or "intermediate"
    return {
        "topic": topic,
        "learner_level": level,
        "sections": [
            "learning goal",
            "mental model",
            "platform-specific walkthrough",
            "decision points and tradeoffs",
            "common mistakes",
            "hands-on practice",
            "knowledge check",
        ],
    }


def make_model(read_timeout: int, connect_timeout: int, max_tokens: int) -> BedrockModel:
    profile = os.environ.get("AWS_PROFILE")
    session = boto3.Session(profile_name=profile, region_name=REGION)
    client_config = BotocoreConfig(
        read_timeout=read_timeout,
        connect_timeout=connect_timeout,
        retries={"max_attempts": 3, "mode": "standard"},
    )
    return BedrockModel(
        model_id=MODEL_ID,
        boto_session=session,
        boto_client_config=client_config,
        max_tokens=max_tokens,
    )


def make_remote_mcp_client(source: str, url: str, startup_timeout: int) -> MCPClient:
    if SOURCE_ENDPOINTS[source].get("api_key_env"):
        return MCPClient(
            lambda: streamable_http_client(
                url,
                http_client=create_mcp_http_client(headers=source_headers(source)),
            ),
            startup_timeout=startup_timeout,
            prefix=source,
        )
    return MCPClient(
        lambda: streamable_http_client(url),
        startup_timeout=startup_timeout,
    )


class FreshMCPAgentTool(AgentTool):
    """MCP tool wrapper that opens a fresh remote session for each invocation."""

    def __init__(
        self,
        source: str,
        url: str,
        startup_timeout: int,
        mcp_tool: MCPTool,
        tool_name: str,
    ) -> None:
        super().__init__()
        self.source = source
        self.url = url
        self.startup_timeout = startup_timeout
        self.mcp_tool = mcp_tool
        self._tool_name = tool_name

    @property
    def tool_name(self) -> str:
        return self._tool_name

    @property
    def tool_spec(self) -> ToolSpec:
        spec: ToolSpec = {
            "inputSchema": {"json": self.mcp_tool.inputSchema},
            "name": self.tool_name,
            "description": self.mcp_tool.description
            or f"Tool which performs {self.mcp_tool.name}",
        }
        if self.mcp_tool.outputSchema:
            spec["outputSchema"] = {"json": self.mcp_tool.outputSchema}
        return spec

    @property
    def tool_type(self) -> str:
        return "python"

    async def _call_once(self, tool_use: ToolUse):
        client = make_remote_mcp_client(self.source, self.url, self.startup_timeout)
        entered = False
        result = None
        try:
            client.__enter__()
            entered = True
            result = await client.call_tool_async(
                tool_use_id=tool_use["toolUseId"],
                name=self.mcp_tool.name,
                arguments=tool_use["input"],
            )
        finally:
            if entered:
                try:
                    client.__exit__(None, None, None)
                except RuntimeError:
                    if result is None:
                        raise
                    LOGGER.debug(
                        "Ignoring %s MCP session close after successful %s call",
                        self.source,
                        self.tool_name,
                    )

        return result

    async def stream(
        self,
        tool_use: ToolUse,
        invocation_state: dict[str, Any],
        **kwargs: Any,
    ) -> ToolGenerator:
        result = None
        for attempt in range(2):
            result = await self._call_once(tool_use)
            if not is_mcp_session_closed_tool_result(result):
                break
            if attempt == 0:
                LOGGER.warning(
                    "Retrying %s after Google MCP session closed during tool call",
                    self.tool_name,
                )

        if result is not None:
            yield ToolResultEvent(result)


def is_mcp_session_closed_tool_result(result: Any) -> bool:
    if not isinstance(result, dict) or result.get("status") != "error":
        return False

    text_parts = []
    for item in result.get("content", []):
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            text_parts.append(item["text"].lower())

    text = "\n".join(text_parts)
    return (
        "connection to the mcp server was closed" in text
        or "client session is not running" in text
    )


def source_headers(source: str) -> dict[str, str]:
    endpoint = SOURCE_ENDPOINTS[source]
    api_key_env = endpoint.get("api_key_env")
    if not api_key_env:
        return {}

    api_key = os.environ.get(api_key_env, "").strip()
    if not api_key:
        raise ValueError(
            f"{endpoint['label']} requires {api_key_env}. Create a Developer Knowledge "
            "API key, restrict it, and export it before enabling this source."
        )
    return {"X-Goog-Api-Key": api_key}


def source_url(source: str, args: argparse.Namespace) -> str:
    endpoint = SOURCE_ENDPOINTS[source]
    cli_value = getattr(args, f"{source}_mcp_url")
    return (cli_value or os.environ.get(endpoint["env"]) or endpoint["url"]).strip()


def build_system_prompt(active_sources: list[str]) -> str:
    source_text = ", ".join(active_sources) if active_sources else "no remote documentation sources"
    return (
        "You are a technical teaching agent for cloud and developer platforms. "
        f"Connected documentation sources: {source_text}. "
        "Your job is to help a user learn how to do practical tasks, not just define terms. "
        "For platform-specific facts, first use the relevant MCP documentation tools. "
        "When a task spans multiple platforms, compare AWS, Cloudflare, Microsoft, and "
        "Google Cloud only where the connected docs support it, and say when a source is "
        "unavailable or does not cover the requested detail. "
        "Use gcp_search_documents, gcp_answer_query, and gcp_get_documents for "
        "Google Cloud and other Google developer documentation. "
        "Do not claim the Google Developer Knowledge key is expired, invalid, or misconfigured unless "
        "a Google tool result explicitly reports an authentication failure; a generic "
        "tool error only means the Google documentation source was not verified in this run. "
        "Do not use AWS, Cloudflare, or Microsoft documentation as evidence for "
        "Google-specific product details. "
        "Prefer concrete steps, minimal runnable examples, setup prerequisites, decision "
        "points, common mistakes, and verification checks. "
        "Adapt explanations to the learner's level and ask a brief clarifying question only "
        "when the missing detail would materially change the answer. "
        "Use lesson_scaffold when a topic needs a structured teaching path. "
        "Large documentation tool results may be offloaded out of context with "
        "a preview; use the preview and offload reference instead of asking the "
        "tool to resend the same large response. "
        "End substantial lessons with a short knowledge check or practice task. "
        "Mention which documentation source families you used."
    )


def context_offloader_plugins(args: argparse.Namespace) -> list[ContextOffloader]:
    if args.no_context_offload:
        return []
    return [
        ContextOffloader(
            storage=InMemoryStorage(),
            max_result_tokens=args.offload_threshold,
            preview_tokens=args.offload_preview,
        )
    ]


def make_agent(tools: list[Any], active_sources: list[str], args: argparse.Namespace) -> Agent:
    model = make_model(
        read_timeout=args.bedrock_read_timeout,
        connect_timeout=args.bedrock_connect_timeout,
        max_tokens=args.max_tokens,
    )
    return Agent(
        model=model,
        system_prompt=build_system_prompt(active_sources),
        tools=tools,
        plugins=context_offloader_plugins(args),
        callback_handler=None,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Teach technical tasks using AWS, Cloudflare, Microsoft, and optional "
            "Google Developer Knowledge remote MCP docs."
        ),
    )
    parser.add_argument(
        "--prompt",
        default=DEFAULT_PROMPT,
        help="Initial learning request.",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Keep the same agent session open for follow-up questions.",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Run the FastAPI/SSE browser teaching UI.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host for --web mode.")
    parser.add_argument("--port", type=int, default=8004, help="Port for --web mode.")
    parser.add_argument(
        "--source",
        action="append",
        choices=sorted(SOURCE_ENDPOINTS),
        help="Restrict docs sources. Repeat for multiple sources. Defaults to all.",
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Continue if one remote MCP source fails to connect.",
    )
    parser.add_argument(
        "--aws-mcp-url",
        default="",
        help="Override AWS Knowledge MCP URL. Env: AWS_KNOWLEDGE_MCP_URL.",
    )
    parser.add_argument(
        "--cloudflare-mcp-url",
        default="",
        help="Override Cloudflare Docs MCP URL. Env: CLOUDFLARE_DOCS_MCP_URL.",
    )
    parser.add_argument(
        "--microsoft-mcp-url",
        default="",
        help="Override Microsoft Learn MCP URL. Env: MICROSOFT_LEARN_MCP_URL.",
    )
    parser.add_argument(
        "--gcp-mcp-url",
        default="",
        help="Override Google Developer Knowledge MCP URL. Env: GCP_DK_MCP_URL.",
    )
    parser.add_argument(
        "--mcp-startup-timeout",
        type=int,
        default=DEFAULT_MCP_STARTUP_TIMEOUT,
        help="Seconds to wait for each remote MCP server to initialize.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=DEFAULT_MAX_TOKENS,
        help=(
            "Maximum Bedrock model output tokens. Defaults to BEDROCK_MAX_TOKENS "
            f"or {DEFAULT_MAX_TOKENS}; raise this for models that support larger outputs."
        ),
    )
    parser.add_argument(
        "--no-context-offload",
        action="store_true",
        help="Disable Strands ContextOffloader for large remote documentation tool results.",
    )
    parser.add_argument(
        "--offload-threshold",
        type=int,
        default=DEFAULT_OFFLOAD_MAX_RESULT_TOKENS,
        help="Tool result token threshold above which ContextOffloader stores content out of context.",
    )
    parser.add_argument(
        "--offload-preview",
        type=int,
        default=DEFAULT_OFFLOAD_PREVIEW_TOKENS,
        help="Preview tokens to keep in context for offloaded tool results.",
    )
    parser.add_argument(
        "--bedrock-read-timeout",
        type=int,
        default=DEFAULT_BEDROCK_READ_TIMEOUT,
        help="Bedrock read timeout in seconds.",
    )
    parser.add_argument(
        "--bedrock-connect-timeout",
        type=int,
        default=DEFAULT_BEDROCK_CONNECT_TIMEOUT,
        help="Bedrock connect timeout in seconds.",
    )
    return parser.parse_args()


def selected_sources(args: argparse.Namespace) -> list[str]:
    if not args.source:
        sources = [source for source in SOURCE_ENDPOINTS if source != "gcp"]
        if os.environ.get("GCP_DK_MCP_API_KEY", "").strip():
            sources.append("gcp")
        return sources

    seen = set()
    ordered = []
    for source in args.source:
        if source not in seen:
            ordered.append(source)
            seen.add(source)
    return ordered


def print_tool_counts(tool_counts: dict[str, int]) -> None:
    print("Synced tool counts:")
    for label, count in tool_counts.items():
        print(f"- {label}: {count}")


def context_offload_status(args: argparse.Namespace) -> str:
    if args.no_context_offload:
        return "ContextOffloader disabled."
    return (
        "ContextOffloader enabled "
        f"(threshold={args.offload_threshold} tokens, preview={args.offload_preview} tokens)."
    )


def token_limit_message(args: argparse.Namespace) -> str:
    return (
        "The agent hit the configured Bedrock max token limit before it could finish. "
        f"Current max_tokens={args.max_tokens}. Try rerunning with a model that supports "
        "a larger output budget and set --max-tokens higher, or ask for a narrower lesson. "
        "For example: --max-tokens 16000."
    )


def is_max_tokens_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return "max_tokens" in text or "maxtokens" in text or "max tokens" in text


def source_label(source: str, url: str) -> str:
    return f"{SOURCE_ENDPOINTS[source]['label']} ({url})"


def build_clients(args: argparse.Namespace) -> list[tuple[str, str, str, MCPClient]]:
    clients: list[tuple[str, str, str, MCPClient]] = []
    for source in selected_sources(args):
        url = source_url(source, args)
        clients.append(
            (
                source,
                source_label(source, url),
                url,
                make_remote_mcp_client(source, url, args.mcp_startup_timeout),
            )
        )
    return clients


def list_fresh_google_tools(
    source: str,
    url: str,
    startup_timeout: int,
    client: MCPClient,
) -> list[FreshMCPAgentTool]:
    entered = False
    gcp_tools = None
    try:
        client.__enter__()
        entered = True
        gcp_tools = client.list_tools_sync()
    finally:
        if entered:
            try:
                client.__exit__(None, None, None)
            except RuntimeError:
                if gcp_tools is None:
                    raise
                LOGGER.debug("Ignoring %s MCP session close after successful tool sync", source)

    if gcp_tools is None:
        return []

    return [
        FreshMCPAgentTool(
            source=source,
            url=url,
            startup_timeout=startup_timeout,
            mcp_tool=gcp_tool.mcp_tool,
            tool_name=gcp_tool.tool_name,
        )
        for gcp_tool in gcp_tools
    ]


def _sse(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload)}\n\n"


def _tool_use_name_from_stream_event(event: dict[str, Any]) -> str:
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
        if isinstance(value, str):
            return value
    return ""


def build_web_prompt(question: str, history: list[dict[str, str]]) -> str:
    bounded_messages = []
    remaining_chars = MAX_WEB_HISTORY_CHARS
    for item in reversed(history[-MAX_WEB_HISTORY_MESSAGES:]):
        role = item.get("role", "user").strip().lower()
        if role not in {"user", "assistant"}:
            role = "user"
        content = item.get("content", "").strip()
        if not content:
            continue
        if remaining_chars <= 0:
            break
        content = content[:remaining_chars]
        remaining_chars -= len(content)
        bounded_messages.append((role, content))

    bounded_messages.reverse()
    if not bounded_messages:
        return question

    transcript = "\n\n".join(
        f"{role.title()}:\n{content}" for role, content in bounded_messages
    )
    return (
        "Recent browser conversation for follow-up context. Use it to resolve "
        "references like 'that option' or 'compare those', but re-check connected "
        "documentation tools for platform-specific factual claims:\n\n"
        f"{transcript}\n\n"
        "Current user request:\n"
        f"{question}"
    )


class ChatRequest(BaseModel):
    message: str
    history: list[dict[str, str]] = Field(default_factory=list)


async def stream_agent_to_stdout(agent: Agent, prompt: str) -> None:
    wrote_text = False
    seen_tools: set[str] = set()
    async for event in agent.stream_async(prompt):
        data = event.get("data")
        if data:
            print(data, end="", flush=True)
            wrote_text = True
            continue

        name = _tool_use_name_from_stream_event(event)
        if name and name not in seen_tools:
            seen_tools.add(name)
            print(f"\n[tool: {name}]\n", file=sys.stderr, flush=True)

    if wrote_text:
        print()


def run_interactive_loop(agent: Agent, args: argparse.Namespace) -> None:
    print("\nAsk follow-up questions. Type 'quit' or 'exit', or press Ctrl-C to stop.\n")
    while True:
        try:
            question = input("teach> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            return

        if question.lower() in {"quit", "exit"}:
            print("Goodbye!")
            return
        if not question:
            continue

        print()
        try:
            asyncio.run(stream_agent_to_stdout(agent, question))
        except KeyboardInterrupt:
            print("\nGoodbye!")
            return
        except Exception as exc:
            if is_max_tokens_error(exc):
                print(token_limit_message(args))
            else:
                raise
        print()


HTML_PAGE = """\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='14' fill='%232457a6'/><path d='M17 20h30v25H17zM23 27h18M23 34h14' fill='none' stroke='white' stroke-width='4' stroke-linejoin='round' stroke-linecap='round'/></svg>">
  <title>Tech Teaching Agent</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f5f7fb;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #5d6673;
      --line: #d8dee8;
      --accent: #2457a6;
      --accent-2: #0f766e;
      --warn: #8a5a00;
      --error: #9f1d1d;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main {
      width: min(100vw - 32px, 1120px);
      margin: 0 auto;
      padding: 18px 0;
      min-height: 100vh;
      display: grid;
      grid-template-rows: auto 1fr auto;
      gap: 12px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 16px;
      border-bottom: 1px solid var(--line);
      padding-bottom: 10px;
    }
    h1 { margin: 0; font-size: 1.15rem; line-height: 1.2; }
    .header-tools {
      display: flex;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }
    .meta { color: var(--muted); font-size: 0.86rem; white-space: nowrap; }
    .activity-toggle {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      color: #405064;
      font-size: 0.82rem;
      font-weight: 700;
      margin: 0;
      white-space: nowrap;
    }
    .activity-toggle input { margin: 0; }
    #log {
      min-height: 420px;
      height: calc(100vh - 210px);
      overflow-y: auto;
      padding: 12px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    #log.hide-tools .tool { display: none; }
    .msg {
      max-width: 88%;
      margin: 0 0 12px;
      padding: 10px 12px;
      border-radius: 8px;
      line-height: 1.45;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .user { margin-left: auto; background: #dbeafe; color: #102a56; }
    .assistant {
      background: #eef2f7;
      color: #17202a;
      white-space: normal;
    }
    .assistant h1 { font-size: 1.25rem; margin: 0.35rem 0 0.45rem; }
    .assistant h2 { font-size: 1.12rem; margin: 0.55rem 0 0.35rem; }
    .assistant h3 { font-size: 1rem; margin: 0.5rem 0 0.3rem; }
    .assistant p { margin: 0.35rem 0; }
    .assistant ul, .assistant ol { margin: 0.35rem 0 0.55rem 1.25rem; padding: 0; }
    .assistant li { margin: 0.18rem 0; }
    .assistant code {
      background: #e0e7ef;
      border-radius: 4px;
      padding: 0.05rem 0.22rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.9em;
    }
    .assistant pre {
      overflow-x: auto;
      background: #111827;
      color: #f9fafb;
      border-radius: 6px;
      padding: 0.7rem;
      white-space: pre;
    }
    .assistant pre code { background: transparent; color: inherit; padding: 0; }
    .assistant table {
      width: 100%;
      border-collapse: collapse;
      margin: 0.55rem 0;
      font-size: 0.88rem;
      display: block;
      overflow-x: auto;
    }
    .assistant th, .assistant td {
      border: 1px solid #cbd5e1;
      padding: 0.4rem 0.5rem;
      text-align: left;
      vertical-align: top;
    }
    .assistant th { background: #e8eef6; }
    .assistant blockquote {
      margin: 0.5rem 0;
      padding: 0.2rem 0 0.2rem 0.75rem;
      border-left: 3px solid #cbd5e1;
      color: #475569;
    }
    .stage, .tool, .error {
      max-width: 100%;
      margin: 0 0 8px;
      font-size: 0.82rem;
      color: var(--muted);
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .tool { color: var(--warn); }
    .error { color: var(--error); }
    form {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 10px;
      align-items: end;
    }
    textarea {
      width: 100%;
      min-height: 62px;
      max-height: 190px;
      resize: vertical;
      padding: 10px 12px;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      font: inherit;
      line-height: 1.35;
      background: #fff;
      color: var(--text);
    }
    button {
      min-width: 96px;
      height: 42px;
      border: 0;
      border-radius: 8px;
      background: var(--accent);
      color: #fff;
      font: inherit;
      font-weight: 650;
      cursor: pointer;
    }
    button:disabled { background: #94a3b8; cursor: not-allowed; }
    .chips {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 8px;
    }
    .chip {
      border: 1px solid #cbd5e1;
      background: #fff;
      color: #334155;
      border-radius: 8px;
      padding: 5px 8px;
      font-size: 0.78rem;
      cursor: pointer;
    }
    .chip:hover { border-color: var(--accent-2); color: var(--accent-2); }
    @media (max-width: 720px) {
      main { width: min(100vw - 20px, 1120px); padding: 10px 0; }
      header { display: block; }
      .header-tools { justify-content: flex-start; margin-top: 4px; }
      .meta { white-space: normal; }
      #log { height: calc(100vh - 220px); padding: 10px; }
      .msg { max-width: 100%; }
      form { grid-template-columns: 1fr; }
      button { width: 100%; }
    }
""" + WEBUI_THEME_CSS + """
  </style>
</head>
<body class="webui-shell">
<main class="ui-shell">
  <header class="ui-header">
    <div>
      <p class="ui-eyebrow">Learning studio / Connected documentation</p>
      <h1>Tech teaching agent</h1>
      <p class="ui-subtitle">Build a grounded lesson from live AWS, Cloudflare, Microsoft, and Google Cloud documentation.</p>
    </div>
    <div class="header-tools">
      <div class="meta">AWS · Cloudflare · Microsoft · Google Cloud</div>
      <label class="activity-toggle" for="show-tools">
        <input id="show-tools" type="checkbox">
        Show tool calls
      </label>
    </div>
  </header>

  <section id="log" class="hide-tools ui-panel" aria-live="polite"></section>

  <section class="ui-composer">
    <form id="form">
      <textarea id="input" autocomplete="off" placeholder="Ask how to build, deploy, secure, observe, or troubleshoot something."></textarea>
      <button id="send" type="submit">Send</button>
    </form>
    <div class="chips">
      <button class="chip" type="button" data-prompt="Teach me how to deploy a static site across AWS, Cloudflare, Microsoft, and Google Cloud.">Static site</button>
      <button class="chip" type="button" data-prompt="Teach me how to put a serverless API behind authentication across the connected platforms.">API auth</button>
      <button class="chip" type="button" data-prompt="Teach me how to observe and troubleshoot a small web application after deployment.">Observability</button>
    </div>
  </section>
</main>

<script>
""" + MARKDOWN_RENDERER_JS + """
""" + WEBUI_INTERACTIONS_JS + """
const log = document.getElementById("log");
const form = document.getElementById("form");
const input = document.getElementById("input");
const send = document.getElementById("send");
const showTools = document.getElementById("show-tools");
const transcript = [];
const maxTranscriptMessages = 12;

function add(cls, text) {
  return WebUI.addMessage(log, cls, text);
}

function append(target, text) {
  WebUI.appendMarkdown(log, target, text);
}

async function streamSSE(response) {
  let assistant = null;
  const assistantParts = [];

  function currentAssistant() {
    if (!assistant) {
      assistant = add("msg assistant", "");
      assistantParts.push(assistant);
    }
    return assistant;
  }

  function closeAssistantPart() {
    if (assistant && (assistant.dataset.markdown || "").trim()) {
      assistant = null;
    }
  }

  for await (const evt of WebUI.events(response)) {
      if (evt.type === "token") {
        append(currentAssistant(), evt.text);
      } else if (evt.type === "tool") {
        closeAssistantPart();
        add("tool", evt.text);
      } else if (evt.type === "stage") {
        closeAssistantPart();
        add("stage", evt.text);
      } else if (evt.type === "error") {
        closeAssistantPart();
        add("error", evt.text);
      }
  }

  return assistantParts
    .map((part) => part.dataset.markdown || "")
    .filter((part) => part.trim())
    .join("\\n\\n");
}

function recentTranscript() {
  return transcript.slice(-maxTranscriptMessages);
}

async function ask(message) {
  add("msg user", message);
  send.disabled = true;
  input.disabled = true;
  try {
    const resp = await fetch("/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, history: recentTranscript() })
    });
    if (!resp.ok || !resp.body) {
      throw new Error(`HTTP ${resp.status}`);
    }
    const assistantText = await streamSSE(resp);
    transcript.push({ role: "user", content: message });
    transcript.push({ role: "assistant", content: assistantText });
  } catch (err) {
    add("error", `Request failed: ${err.message}`);
  } finally {
    send.disabled = false;
    input.disabled = false;
    input.focus();
  }
}

WebUI.bindComposer(form, input, async (message) => {
  await ask(message);
});

WebUI.bindPromptChips(input);

showTools.addEventListener("change", () => {
  log.classList.toggle("hide-tools", !showTools.checked);
});
</script>
</body>
</html>
"""


def create_web_app(args: argparse.Namespace) -> FastAPI:
    app = FastAPI()
    app.state.args = args
    install_http_request_logging_middleware(app, LOGGER)

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        LOGGER.debug("Serving teaching WebUI index page")
        return HTML_PAGE

    @app.post("/chat")
    async def chat(req: ChatRequest) -> StreamingResponse:
        LOGGER.debug("Received /chat request message_chars=%d", len(req.message))
        return StreamingResponse(
            _stream_web_turn(app.state.args, req.message, req.history),
            media_type="text/event-stream",
        )

    return app


async def _stream_web_turn(args: argparse.Namespace, message: str, history: list[dict[str, str]]):
    question = message.strip()
    if not question:
        yield _sse({"type": "error", "text": "Enter a question."})
        yield _sse({"type": "done"})
        return

    try:
        native_tools = [current_time, lesson_scaffold]
        synced_tools = list(native_tools)
        tool_counts = {"native": len(native_tools)}
        active_source_labels: list[str] = []

        yield _sse({"type": "stage", "stage": "sources", "text": "Connecting to documentation MCP sources."})
        with ExitStack() as stack:
            for source, label, url, client in build_clients(args):
                try:
                    if source == "gcp":
                        tools = list_fresh_google_tools(
                            source=source,
                            url=url,
                            startup_timeout=args.mcp_startup_timeout,
                            client=client,
                        )
                    else:
                        stack.enter_context(client)
                        tools = client.list_tools_sync()
                except Exception as exc:
                    if not args.allow_partial:
                        raise RuntimeError(
                            f"Could not initialize {label}. Use --allow-partial to continue "
                            "with the sources that are reachable."
                        ) from exc
                    LOGGER.warning("Skipping %s: %s", label, exc)
                    yield _sse({"type": "stage", "stage": "sources", "text": f"Skipping {label}: {exc}"})
                    continue

                synced_tools.extend(tools)
                tool_counts[label] = len(tools)
                active_source_labels.append(label)

            if not active_source_labels:
                raise RuntimeError("No remote MCP documentation sources were available.")

            source_count = max(0, len(tool_counts) - 1)
            yield _sse(
                {
                    "type": "stage",
                    "stage": "sources",
                    "text": (
                        f"Using {source_count} documentation source(s). "
                        f"{context_offload_status(args)}"
                    ),
                }
            )

            agent = make_agent(synced_tools, active_source_labels, args)
            prompt = build_web_prompt(question, history)
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
                    yield _sse({"type": "stage", "stage": "done", "text": "Agent finished."})

        yield _sse({"type": "done"})
    except Exception as exc:
        LOGGER.exception("Teaching WebUI turn failed")
        text = token_limit_message(args) if is_max_tokens_error(exc) else str(exc)
        yield _sse({"type": "error", "text": text})


def main() -> None:
    args = parse_args()
    if args.web:
        print(f"Open http://{args.host}:{args.port} in your browser.")
        uvicorn.run(
            create_web_app(args),
            host=args.host,
            port=args.port,
            log_level="debug",
            log_config=None,
            access_log=True,
        )
        return

    native_tools = [current_time, lesson_scaffold]
    synced_tools = list(native_tools)
    tool_counts = {"native": len(native_tools)}
    active_source_labels: list[str] = []

    clients = build_clients(args)

    with ExitStack() as stack:
        for source, label, url, client in clients:
            try:
                if source == "gcp":
                    tools = list_fresh_google_tools(
                        source=source,
                        url=url,
                        startup_timeout=args.mcp_startup_timeout,
                        client=client,
                    )
                else:
                    stack.enter_context(client)
                    tools = client.list_tools_sync()
            except Exception as exc:
                if not args.allow_partial:
                    raise RuntimeError(
                        f"Could not initialize {label}. Use --allow-partial to continue "
                        "with the sources that are reachable."
                    ) from exc
                print(f"Warning: skipping {label}: {exc}")
                continue

            synced_tools.extend(tools)
            tool_counts[label] = len(tools)
            active_source_labels.append(label)

        if not active_source_labels:
            raise RuntimeError("No remote MCP documentation sources were available.")

        agent = make_agent(synced_tools, active_source_labels, args)
        print_tool_counts(tool_counts)
        print(context_offload_status(args))
        print("\nAgent response (streaming):\n")
        try:
            asyncio.run(stream_agent_to_stdout(agent, args.prompt))
        except KeyboardInterrupt:
            print("\nGoodbye!")
            return
        except Exception as exc:
            if is_max_tokens_error(exc):
                print(token_limit_message(args))
            else:
                raise

        if args.interactive:
            run_interactive_loop(agent, args)


if __name__ == "__main__":
    main()
