"""
Hello World: Strands Swarm - RSS briefing with remote MCP web search

Creates a three-agent swarm that:
  - Uses the strands_tools.rss community tool to collect recent RSS items
  - Filters the briefing scope to the last 14 days by default
  - Fetches relevant article pages for more detail before summarising
  - Optionally calls Exa's remote MCP web-search tool from EXA_API_KEY
  - Runs on the configured Bedrock Runtime model

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Exa:     export EXA_API_KEY=...
Run:     uv run python 23_strands_rss_exa_swarm.py
         uv run python 23_strands_rss_exa_swarm.py --feed https://example.com/feed.xml
"""

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)
import argparse
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode, urlparse

import boto3
import requests
from bs4 import BeautifulSoup
from botocore.config import Config as BotocoreConfig
from mcp.client.streamable_http import streamable_http_client
from strands import Agent, tool
from strands.models import BedrockModel
from strands.multiagent import Swarm
from strands.tools.mcp import MCPClient
from strands.vended_plugins.context_offloader import ContextOffloader, InMemoryStorage
from strands_tools import rss as rss_tool

REGION = "us-east-1"
MODEL_ID = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
DEFAULT_DAYS = 14
DEFAULT_MAX_ARTICLES = 10
DEFAULT_FEED_LIMIT = 3
DEFAULT_MODEL_MAX_TOKENS = 4_096
DEFAULT_BEDROCK_READ_TIMEOUT = 300
DEFAULT_BEDROCK_CONNECT_TIMEOUT = 10
DEFAULT_OFFLOAD_MAX_RESULT_TOKENS = 1_500
DEFAULT_OFFLOAD_PREVIEW_TOKENS = 500
ARTICLE_MAX_CHARS = 12_000
EXA_MCP_BASE_URL = "https://mcp.exa.ai/mcp"
DEFAULT_FEEDS = [
    "https://www.schneier.com/feed/atom/",
    "https://krebsonsecurity.com/feed/",
    "https://www.cloudvulndb.org/rss/feed.xml",
    "https://www.darkreading.com/rss.xml",
    "https://www.blackhillsinfosec.com/blog/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.securityweek.com/feed/",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.kb.cert.org/vulfeed/",
    "https://www.csoonline.com/feed/",
    "https://unit42.paloaltonetworks.com/feed/",
    "https://feeds.feedburner.com/feedburner/Talos",
    "https://www.nist.gov/blogs/cybersecurity-insights/rss.xml",
    "https://www.bleepingcomputer.com/feed/",
]
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


def make_exa_mcp_client(api_key: str) -> MCPClient:
    query = urlencode({"exaApiKey": api_key})
    return MCPClient(lambda: streamable_http_client(f"{EXA_MCP_BASE_URL}?{query}"))


def browser_headers_for(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}/" if parsed.scheme and parsed.netloc else url
    return {**BROWSER_HEADERS, "Referer": origin}


def clean_article_text(html: str) -> tuple[str, str]:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg", "form", "nav", "footer", "aside"]):
        tag.decompose()

    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()

    body = soup.find("article") or soup.find("main") or soup.body or soup
    text = body.get_text("\n", strip=True)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    deduped: list[str] = []
    seen: set[str] = set()
    for line in lines:
        normalized = " ".join(line.split())
        if len(normalized) < 30 or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)

    return title, "\n".join(deduped)[:ARTICLE_MAX_CHARS]


@tool
def fetch_rss_feed(url: str, max_entries: int = DEFAULT_FEED_LIMIT) -> dict[str, Any]:
    """Fetch a bounded RSS feed using the Strands community rss tool.

    Args:
        url: RSS or Atom feed URL.
        max_entries: Maximum number of entries to return.

    Returns:
        A compact feed result with title, link, published date, author, and categories.
    """
    limit = max(1, min(max_entries, 10))
    result = rss_tool(action="fetch", url=url, max_entries=limit, include_content=False)
    if isinstance(result, dict) and result.get("status") == "error":
        return {"feed_url": url, "error": result}
    if not isinstance(result, list):
        return {"feed_url": url, "error": result}

    entries = []
    for entry in result[:limit]:
        if not isinstance(entry, dict):
            continue
        entries.append(
            {
                "title": entry.get("title", "Untitled"),
                "link": entry.get("link", ""),
                "published": entry.get("published", "Unknown date"),
                "author": entry.get("author", "Unknown author"),
                "categories": (entry.get("categories") or [])[:5],
            }
        )

    return {"feed_url": url, "max_entries": limit, "entries": entries}


@tool
def fetch_article(url: str) -> dict[str, Any]:
    """Fetch an article URL and return bounded clean text for deeper summarisation.

    Args:
        url: The HTTP or HTTPS article URL to fetch.

    Returns:
        A dictionary with the URL, page title, extracted text, and any fetch error.
    """
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {"url": url, "error": "Invalid HTTP(S) URL."}

    try:
        response = requests.get(url, timeout=25, headers=browser_headers_for(url))
        response.raise_for_status()
    except requests.RequestException as exc:
        return {"url": url, "error": str(exc)}

    title, text = clean_article_text(response.text)
    if not text:
        return {"url": url, "title": title, "error": "No article text could be extracted."}

    return {
        "url": url,
        "title": title,
        "text": text,
        "truncated_to_chars": ARTICLE_MAX_CHARS,
    }


@tool
def exa_web_search(query: str, max_results: int = 5) -> dict[str, Any]:
    """Search the web through Exa's remote MCP server for corroborating article details.

    Args:
        query: The web search query.
        max_results: Maximum number of search results to request when the MCP tool supports it.

    Returns:
        Search results from Exa's web_search_exa MCP tool, or an error message.
    """
    api_key = os.environ.get("EXA_API_KEY", "").strip()
    if not api_key:
        return {"error": "EXA_API_KEY is not set."}

    client = make_exa_mcp_client(api_key)
    with client:
        tools = client.list_tools_sync()
        search_tool = next((tool for tool in tools if tool.mcp_tool.name == "web_search_exa"), None)
        if search_tool is None:
            names = [tool.mcp_tool.name for tool in tools]
            search_tool = next((tool for tool in tools if "search" in tool.mcp_tool.name), None)
            if search_tool is None:
                return {"error": "No Exa search tool found.", "available_tools": names}

        input_schema = search_tool.mcp_tool.inputSchema or {}
        properties = input_schema.get("properties") or {}
        arguments: dict[str, Any] = {}

        if "query" in properties or not properties:
            arguments["query"] = query
        elif "q" in properties:
            arguments["q"] = query
        else:
            arguments["query"] = query

        for limit_field in ("numResults", "num_results", "maxResults", "limit"):
            if limit_field in properties:
                arguments[limit_field] = max(1, min(max_results, 10))
                break

        return {
            "tool": search_tool.mcp_tool.name,
            "arguments": arguments,
            "result": client.call_tool_sync(
                tool_use_id=str(uuid.uuid4()),
                name=search_tool.mcp_tool.name,
                arguments=arguments,
            ),
        }


def result_text(value: Any) -> str:
    result = getattr(value, "result", value)
    message = getattr(result, "message", None)
    if isinstance(message, dict):
        parts = message.get("content") or []
        texts = [part.get("text", "") for part in parts if isinstance(part, dict)]
        return "\n".join(texts).strip()
    return str(result).strip()


def build_swarm(
    read_timeout: int,
    connect_timeout: int,
    max_tokens: int,
    offload_max_result_tokens: int,
    offload_preview_tokens: int,
    enable_context_offload: bool = True,
    enable_exa_search: bool = False,
) -> Swarm:
    model = make_model(read_timeout, connect_timeout, max_tokens)
    article_tools: list[Any] = [fetch_article]
    if enable_exa_search:
        article_tools.append(exa_web_search)
    offload_storage = InMemoryStorage()

    def context_offloader_plugins() -> list[ContextOffloader]:
        if not enable_context_offload:
            return []
        return [
            ContextOffloader(
                storage=offload_storage,
                max_result_tokens=offload_max_result_tokens,
                preview_tokens=offload_preview_tokens,
            )
        ]

    feed_collector = Agent(
        name="feed_collector",
        model=model,
        system_prompt="""You collect RSS feed items for a news briefing.

Use fetch_rss_feed for every feed URL in the user's request. Pass the requested
per-feed item limit as max_entries. Keep only items whose publication date is on
or after the cutoff date. If an item has no publication date, keep it only when
it clearly appears recent. Return a compact structured list with feed, title,
URL, publication date, and at most one short relevance note per item.

After collecting the list, always hand off to article_researcher with the
structured list. Do not write the final briefing yourself.""",
        tools=[fetch_rss_feed],
        plugins=context_offloader_plugins(),
        callback_handler=None,
    )

    article_researcher = Agent(
        name="article_researcher",
        model=model,
        system_prompt="""You enrich RSS items with article-page details.

Select the most relevant and non-duplicative article URLs from the feed list,
respecting the user's max article count. Prefer primary articles, major security
or AWS-impact items, and items with concrete operational detail. Call
fetch_article for each selected URL. Use remote MCP web-search tools when they
are available to find relevant corroborating or follow-up coverage, especially
when a feed item is sparse, an article fetch fails, or the topic needs extra
context. Preserve source URLs and note fetch or search errors.

After fetching details, always hand off to briefing_writer with the RSS list,
article details, web-search findings, and fetch errors. Do not write the final
briefing yourself.""",
        tools=article_tools,
        plugins=context_offloader_plugins(),
        callback_handler=None,
    )

    briefing_writer = Agent(
        name="briefing_writer",
        model=model,
        system_prompt="""You write concise RSS briefings from feed items and fetched article details.

Use only facts from the RSS entries and fetched article text. Include:
- Coverage window
- Executive summary with the most important themes
- Top stories as numbered items with title, source URL, date, 2-4 sentence summary,
  and why it matters
- Notable patterns across feeds
- Fetch and web-search limitations, including URLs that failed or were blocked

Do not hand off unless the input is missing RSS data, in which case hand off to
feed_collector and ask it to collect the feeds first.""",
        plugins=context_offloader_plugins(),
        callback_handler=None,
    )

    return Swarm(
        nodes=[feed_collector, article_researcher, briefing_writer],
        entry_point=feed_collector,
        max_handoffs=6,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--feed",
        action="append",
        dest="feeds",
        help="RSS feed URL. Repeat to provide multiple feeds. Defaults to security/AWS feeds.",
    )
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS, help="Lookback window in days.")
    parser.add_argument(
        "--feed-limit",
        type=int,
        default=DEFAULT_FEED_LIMIT,
        help="Maximum RSS items to keep per feed before handoff.",
    )
    parser.add_argument(
        "--max-articles",
        type=int,
        default=DEFAULT_MAX_ARTICLES,
        help="Maximum article pages to fetch for details.",
    )
    parser.add_argument(
        "--no-exa",
        action="store_true",
        help="Disable Exa remote MCP web-search tools even when EXA_API_KEY is set.",
    )
    parser.add_argument(
        "--read-timeout",
        type=int,
        default=DEFAULT_BEDROCK_READ_TIMEOUT,
        help="Bedrock Runtime read timeout in seconds.",
    )
    parser.add_argument(
        "--connect-timeout",
        type=int,
        default=DEFAULT_BEDROCK_CONNECT_TIMEOUT,
        help="Bedrock Runtime connect timeout in seconds.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=DEFAULT_MODEL_MAX_TOKENS,
        help="Maximum output tokens for each Bedrock model call.",
    )
    parser.add_argument(
        "--no-context-offload",
        action="store_true",
        help="Disable Strands ContextOffloader for large tool results.",
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
    args = parser.parse_args()

    feeds = args.feeds or DEFAULT_FEEDS
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=args.days)
    feed_lines = "\n".join(f"- {feed}" for feed in feeds)

    prompt = f"""Summarize these RSS feeds from the last {args.days} days.

Current UTC time: {now.isoformat(timespec="seconds")}
Cutoff UTC date: {cutoff.date().isoformat()}
Maximum article pages to fetch for details: {args.max_articles}
Maximum RSS items to keep per feed: {args.feed_limit}

Feeds:
{feed_lines}

Collect the feed items first, fetch relevant articles for more detail, then
write the final briefing."""

    exa_api_key = os.environ.get("EXA_API_KEY", "").strip()
    enable_exa_search = bool(exa_api_key and not args.no_exa)
    if not exa_api_key and not args.no_exa:
        print("EXA_API_KEY is not set; continuing without remote MCP web search.\n")

    if not args.no_context_offload and args.offload_preview >= args.offload_threshold:
        parser.error("--offload-preview must be less than --offload-threshold")

    enable_context_offload = not args.no_context_offload
    swarm = build_swarm(
        args.read_timeout,
        args.connect_timeout,
        args.max_tokens,
        args.offload_threshold,
        args.offload_preview,
        enable_context_offload,
        enable_exa_search,
    )
    exa_status = "enabled" if enable_exa_search else "disabled"
    offload_status = (
        f"enabled over {args.offload_threshold} tokens"
        if enable_context_offload
        else "disabled"
    )
    print(
        f"Collecting {len(feeds)} RSS feeds with up to {args.feed_limit} items per feed, "
        f"fetching up to {args.max_articles} articles, Exa MCP web search is {exa_status}, "
        f"ContextOffloader is {offload_status}, Bedrock read timeout is {args.read_timeout}s, "
        f"and max_tokens is {args.max_tokens}...\n"
    )
    result = swarm(prompt)

    node_history = [node.node_id for node in result.node_history]
    final_agent = node_history[-1] if node_history else "briefing_writer"
    final_result = result.results.get(final_agent) or result.results.get("briefing_writer") or result

    print(f"Final agent: {final_agent}")
    print(f"Node history: {node_history}\n")
    print(result_text(final_result))


if __name__ == "__main__":
    main()
