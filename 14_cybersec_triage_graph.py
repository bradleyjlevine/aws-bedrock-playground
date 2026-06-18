"""
Hello World: Strands Graph — cyber-security triage pipeline
Runs a deterministic multi-agent graph over a PDF or URL:
  extract context -> threat triage -> IOC/CVE extraction -> defensive plan -> briefing

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python 14_cybersec_triage_graph.py --url https://example.com/report
         uv run python 14_cybersec_triage_graph.py --pdf ./report.pdf
         uv run python 14_cybersec_triage_graph.py --html ./saved-page.html
"""
import argparse
import io
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import boto3
import markdownify
import pypdf
import requests
from bs4 import BeautifulSoup
from strands import Agent
from strands.models import BedrockModel
from strands.multiagent import GraphBuilder

REGION = "us-east-1"
MODEL_ID = "openai.gpt-oss-120b-1:0"
MAX_CHARS = 90_000
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


def make_model() -> BedrockModel:
    profile = os.environ.get("AWS_PROFILE")
    session = boto3.Session(profile_name=profile, region_name=REGION)
    return BedrockModel(model_id=MODEL_ID, boto_session=session)


def browser_headers_for(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}/" if parsed.scheme and parsed.netloc else url
    return {**BROWSER_HEADERS, "Referer": origin}


def fetch_url_markdown(url: str) -> str:
    try:
        resp = requests.get(url, timeout=25, headers=browser_headers_for(url))
        resp.raise_for_status()
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 403:
            raise ValueError(
                "The site returned HTTP 403 Forbidden. It is likely blocking automated "
                "fetches. Open the page in a browser, save it as HTML, then rerun with "
                "--html ./saved-page.html."
            ) from exc
        raise
    return html_to_markdown(resp.text)


def html_to_markdown(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg"]):
        tag.decompose()
    return markdownify.markdownify(str(soup), heading_style="ATX").strip()


def load_source(
    pdf_path: str | None,
    url: str | None,
    html_path: str | None,
    text_path: str | None,
) -> str:
    if pdf_path:
        with open(pdf_path, "rb") as f:
            reader = pypdf.PdfReader(io.BytesIO(f.read()))
        text = "\n\n".join(page.extract_text() or "" for page in reader.pages).strip()
        if not text:
            raise ValueError("No text could be extracted from the PDF.")
        return f"Source: {pdf_path}\n\n{text[:MAX_CHARS]}"

    if html_path:
        html = Path(html_path).read_text(errors="replace")
        text = html_to_markdown(html)
        return f"Source: {html_path}\n\n{text[:MAX_CHARS]}"

    if text_path:
        text = Path(text_path).read_text(errors="replace")
        return f"Source: {text_path}\n\n{text[:MAX_CHARS]}"

    if url:
        text = fetch_url_markdown(url)
        return f"Source: {url}\n\n{text[:MAX_CHARS]}"

    raise ValueError("Pass --pdf, --url, --html, or --text.")


def result_text(value: Any) -> str:
    result = getattr(value, "result", value)
    message = getattr(result, "message", None)
    if isinstance(message, dict):
        parts = message.get("content") or []
        texts = [part.get("text", "") for part in parts if isinstance(part, dict)]
        return "\n".join(texts).strip()
    return str(result).strip()


def build_graph():
    model = make_model()

    triage = Agent(
        name="triage",
        model=model,
        system_prompt=(
            "You classify cyber-security source material. Identify the threat type, "
            "likely affected sectors, severity, attacker intent, and what changed."
        ),
        callback_handler=None,
    )
    ioc_extractor = Agent(
        name="ioc_extractor",
        model=model,
        system_prompt=(
            "You extract concrete security facts. Return CVEs, malware names, actor "
            "names, IPs, domains, hashes, product names, versions, dates, and citations "
            "or short source phrases when available. Do not invent missing indicators."
        ),
        callback_handler=None,
    )
    defender = Agent(
        name="defender",
        model=model,
        system_prompt=(
            "You convert threat intelligence into defensive action. Prioritize detection, "
            "patching, containment, logging, and executive risk decisions."
        ),
        callback_handler=None,
    )
    briefing = Agent(
        name="briefing",
        model=model,
        system_prompt=(
            "You write final incident-style briefings from upstream graph outputs. "
            "Use sections: Executive Summary, What Changed, Evidence, Recommended Actions, "
            "Open Questions. Be concise and specific."
        ),
        callback_handler=None,
    )

    builder = GraphBuilder()
    builder.add_node(triage, "triage")
    builder.add_node(ioc_extractor, "iocs")
    builder.add_node(defender, "defense")
    builder.add_node(briefing, "briefing")
    builder.add_edge("triage", "iocs")
    builder.add_edge("triage", "defense")
    builder.add_edge("iocs", "briefing")
    builder.add_edge("defense", "briefing")
    builder.set_entry_point("triage")
    builder.set_execution_timeout(600)
    return builder.build()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pdf", help="Path to a PDF report.")
    parser.add_argument("--url", help="URL to fetch and analyze.")
    parser.add_argument("--html", help="Path to a saved HTML page to analyze.")
    parser.add_argument("--text", help="Path to a plain text or markdown file to analyze.")
    args = parser.parse_args()

    source = load_source(args.pdf, args.url, args.html, args.text)
    graph = build_graph()
    result = graph(
        "Analyze this cyber-security source through the triage graph. "
        "Preserve concrete facts and cite source phrases when possible.\n\n"
        f"{source}"
    )

    print(f"Status: {result.status}")
    print(f"Execution order: {[node.node_id for node in result.execution_order]}\n")
    final = result.results.get("briefing")
    print(result_text(final if final is not None else result))


if __name__ == "__main__":
    main()
