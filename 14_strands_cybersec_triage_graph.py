"""
Hello World: Strands Graph — cyber-security triage pipeline
Runs a deterministic multi-agent graph over a PDF or URL:
  extract context -> threat triage -> IOC/CVE extraction -> defensive plan -> briefing

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python 14_strands_cybersec_triage_graph.py --url https://example.com/report
         uv run python 14_strands_cybersec_triage_graph.py --pdf ./report.pdf
         uv run python 14_strands_cybersec_triage_graph.py --html ./saved-page.html
"""

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)
import argparse
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import boto3
import markdownify
import requests
from bs4 import BeautifulSoup
from strands import Agent, tool
from strands.models import BedrockModel
from strands.multiagent import GraphBuilder

from pdf_utils import extract_pdf_text_from_path

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
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
EUVD_ID_RE = re.compile(r"^EUVD-\d{4}-\d{4,}$", re.IGNORECASE)
CVEDB_BASE_URL = "https://cvedb.shodan.io"


def summarize_cve_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": record.get("cve_id"),
        "summary": record.get("summary"),
        "cvss": record.get("cvss"),
        "cvss_version": record.get("cvss_version"),
        "epss": record.get("epss"),
        "ranking_epss": record.get("ranking_epss"),
        "kev": record.get("kev"),
        "ransomware_campaign": record.get("ransomware_campaign"),
        "published_time": record.get("published_time"),
        "propose_action": record.get("propose_action"),
        "references": (record.get("references") or [])[:5],
        "cpes": (record.get("cpes") or [])[:10],
    }


def summarize_euvd_record(record: dict[str, Any]) -> dict[str, Any]:
    cve = record.get("cve") or {}
    return {
        "euvd_id": record.get("euvd_id"),
        "description": record.get("description"),
        "cvss": record.get("cvss"),
        "cvss_version": record.get("cvss_version"),
        "epss": record.get("epss"),
        "published_time": record.get("published_time"),
        "assigner": record.get("assigner"),
        "vendors": record.get("vendors") or [],
        "products": record.get("products") or [],
        "references": (record.get("references") or [])[:5],
        "linked_cve": {
            "cve_id": cve.get("id"),
            "summary": cve.get("summary"),
            "cvss": cve.get("cvss"),
            "epss": cve.get("epss"),
            "kev": cve.get("kev"),
            "references": (cve.get("references") or [])[:5],
        } if cve else None,
    }


@tool
def lookup_cve(cve_id: str) -> dict[str, Any]:
    """Look up CVE details from Shodan CVEDB.

    Args:
        cve_id: CVE identifier in CVE-YYYY-NNNN format.

    Returns:
        Selected CVE details including summary, CVSS, EPSS, KEV status, references, and CPEs.
    """
    normalized = cve_id.strip().upper()
    if not CVE_ID_RE.match(normalized):
        return {"error": f"Invalid CVE ID: {cve_id}"}

    try:
        response = requests.get(f"{CVEDB_BASE_URL}/cve/{normalized}", timeout=15)
        response.raise_for_status()
    except requests.RequestException as exc:
        return {"cve_id": normalized, "error": str(exc)}

    return summarize_cve_record(response.json())


@tool
def lookup_euvd(euvd_id: str) -> dict[str, Any]:
    """Look up EUVD details from Shodan CVEDB.

    Args:
        euvd_id: EUVD identifier in EUVD-YYYY-NNNN format.

    Returns:
        Selected EUVD details including description, CVSS, EPSS, references, affected products, and linked CVE data.
    """
    normalized = euvd_id.strip().upper()
    if not EUVD_ID_RE.match(normalized):
        return {"error": f"Invalid EUVD ID: {euvd_id}"}

    try:
        response = requests.get(f"{CVEDB_BASE_URL}/euvd/{normalized}", timeout=15)
        response.raise_for_status()
    except requests.RequestException as exc:
        return {"euvd_id": normalized, "error": str(exc)}

    return summarize_euvd_record(response.json())


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


def load_one_source(kind: str, value: str, index: int) -> str:
    label = f"Source {index}: {kind} - {value}"
    if kind == "PDF":
        text = extract_pdf_text_from_path(value)
        if not text:
            raise ValueError(f"No text could be extracted from the PDF: {value}")
        return f"{label}\n\n{text[:MAX_CHARS]}"

    if kind == "HTML":
        html = Path(value).read_text(errors="replace")
        text = html_to_markdown(html)
        return f"{label}\n\n{text[:MAX_CHARS]}"

    if kind == "TEXT":
        text = Path(value).read_text(errors="replace")
        return f"{label}\n\n{text[:MAX_CHARS]}"

    if kind == "URL":
        text = fetch_url_markdown(value)
        return f"{label}\n\n{text[:MAX_CHARS]}"

    raise ValueError(f"Unsupported source kind: {kind}")


def load_sources(
    pdf_paths: list[str] | None,
    urls: list[str] | None,
    html_paths: list[str] | None,
    text_paths: list[str] | None,
) -> str:
    source_specs: list[tuple[str, str]] = []
    source_specs.extend(("PDF", path) for path in pdf_paths or [])
    source_specs.extend(("URL", item) for item in urls or [])
    source_specs.extend(("HTML", path) for path in html_paths or [])
    source_specs.extend(("TEXT", path) for path in text_paths or [])

    if not source_specs:
        raise ValueError("Pass --pdf, --url, --html, or --text at least once.")

    sections = [
        load_one_source(kind, value, index)
        for index, (kind, value) in enumerate(source_specs, start=1)
    ]
    return "\n\n---\n\n".join(sections)


def load_source(
    pdf_path: str | None,
    url: str | None,
    html_path: str | None,
    text_path: str | None,
) -> str:
    """Backward-compatible single-source loader."""
    if pdf_path:
        text = extract_pdf_text_from_path(pdf_path)
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
            "or short source phrases when available. When CVE or EUVD IDs are present, "
            "call lookup_cve or lookup_euvd to enrich them with CVSS, EPSS, KEV, "
            "references, affected CPEs, products, and linked CVE data. Do not invent "
            "missing indicators. Put the lookup details directly under the matching "
            "CVE or EUVD indicator instead of only listing them separately."
        ),
        tools=[lookup_cve, lookup_euvd],
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
    parser.add_argument("--pdf", action="append", help="Path to a PDF report. Repeat for multiple PDFs.")
    parser.add_argument("--url", action="append", help="URL to fetch and analyze. Repeat for multiple URLs.")
    parser.add_argument("--html", action="append", help="Path to a saved HTML page. Repeat for multiple files.")
    parser.add_argument("--text", action="append", help="Path to a text/markdown file. Repeat for multiple files.")
    args = parser.parse_args()

    source = load_sources(args.pdf, args.url, args.html, args.text)
    graph = build_graph()
    result = graph(
        "Analyze these cyber-security sources together through the triage graph. "
        "Preserve concrete facts and cite source names, source URLs, or short source "
        "phrases when possible.\n\n"
        f"{source}"
    )

    print(f"Status: {result.status}")
    print(f"Execution order: {[node.node_id for node in result.execution_order]}\n")
    final = result.results.get("briefing")
    print(result_text(final if final is not None else result))


if __name__ == "__main__":
    main()
