"""
Hello World: Strands Structured Output — typed cyber-security summary
Extracts a PDF or URL into a validated Pydantic object instead of free-form text.

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python 15_structured_cybersec_output.py --url https://example.com/report
         uv run python 15_structured_cybersec_output.py --pdf ./report.pdf
         uv run python 15_structured_cybersec_output.py --html ./saved-page.html
"""
import argparse
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import boto3
import markdownify
import requests
from bs4 import BeautifulSoup
from pydantic import BaseModel, Field
from strands import Agent, tool
from strands.models import BedrockModel

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


class VulnerabilityDetails(BaseModel):
    """Optional enrichment for CVE or EUVD indicators."""

    summary: str | None = Field(description="CVEDB summary or EUVD description")
    cvss: float | None = Field(description="CVSS score from CVEDB, if available")
    cvss_version: float | str | None = Field(description="CVSS version from CVEDB, if available")
    epss: float | None = Field(description="EPSS probability from CVEDB, if available")
    kev: bool | None = Field(description="Whether the linked CVE is known exploited, if available")
    published_time: str | None = Field(description="Published timestamp from CVEDB, if available")
    linked_cve_id: str | None = Field(description="Linked CVE ID for EUVD records, if present")
    references: list[str] = Field(description="Up to five supporting references from CVEDB")
    affected_cpes_or_products: list[str] = Field(description="Affected CPEs, products, or vendors from CVEDB")


class CyberIndicator(BaseModel):
    """Concrete indicator or named security artifact from the source."""

    kind: str = Field(description="Type, e.g. CVE, EUVD, domain, IP, hash, malware, actor, product")
    cwe: str | None = Field(description=("IF kind = CVE THEN CWE (Common Weakness Enumeration),"
                                  " e.x CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
                                  "ELSE None"))
    value: str = Field(description="Exact indicator value or name")
    context: str = Field(description="Short explanation of why it matters")
    vulnerability_details: VulnerabilityDetails | None = Field(
        description=(
            "For CVE or EUVD indicators, details from lookup_cve or lookup_euvd. "
            "Use null for non-vulnerability indicators or when lookup fails."
        )
    )


class CyberAction(BaseModel):
    """Recommended defensive action."""

    priority: str = Field(description="high, medium, or low")
    owner: str = Field(description="Likely owning team or role")
    action: str = Field(description="Concrete action to take")
    rationale: str = Field(description="Why this action follows from the source")


class CyberBrief(BaseModel):
    """Validated cyber-security briefing extracted from source material."""

    title: str
    severity: str = Field(description="critical, high, medium, low, or informational")
    confidence: str = Field(description="high, medium, or low")
    executive_summary: str = Field(description="2-4 sentence plain-language summary")
    key_changes: list[str] = Field(description="What changed in the threat landscape")
    affected_products_or_sectors: list[str]
    indicators: list[CyberIndicator]
    recommended_actions: list[CyberAction]
    open_questions: list[str]


def make_agent() -> Agent:
    profile = os.environ.get("AWS_PROFILE")
    session = boto3.Session(profile_name=profile, region_name=REGION)
    model = BedrockModel(model_id=MODEL_ID, boto_session=session)
    return Agent(
        model=model,
        system_prompt=(
            "You are a cyber-security analyst. Extract only facts supported by the "
            "source. Use lookup_cve for CVE IDs and lookup_euvd for EUVD IDs when "
            "present so CVSS, EPSS, KEV status, linked CVEs, and recommendations can "
            "be grounded in current vulnerability data. Add successful lookup results "
            "to each matching indicator's vulnerability_details field. "
            "If evidence is thin, lower confidence and add open questions."
        ),
        tools=[lookup_cve, lookup_euvd],
        callback_handler=None,
    )


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pdf", action="append", help="Path to a PDF report. Repeat for multiple PDFs.")
    parser.add_argument("--url", action="append", help="URL to fetch and analyze. Repeat for multiple URLs.")
    parser.add_argument("--html", action="append", help="Path to a saved HTML page. Repeat for multiple files.")
    parser.add_argument("--text", action="append", help="Path to a text/markdown file. Repeat for multiple files.")
    args = parser.parse_args()

    source = load_sources(args.pdf, args.url, args.html, args.text)
    result = make_agent()(
        "Create a structured cyber-security briefing from these sources. "
        "Preserve source attribution in context fields and recommended-action rationales "
        "when a claim comes from a specific source.\n\n" + source,
        structured_output_model=CyberBrief,
    )

    print(json.dumps(result.structured_output.model_dump(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
