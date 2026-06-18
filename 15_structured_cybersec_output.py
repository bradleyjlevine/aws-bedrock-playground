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
import io
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import boto3
import markdownify
import pypdf
import requests
from bs4 import BeautifulSoup
from pydantic import BaseModel, Field
from strands import Agent
from strands.models import BedrockModel

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


class CyberIndicator(BaseModel):
    """Concrete indicator or named security artifact from the source."""

    kind: str = Field(description="Type, e.g. CVE, domain, IP, hash, malware, actor, product")
    cwe: str | None = Field(description=("IF kind = CVE THEN CWE (Common Weakness Enumeration),"
                                  " e.x CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
                                  "ELSE None"))
    value: str = Field(description="Exact indicator value or name")
    context: str = Field(description="Short explanation of why it matters")


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
            "source. If evidence is thin, lower confidence and add open questions."
        ),
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pdf", help="Path to a PDF report.")
    parser.add_argument("--url", help="URL to fetch and analyze.")
    parser.add_argument("--html", help="Path to a saved HTML page to analyze.")
    parser.add_argument("--text", help="Path to a plain text or markdown file to analyze.")
    args = parser.parse_args()

    source = load_source(args.pdf, args.url, args.html, args.text)
    result = make_agent()(
        "Create a structured cyber-security briefing from this source.\n\n" + source,
        structured_output_model=CyberBrief,
    )

    print(json.dumps(result.structured_output.model_dump(), indent=2))


if __name__ == "__main__":
    main()
