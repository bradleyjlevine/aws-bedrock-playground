"""
Hello World: Strands Structured Output — typed cyber-security summary
Extracts a PDF or URL into a validated Pydantic object instead of free-form text.

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python examples/cybersecurity/15_strands_structured_cybersec_brief.py --url https://example.com/report
         uv run python examples/cybersecurity/15_strands_structured_cybersec_brief.py --pdf ./report.pdf
         uv run python examples/cybersecurity/15_strands_structured_cybersec_brief.py --html ./saved-page.html
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
import os
from typing import Any

import boto3
from pydantic import BaseModel, Field
from strands import Agent, tool
from strands.models import BedrockModel

from cyber_source_utils import load_sources as load_source_sections
from cyber_vuln_utils import lookup_cve_record, lookup_euvd_record

REGION = "us-east-1"
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "openai.gpt-oss-120b-1:0")
MAX_CHARS = 90_000


@tool
def lookup_cve(cve_id: str) -> dict[str, Any]:
    """Look up CVE details from Shodan CVEDB.

    Args:
        cve_id: CVE identifier in CVE-YYYY-NNNN format.

    Returns:
        Selected CVE details including summary, CVSS, EPSS, KEV status, references, and CPEs.
    """
    return lookup_cve_record(cve_id)


@tool
def lookup_euvd(euvd_id: str) -> dict[str, Any]:
    """Look up EUVD details from Shodan CVEDB.

    Args:
        euvd_id: EUVD identifier in EUVD-YYYY-NNNN format.

    Returns:
        Selected EUVD details including description, CVSS, EPSS, references, affected products, and linked CVE data.
    """
    return lookup_euvd_record(euvd_id)


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


def load_sources(
    pdf_paths: list[str] | None,
    urls: list[str] | None,
    html_paths: list[str] | None,
    text_paths: list[str] | None,
) -> str:
    return load_source_sections(pdf_paths, urls, html_paths, text_paths, max_chars=MAX_CHARS)


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
