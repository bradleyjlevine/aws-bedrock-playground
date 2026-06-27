"""
Hello World: Strands Graph — cyber-security triage pipeline
Runs a deterministic multi-agent graph over a PDF or URL:
  extract context -> threat triage -> IOC/CVE extraction -> defensive plan -> briefing

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python examples/cybersecurity/14_strands_cybersec_triage_graph.py --url https://example.com/report
         uv run python examples/cybersecurity/14_strands_cybersec_triage_graph.py --pdf ./report.pdf
         uv run python examples/cybersecurity/14_strands_cybersec_triage_graph.py --html ./saved-page.html
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)
import argparse
import os
from typing import Any

import boto3
from strands import Agent, tool
from strands.models import BedrockModel
from strands.multiagent import GraphBuilder

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


def make_model() -> BedrockModel:
    profile = os.environ.get("AWS_PROFILE")
    session = boto3.Session(profile_name=profile, region_name=REGION)
    return BedrockModel(model_id=MODEL_ID, boto_session=session)


def load_sources(
    pdf_paths: list[str] | None,
    urls: list[str] | None,
    html_paths: list[str] | None,
    text_paths: list[str] | None,
) -> str:
    return load_source_sections(pdf_paths, urls, html_paths, text_paths, max_chars=MAX_CHARS)


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
