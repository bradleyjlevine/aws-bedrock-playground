"""
Hello World: Strands Threat Intel + Risk Chat
Interactive analyst chat for CVE/EUVD enrichment, MITRE/OWASP mapping, threat
modeling, and lightweight qualitative/quantitative risk analysis.

Examples:
  uv run python examples/cybersecurity/29_strands_threat_intel_risk_chat.py
  uv run python examples/cybersecurity/29_strands_threat_intel_risk_chat.py \
    --prompt "Explain CVE-2023-34362 and map it to CWE, ATT&CK, OWASP, STRIDE, and FAIR."

The tools use public sources where practical:
  - Shodan CVEDB for CVE/EUVD lookup
  - MITRE ATT&CK STIX data from mitre-attack/attack-stix-data
  - MITRE ATLAS data from mitre-atlas/atlas-data
  - MITRE CWE and CAPEC definition pages
  - Local reference tables for OWASP Top 10, STRIDE, PASTA, Lockheed Kill Chain,
    Unified Kill Chain, Security Cards, and risk calculations
  - Cached PDF-to-markdown references for Security Cards and Unified Kill Chain
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)
import argparse
import html
import json
import os
import random
import re
import statistics
import time
import zipfile
from functools import lru_cache
from typing import Any
from urllib.error import URLError
from urllib.request import Request as UrlRequest
from urllib.request import urlopen
from xml.etree import ElementTree

import boto3
from fastapi import FastAPI
from fastapi import Request as FastAPIRequest
from fastapi.responses import HTMLResponse, StreamingResponse
import uvicorn
from pydantic import BaseModel
from strands import Agent, tool
from strands.models import BedrockModel

REGION = "us-east-1"
MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
)

CVEDB_BASE_URL = "https://cvedb.shodan.io"
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
ATLAS_TREE_URL = "https://api.github.com/repos/mitre-atlas/atlas-data/git/trees/main?recursive=1"
ATLAS_RAW_BASE = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main"
CWE_DEFINITION_URL = "https://cwe.mitre.org/data/definitions/{id}.html"
CAPEC_DEFINITION_URL = "https://capec.mitre.org/data/definitions/{id}.html"
CAPEC_XML_ZIP_URL = "https://capec.mitre.org/data/xml/views/2000.xml.zip"
SECURITY_CARDS_URL = "https://securitycards.cs.washington.edu/assets/security-cards-deck-with-croplines.pdf"
UNIFIED_KILL_CHAIN_URL = "https://www.unifiedkillchain.com/assets/The-Unified-Kill-Chain.pdf"
REFERENCE_CACHE_DIR = ROOT / "downloads" / "threat_model_refs"

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
EUVD_ID_RE = re.compile(r"^EUVD-\d{4}-\d{4,}$", re.IGNORECASE)
CWE_ID_RE = re.compile(r"^(?:CWE-)?(\d+)$", re.IGNORECASE)
CAPEC_ID_RE = re.compile(r"^(?:CAPEC-)?(\d+)$", re.IGNORECASE)
CWE_MENTION_RE = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)
CAPEC_MENTION_RE = re.compile(r"\bCAPEC-(\d+)\b", re.IGNORECASE)
ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
SPACE_RE = re.compile(r"\s+")

ATTACK_QUERY_ALIASES = {
    "public-facing": ["T1190"],
    "public facing": ["T1190"],
    "remote code execution": ["T1190", "T1059"],
    "rce": ["T1190", "T1059"],
    "exploit public": ["T1190"],
    "web application": ["T1190"],
    "internet-facing": ["T1190"],
    "internet facing": ["T1190"],
    "command execution": ["T1059"],
    "script execution": ["T1059"],
    "powershell": ["T1059.001"],
    "shell": ["T1059.004"],
    "ldap": ["T1105", "T1071"],
    "jndi": ["T1190"],
    "log4shell": ["T1190", "T1059"],
    "spring4shell": ["T1190", "T1059"],
    "deserialization": ["T1190"],
    "data binding": ["T1190"],
    "initial access": ["T1190"],
}

OWASP_TOP_10_SOURCE = "https://owasp.org/www-project-top-ten/"
OWASP_TOP_10_2025_SOURCE = "https://owasp.org/Top10/2025/"
OWASP_TOP_10_2021_SOURCE = "https://owasp.org/Top10/"
OWASP_TOP_10 = {
    "2025": [
        ("A01:2025", "Broken Access Control", ["authorization", "idor", "access control", "privilege"]),
        ("A02:2025", "Security Misconfiguration", ["misconfiguration", "default", "header", "cloud config"]),
        ("A03:2025", "Software Supply Chain Failures", ["dependency", "component", "library", "supply chain", "ci/cd", "package"]),
        ("A04:2025", "Cryptographic Failures", ["crypto", "encryption", "tls", "sensitive data", "secret"]),
        ("A05:2025", "Injection", ["sql", "command", "ldap", "template", "injection"]),
        ("A06:2025", "Insecure Design", ["design", "architecture", "threat model", "business logic"]),
        ("A07:2025", "Authentication Failures", ["auth", "password", "session", "mfa", "credential"]),
        ("A08:2025", "Software or Data Integrity Failures", ["deserialization", "update", "integrity", "signed", "pipeline"]),
        ("A09:2025", "Security Logging and Alerting Failures", ["logging", "monitoring", "alert", "detection", "audit"]),
        ("A10:2025", "Mishandling of Exceptional Conditions", ["exception", "error", "failure", "timeout", "fallback", "edge case"]),
    ],
    "2021": [
        ("A01:2021", "Broken Access Control", ["authorization", "idor", "access control", "privilege"]),
        ("A02:2021", "Cryptographic Failures", ["crypto", "encryption", "tls", "sensitive data", "secret"]),
        ("A03:2021", "Injection", ["sql", "command", "ldap", "template", "injection"]),
        ("A04:2021", "Insecure Design", ["design", "architecture", "threat model", "business logic"]),
        ("A05:2021", "Security Misconfiguration", ["misconfiguration", "default", "header", "cloud config"]),
        ("A06:2021", "Vulnerable and Outdated Components", ["dependency", "component", "library", "cve"]),
        ("A07:2021", "Identification and Authentication Failures", ["auth", "password", "session", "mfa", "credential"]),
        ("A08:2021", "Software and Data Integrity Failures", ["ci/cd", "deserialization", "update", "integrity"]),
        ("A09:2021", "Security Logging and Monitoring Failures", ["logging", "monitoring", "alert", "detection", "audit"]),
        ("A10:2021", "Server-Side Request Forgery", ["ssrf", "metadata service", "url fetch"]),
    ],
}

STRIDE = {
    "Spoofing": "Can an actor pretend to be another user, service, host, or workload?",
    "Tampering": "Can data, code, requests, models, prompts, or configurations be modified?",
    "Repudiation": "Can actors deny actions because logs, identity, or audit integrity is weak?",
    "Information Disclosure": "Can secrets, PII, model data, or internal state be exposed?",
    "Denial of Service": "Can availability, quotas, cost, or model/service capacity be exhausted?",
    "Elevation of Privilege": "Can actors gain stronger privileges or cross trust boundaries?",
}

PASTA_STAGES = [
    "Define business and security objectives.",
    "Define technical scope and dependencies.",
    "Decompose the application or system.",
    "Analyze threats and threat communities.",
    "Identify vulnerabilities and weaknesses.",
    "Model attacks and abuse cases.",
    "Analyze risk and choose treatments.",
]

KILL_CHAIN = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command and Control",
    "Actions on Objectives",
]

UNIFIED_KILL_CHAIN = [
    "Reconnaissance",
    "Resource Development",
    "Delivery",
    "Social Engineering",
    "Exploitation",
    "Persistence",
    "Defense Evasion",
    "Command & Control",
    "Pivoting",
    "Discovery",
    "Privilege Escalation",
    "Execution",
    "Credential Access",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact",
    "Objectives",
]

SECURITY_CARD_PROMPTS = [
    "Human impact: who can be harmed, coerced, excluded, or put at physical/economic risk?",
    "Adversary motivation: who benefits financially, politically, operationally, or reputationally?",
    "Asset misuse: how could legitimate features be repurposed for abuse?",
    "Trust and assumptions: what hidden assumptions does the design make about users or operators?",
    "Failure and recovery: how does the system fail, alert, and recover after abuse?",
    "Supply chain: what external providers, data, models, plugins, or update paths can be abused?",
]


def _http_json(url: str, timeout: int = 20) -> Any:
    request = UrlRequest(url, headers={"User-Agent": "aws-bedrock-playground-threat-intel-demo"})
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _http_text(url: str, timeout: int = 20) -> str:
    request = UrlRequest(url, headers={"User-Agent": "aws-bedrock-playground-threat-intel-demo"})
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _download_file(url: str, path: Path, timeout: int = 60) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    request = UrlRequest(url, headers={"User-Agent": "aws-bedrock-playground-threat-intel-demo"})
    with urlopen(request, timeout=timeout) as response:
        path.write_bytes(response.read())


def _clean_html_text(markup: str) -> str:
    text = re.sub(r"<script.*?</script>", " ", markup, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = TAG_RE.sub(" ", text)
    return SPACE_RE.sub(" ", html.unescape(text)).strip()


def _score_text(query_terms: set[str], *parts: str) -> int:
    haystack = " ".join(part.lower() for part in parts if part)
    return sum(1 for term in query_terms if term in haystack)


def _attack_ids_for_query(query: str) -> set[str]:
    lowered = query.lower()
    ids = {match.upper() for match in ATTACK_ID_RE.findall(query)}
    for phrase, mapped_ids in ATTACK_QUERY_ALIASES.items():
        if phrase in lowered:
            ids.update(mapped_ids)
    return ids


def _reference_paths(reference_id: str) -> tuple[Path, Path]:
    safe_id = re.sub(r"[^a-z0-9_-]+", "_", reference_id.lower())
    return REFERENCE_CACHE_DIR / f"{safe_id}.pdf", REFERENCE_CACHE_DIR / f"{safe_id}.md"


def _capec_cache_paths() -> tuple[Path, Path]:
    return REFERENCE_CACHE_DIR / "capec_latest.xml.zip", REFERENCE_CACHE_DIR / "capec_latest.xml"


def _xml_text(element: ElementTree.Element | None) -> str:
    if element is None:
        return ""
    return SPACE_RE.sub(" ", " ".join(element.itertext())).strip()


def _xml_children(element: ElementTree.Element, name: str) -> list[ElementTree.Element]:
    return [child for child in element if child.tag.rsplit("}", 1)[-1] == name]


def _xml_child(element: ElementTree.Element, name: str) -> ElementTree.Element | None:
    children = _xml_children(element, name)
    return children[0] if children else None


def _pdf_markdown_with_unstructured(pdf_path: Path) -> str:
    from unstructured.partition.pdf import partition_pdf

    elements = partition_pdf(filename=str(pdf_path), strategy="fast")
    blocks = []
    for index, element in enumerate(elements, start=1):
        text = str(element).strip()
        if not text:
            continue
        category = element.__class__.__name__
        page = getattr(getattr(element, "metadata", None), "page_number", None)
        prefix = f"## {index}. {category}"
        if page:
            prefix += f" (page {page})"
        blocks.append(f"{prefix}\n\n{text}")
    return "\n\n".join(blocks)


def _pdf_markdown_with_pypdf(pdf_path: Path) -> str:
    from pypdf import PdfReader

    reader = PdfReader(str(pdf_path))
    blocks = []
    for index, page in enumerate(reader.pages, start=1):
        text = (page.extract_text() or "").strip()
        if text:
            blocks.append(f"## Page {index}\n\n{text}")
    return "\n\n".join(blocks)


@lru_cache(maxsize=8)
def load_pdf_reference_markdown(reference_id: str, title: str, source_url: str) -> dict[str, Any]:
    pdf_path, md_path = _reference_paths(reference_id)
    if md_path.exists():
        markdown = md_path.read_text(encoding="utf-8", errors="replace")
        extractor_match = re.search(r"^Extractor:\s*(.+)$", markdown, flags=re.MULTILINE)
        return {
            "title": title,
            "source": source_url,
            "pdf_cache": str(pdf_path),
            "markdown_cache": str(md_path),
            "extractor": extractor_match.group(1) if extractor_match else "cached markdown",
            "fetched": pdf_path.exists(),
            "markdown": markdown,
        }

    if not pdf_path.exists():
        _download_file(source_url, pdf_path)

    extractor = "unstructured"
    try:
        body = _pdf_markdown_with_unstructured(pdf_path)
    except Exception as exc:  # noqa: BLE001 - fallback keeps the chat demo usable.
        extractor = f"pypdf fallback after Unstructured error: {exc}"
        body = _pdf_markdown_with_pypdf(pdf_path)

    markdown = f"# {title}\n\nSource: {source_url}\nExtractor: {extractor}\n\n{body}\n"
    md_path.write_text(markdown, encoding="utf-8")
    return {
        "title": title,
        "source": source_url,
        "pdf_cache": str(pdf_path),
        "markdown_cache": str(md_path),
        "extractor": extractor,
        "fetched": True,
        "markdown": markdown,
    }


def _select_markdown_excerpts(markdown: str, query: str, max_chars: int = 4_000) -> list[str]:
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", markdown) if part.strip()]
    if not query.strip():
        return ["\n\n".join(paragraphs)[:max_chars]]
    terms = {term for term in re.findall(r"[a-z0-9]+", query.lower()) if len(term) > 2}
    scored = [
        (_score_text(terms, paragraph), index, paragraph)
        for index, paragraph in enumerate(paragraphs)
    ]
    selected = []
    used = 0
    for score, _, paragraph in sorted(scored, key=lambda item: (item[0], -item[1]), reverse=True):
        if score <= 0 and selected:
            break
        remaining = max_chars - used
        if remaining <= 0:
            break
        clipped = paragraph[:remaining]
        selected.append(clipped)
        used += len(clipped) + 2
    return selected or ["\n\n".join(paragraphs)[:max_chars]]


REFERENCE_REGISTRY = {
    "security_cards": {
        "title": "Security Cards",
        "source": SECURITY_CARDS_URL,
        "aliases": {"security_cards", "security cards", "cards"},
    },
    "unified_kill_chain": {
        "title": "Unified Kill Chain",
        "source": UNIFIED_KILL_CHAIN_URL,
        "aliases": {"unified_kill_chain", "unified kill chain", "ukc"},
    },
}


def _resolve_reference_ids(reference: str) -> list[str]:
    requested = reference.strip().lower().replace("-", " ").replace("_", " ")
    if requested in {"", "all", "both"}:
        return list(REFERENCE_REGISTRY)

    resolved = []
    for reference_id, metadata in REFERENCE_REGISTRY.items():
        aliases = {alias.replace("_", " ") for alias in metadata["aliases"]}
        if requested == reference_id.replace("_", " ") or requested in aliases:
            resolved.append(reference_id)
    return resolved


@tool
def get_threat_model_reference(reference: str = "both", query: str = "") -> dict[str, Any]:
    """Load cached PDF-derived threat-modeling reference excerpts.

    Downloads Security Cards and Unified Kill Chain PDFs on first use, extracts
    text to markdown with Unstructured, falls back to pypdf if needed, and reuses
    the cached markdown for later chats.

    Args:
        reference: security_cards, unified_kill_chain, both, all, cards, or ukc.
        query: Optional topic used to select the most relevant markdown excerpts.

    Returns:
        Source URLs, cache paths, extractor metadata, and bounded markdown excerpts.
    """
    reference_ids = _resolve_reference_ids(reference)
    if not reference_ids:
        return {
            "error": "reference must be security_cards, unified_kill_chain, both, all, cards, or ukc",
            "requested_reference": reference,
            "available_references": sorted(REFERENCE_REGISTRY),
        }

    results = {}
    for reference_id in reference_ids:
        metadata = REFERENCE_REGISTRY[reference_id]
        try:
            loaded = load_pdf_reference_markdown(
                reference_id,
                str(metadata["title"]),
                str(metadata["source"]),
            )
            markdown = loaded.pop("markdown")
            loaded["excerpts"] = _select_markdown_excerpts(markdown, query)
            loaded["excerpt_query"] = query
            results[reference_id] = loaded
        except Exception as exc:  # noqa: BLE001 - surface per-reference failures to the agent.
            results[reference_id] = {
                "title": metadata["title"],
                "source": metadata["source"],
                "error": str(exc),
            }

    return {
        "cache_directory": str(REFERENCE_CACHE_DIR),
        "references": results,
    }


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


def _capec_xml_path() -> Path:
    zip_path, xml_path = _capec_cache_paths()
    if xml_path.exists():
        return xml_path

    if not zip_path.exists():
        _download_file(CAPEC_XML_ZIP_URL, zip_path, timeout=60)

    with zipfile.ZipFile(zip_path) as archive:
        xml_names = [name for name in archive.namelist() if name.lower().endswith(".xml")]
        if not xml_names:
            raise ValueError("CAPEC XML zip did not contain an XML file.")
        xml_path.parent.mkdir(parents=True, exist_ok=True)
        xml_path.write_bytes(archive.read(xml_names[0]))
    return xml_path


def _capec_pattern_from_xml(element: ElementTree.Element) -> dict[str, Any]:
    capec_id = element.attrib.get("ID", "")
    description = _xml_text(_xml_child(element, "Description"))
    related_weaknesses = []
    related_weaknesses_element = _xml_child(element, "Related_Weaknesses")
    if related_weaknesses_element is not None:
        for weakness in _xml_children(related_weaknesses_element, "Related_Weakness"):
            cwe_id = weakness.attrib.get("CWE_ID")
            if cwe_id:
                related_weaknesses.append(f"CWE-{cwe_id}")

    taxonomy_mappings = []
    taxonomy_mappings_element = _xml_child(element, "Taxonomy_Mappings")
    if taxonomy_mappings_element is not None:
        for mapping in _xml_children(taxonomy_mappings_element, "Taxonomy_Mapping"):
            taxonomy_mappings.append(
                {
                    "taxonomy": mapping.attrib.get("Taxonomy_Name", ""),
                    "entry_id": mapping.attrib.get("Entry_ID", ""),
                    "entry_name": mapping.attrib.get("Entry_Name", ""),
                }
            )

    prerequisites = []
    prerequisites_element = _xml_child(element, "Prerequisites")
    if prerequisites_element is not None:
        for prerequisite in _xml_children(prerequisites_element, "Prerequisite"):
            text = _xml_text(prerequisite)
            if text:
                prerequisites.append(text)

    mitigations = []
    mitigations_element = _xml_child(element, "Mitigations")
    if mitigations_element is not None:
        for mitigation in _xml_children(mitigations_element, "Mitigation"):
            text = _xml_text(mitigation)
            if text:
                mitigations.append(text)

    execution_steps = []
    execution_flow = _xml_child(element, "Execution_Flow")
    if execution_flow is not None:
        for attack_step in _xml_children(execution_flow, "Attack_Step"):
            phase = _xml_text(_xml_child(attack_step, "Phase"))
            technique = _xml_text(_xml_child(attack_step, "Technique"))
            description_text = _xml_text(_xml_child(attack_step, "Description"))
            if phase or technique or description_text:
                execution_steps.append(
                    {
                        "phase": phase,
                        "description": description_text[:500],
                        "technique": technique[:500],
                    }
                )

    return {
        "capec_id": f"CAPEC-{capec_id}",
        "name": element.attrib.get("Name", ""),
        "abstraction": element.attrib.get("Abstraction", ""),
        "status": element.attrib.get("Status", ""),
        "source": CAPEC_DEFINITION_URL.format(id=capec_id),
        "description": description[:1_200],
        "likelihood": _xml_text(_xml_child(element, "Likelihood_Of_Attack")),
        "severity": _xml_text(_xml_child(element, "Typical_Severity")),
        "related_weaknesses": related_weaknesses[:12],
        "taxonomy_mappings": taxonomy_mappings[:8],
        "prerequisites": prerequisites[:5],
        "mitigations": mitigations[:6],
        "execution_flow": execution_steps[:6],
    }


@lru_cache(maxsize=1)
def load_capec_patterns() -> list[dict[str, Any]]:
    tree = ElementTree.parse(_capec_xml_path())
    patterns = []
    for element in tree.iter():
        if element.tag.rsplit("}", 1)[-1] == "Attack_Pattern":
            patterns.append(_capec_pattern_from_xml(element))
    return patterns


@lru_cache(maxsize=1)
def capec_patterns_by_id() -> dict[str, dict[str, Any]]:
    return {
        pattern["capec_id"].upper(): pattern
        for pattern in load_capec_patterns()
        if pattern.get("capec_id")
    }


def _fallback_capec_html(capec_num: str) -> dict[str, str]:
    url = CAPEC_DEFINITION_URL.format(id=capec_num)
    try:
        text = _clean_html_text(_http_text(url))
    except (OSError, URLError, UnicodeDecodeError) as exc:
        return {"capec_id": f"CAPEC-{capec_num}", "source": url, "error": str(exc)}
    return {
        "capec_id": f"CAPEC-{capec_num}",
        "source": url,
        "excerpt": text[:1_500],
        "warning": "Used HTML fallback because the CAPEC XML cache could not be loaded.",
    }


@lru_cache(maxsize=1)
def load_attack_patterns() -> list[dict[str, Any]]:
    bundle = _http_json(ATTACK_STIX_URL)
    patterns = []
    for item in bundle.get("objects", []):
        if item.get("type") != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        external_id = None
        url = None
        for ref in item.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id")
                url = ref.get("url")
                break
        patterns.append(
            {
                "id": external_id,
                "name": item.get("name"),
                "description": item.get("description", "")[:1_200],
                "tactics": item.get("kill_chain_phases", []),
                "platforms": item.get("x_mitre_platforms", [])[:8],
                "url": url,
            }
        )
    return patterns


@lru_cache(maxsize=1)
def attack_patterns_by_id() -> dict[str, dict[str, Any]]:
    return {
        str(pattern.get("id")).upper(): pattern
        for pattern in load_attack_patterns()
        if pattern.get("id")
    }


@lru_cache(maxsize=16)
def load_atlas_records(query: str) -> list[dict[str, Any]]:
    tree = _http_json(ATLAS_TREE_URL)
    terms = {term for term in re.findall(r"[a-z0-9]+", query.lower()) if len(term) > 2}
    candidates = []
    for item in tree.get("tree", []):
        path = item.get("path", "")
        if item.get("type") != "blob" or not path.endswith((".yaml", ".yml", ".json", ".md")):
            continue
        score = _score_text(terms, path)
        if score:
            candidates.append((score, path))
    records = []
    for _, path in sorted(candidates, reverse=True)[:5]:
        try:
            content = _http_text(f"{ATLAS_RAW_BASE}/{path}")[:2_000]
        except (OSError, URLError, UnicodeDecodeError) as exc:
            content = f"Fetch error: {exc}"
        records.append({"path": path, "source": f"https://github.com/mitre-atlas/atlas-data/blob/main/{path}", "excerpt": content})
    return records


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
        return summarize_cve_record(_http_json(f"{CVEDB_BASE_URL}/cve/{normalized}"))
    except (OSError, URLError, json.JSONDecodeError) as exc:
        return {"cve_id": normalized, "error": str(exc)}


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
        return summarize_euvd_record(_http_json(f"{CVEDB_BASE_URL}/euvd/{normalized}"))
    except (OSError, URLError, json.JSONDecodeError) as exc:
        return {"euvd_id": normalized, "error": str(exc)}


@tool
def lookup_cwe(cwe_id: str) -> dict[str, str]:
    """Fetch a MITRE CWE definition page and extract a bounded text summary.

    Args:
        cwe_id: CWE identifier such as CWE-79 or 79.

    Returns:
        CWE ID, source URL, and a bounded text excerpt from MITRE CWE.
    """
    match = CWE_ID_RE.match(cwe_id.strip())
    if not match:
        return {"error": f"Invalid CWE ID: {cwe_id}"}
    cwe_num = match.group(1)
    url = CWE_DEFINITION_URL.format(id=cwe_num)
    try:
        text = _clean_html_text(_http_text(url))
    except (OSError, URLError, UnicodeDecodeError) as exc:
        return {"cwe_id": f"CWE-{cwe_num}", "source": url, "error": str(exc)}
    return {"cwe_id": f"CWE-{cwe_num}", "source": url, "excerpt": text[:1_500]}


@tool
def lookup_capec(capec_id: str) -> dict[str, Any]:
    """Look up a MITRE CAPEC attack pattern by ID.

    Args:
        capec_id: CAPEC identifier such as CAPEC-66 or 66.

    Returns:
        Structured CAPEC details including description, severity, related CWE IDs, mappings, and mitigations.
    """
    match = CAPEC_ID_RE.match(capec_id.strip())
    if not match:
        return {"error": f"Invalid CAPEC ID: {capec_id}"}
    capec_num = match.group(1)
    try:
        pattern = capec_patterns_by_id().get(f"CAPEC-{capec_num}".upper())
    except (OSError, URLError, zipfile.BadZipFile, ElementTree.ParseError, ValueError) as exc:
        fallback = _fallback_capec_html(capec_num)
        fallback["xml_error"] = str(exc)
        fallback["xml_source"] = CAPEC_XML_ZIP_URL
        return fallback

    if not pattern:
        return {
            "capec_id": f"CAPEC-{capec_num}",
            "source": CAPEC_DEFINITION_URL.format(id=capec_num),
            "xml_source": CAPEC_XML_ZIP_URL,
            "error": "CAPEC ID not found in the current MITRE CAPEC XML dataset.",
        }
    return {**pattern, "xml_source": CAPEC_XML_ZIP_URL}


@tool
def search_capec(query: str) -> dict[str, Any]:
    """Search MITRE CAPEC attack patterns by CAPEC ID, CWE ID, name, or keyword.

    Args:
        query: CAPEC ID, CWE ID, attack pattern name, weakness, or behavior phrase.

    Returns:
        Up to five matching CAPEC attack patterns from the official CAPEC XML dataset.
    """
    try:
        patterns = load_capec_patterns()
    except (OSError, URLError, zipfile.BadZipFile, ElementTree.ParseError, ValueError) as exc:
        return {"source": CAPEC_XML_ZIP_URL, "error": str(exc), "matches": []}

    requested_capec_ids = {f"CAPEC-{match}" for match in CAPEC_MENTION_RE.findall(query)}
    requested_cwe_ids = {f"CWE-{match}" for match in CWE_MENTION_RE.findall(query)}
    if CAPEC_ID_RE.match(query.strip()):
        requested_capec_ids.add(f"CAPEC-{CAPEC_ID_RE.match(query.strip()).group(1)}")
    if CWE_ID_RE.match(query.strip()):
        requested_cwe_ids.add(f"CWE-{CWE_ID_RE.match(query.strip()).group(1)}")
    terms = {term for term in re.findall(r"[a-z0-9]+", query.lower()) if len(term) > 2}
    ranked = []
    for pattern in patterns:
        capec_id = str(pattern.get("capec_id", "")).upper()
        related_weaknesses = {str(item).upper() for item in pattern.get("related_weaknesses", [])}
        exact_score = 0
        if capec_id in {item.upper() for item in requested_capec_ids}:
            exact_score += 10
        if requested_cwe_ids & related_weaknesses:
            exact_score += 8

        mapping_text = " ".join(
            f"{mapping.get('taxonomy', '')} {mapping.get('entry_id', '')} {mapping.get('entry_name', '')}"
            for mapping in pattern.get("taxonomy_mappings", [])
        )
        keyword_score = _score_text(
            terms,
            pattern.get("capec_id", ""),
            pattern.get("name", ""),
            pattern.get("description", ""),
            " ".join(pattern.get("related_weaknesses", [])),
            mapping_text,
        )
        score = exact_score + keyword_score
        if score:
            ranked.append((score, pattern.get("capec_id", ""), pattern))

    matches = []
    for _, _, pattern in sorted(ranked, key=lambda item: (item[0], item[1]), reverse=True)[:5]:
        matches.append(
            {
                "capec_id": pattern.get("capec_id"),
                "name": pattern.get("name"),
                "abstraction": pattern.get("abstraction"),
                "source": pattern.get("source"),
                "description": pattern.get("description"),
                "likelihood": pattern.get("likelihood"),
                "severity": pattern.get("severity"),
                "related_weaknesses": pattern.get("related_weaknesses", [])[:8],
                "taxonomy_mappings": pattern.get("taxonomy_mappings", [])[:5],
                "mitigations": pattern.get("mitigations", [])[:3],
            }
        )

    return {
        "source": CAPEC_XML_ZIP_URL,
        "query": query,
        "match_count": len(matches),
        "matches": matches,
    }


@tool
def search_attack(query: str) -> dict[str, Any]:
    """Search MITRE ATT&CK Enterprise techniques.

    Args:
        query: Technique ID, technique name, tactic, vulnerability behavior, or adversary behavior.

    Returns:
        Up to five matching ATT&CK technique summaries from official STIX data.
    """
    try:
        patterns = load_attack_patterns()
    except (OSError, URLError, json.JSONDecodeError) as exc:
        return {"source": ATTACK_STIX_URL, "error": str(exc), "matches": []}

    explicit_ids = {match.upper() for match in ATTACK_ID_RE.findall(query)}
    terms = {term for term in re.findall(r"[a-z0-9.]+", query.lower()) if len(term) > 2}
    by_id = attack_patterns_by_id()
    requested_ids = _attack_ids_for_query(query)
    matches_by_id: dict[str, dict[str, Any]] = {}
    for attack_id in requested_ids:
        if attack_id in by_id:
            pattern = dict(by_id[attack_id])
            pattern["match_reason"] = "matched explicit ATT&CK ID or built-in vulnerability exploitation alias"
            matches_by_id[attack_id] = pattern

    ranked = []
    if not explicit_ids:
        minimum_score = 2 if requested_ids else 1
        for pattern in patterns:
            tactics = " ".join(phase.get("phase_name", "") for phase in pattern.get("tactics", []))
            score = _score_text(terms, pattern.get("id") or "", pattern.get("name") or "", pattern.get("description") or "", tactics)
            if score >= minimum_score:
                ranked.append((score, pattern.get("id") or "", pattern))

    matches = list(matches_by_id.values())
    for _, _, pattern in sorted(ranked, key=lambda item: (item[0], item[1]), reverse=True):
        if len(matches) >= 5:
            break
        attack_id = str(pattern.get("id")).upper()
        if attack_id in matches_by_id:
            continue
        enriched = dict(pattern)
        enriched["match_reason"] = "matched query terms against official ATT&CK STIX name, description, tactic, or ID"
        matches.append(enriched)

    return {
        "source": ATTACK_STIX_URL,
        "requested_or_inferred_attack_ids": sorted(requested_ids),
        "match_count": len(matches),
        "matches": matches,
    }


@tool
def search_atlas(query: str) -> dict[str, Any]:
    """Search MITRE ATLAS data files for AI/ML threat intelligence references.

    Args:
        query: AI/ML threat behavior, tactic, technique, or risk phrase.

    Returns:
        Bounded matching ATLAS data file excerpts.
    """
    try:
        records = load_atlas_records(query)
    except (OSError, URLError, json.JSONDecodeError) as exc:
        return {"source": ATLAS_TREE_URL, "error": str(exc), "matches": []}
    return {"source": "https://github.com/mitre-atlas/atlas-data", "matches": records}


@tool
def map_owasp_top10(description: str, version: str = "latest") -> dict[str, Any]:
    """Map a weakness or scenario to OWASP Top 10 categories.

    Args:
        description: Vulnerability, design, incident, or feature description.
        version: latest, 2025, 2021, or both.

    Returns:
        Ranked OWASP Top 10 category matches with matching keywords and source metadata.
    """
    lowered = description.lower()
    selected_versions = ["2025", "2021"] if version.lower() == "both" else ["2025" if version.lower() == "latest" else version]
    matches = []
    for selected_version in selected_versions:
        categories = OWASP_TOP_10.get(selected_version)
        if not categories:
            return {
                "error": "version must be latest, 2025, 2021, or both",
                "requested_version": version,
                "available_versions": sorted(OWASP_TOP_10),
            }
        for code, name, keywords in categories:
            hit = [keyword for keyword in keywords if keyword in lowered]
            if hit:
                matches.append(
                    {
                        "version": selected_version,
                        "category": code,
                        "name": name,
                        "matched_keywords": hit,
                    }
                )
    if not matches:
        matches.append(
            {
                "version": selected_versions[0],
                "note": "No direct keyword match. Consider Insecure Design for unclear design-level risk.",
            }
        )
    return {
        "latest_released_version": "2025",
        "project_source": OWASP_TOP_10_SOURCE,
        "sources": {
            "2025": OWASP_TOP_10_2025_SOURCE,
            "2021": OWASP_TOP_10_2021_SOURCE,
        },
        "matches": matches,
    }


@tool
def threat_model_frameworks(scenario: str) -> dict[str, Any]:
    """Generate framework prompts for threat modeling a scenario.

    Args:
        scenario: System, feature, vulnerability, or incident scenario to analyze.

    Returns:
        STRIDE prompts, PASTA stages, Kill Chain stages, Security Cards prompts,
        Unified Kill Chain stages, and source notes.
    """
    lowered = scenario.lower()
    stride_hits = [
        {"category": name, "question": question}
        for name, question in STRIDE.items()
        if name.lower().split()[0] in lowered
        or any(word in lowered for word in name.lower().split())
    ]
    if not stride_hits:
        stride_hits = [{"category": name, "question": question} for name, question in STRIDE.items()]
    return {
        "scenario": scenario,
        "stride": stride_hits,
        "pasta_stages": PASTA_STAGES,
        "lockheed_cyber_kill_chain": KILL_CHAIN,
        "unified_kill_chain": UNIFIED_KILL_CHAIN,
        "unified_kill_chain_source": UNIFIED_KILL_CHAIN_URL,
        "security_cards_prompts": SECURITY_CARD_PROMPTS,
        "security_cards_source": SECURITY_CARDS_URL,
        "note": (
            "Use these as analyst prompts. Call get_threat_model_reference for "
            "Security Cards or Unified Kill Chain excerpts when the user asks for "
            "framework detail, source-backed mapping, or card/phase-specific analysis. "
            "Preserve assumptions and uncertainty in the final answer."
        ),
    }


@tool
def risk_calculator(
    loss_event_frequency_min: float,
    loss_event_frequency_most_likely: float,
    loss_event_frequency_max: float,
    loss_magnitude_min: float,
    loss_magnitude_most_likely: float,
    loss_magnitude_max: float,
) -> dict[str, Any]:
    """Estimate annualized cyber risk with a simple FAIR-inspired calculation.

    Args:
        loss_event_frequency_min: Low annual loss event frequency estimate.
        loss_event_frequency_most_likely: Most likely annual loss event frequency estimate.
        loss_event_frequency_max: High annual loss event frequency estimate.
        loss_magnitude_min: Low loss magnitude estimate in currency units.
        loss_magnitude_most_likely: Most likely loss magnitude estimate in currency units.
        loss_magnitude_max: High loss magnitude estimate in currency units.

    Returns:
        Low/most-likely/high annual loss estimates and an explicit caveat.
    """
    low = loss_event_frequency_min * loss_magnitude_min
    likely = loss_event_frequency_most_likely * loss_magnitude_most_likely
    high = loss_event_frequency_max * loss_magnitude_max
    return {
        "annual_loss_low": round(low, 2),
        "annual_loss_most_likely": round(likely, 2),
        "annual_loss_high": round(high, 2),
        "inputs": {
            "loss_event_frequency": [
                loss_event_frequency_min,
                loss_event_frequency_most_likely,
                loss_event_frequency_max,
            ],
            "loss_magnitude": [
                loss_magnitude_min,
                loss_magnitude_most_likely,
                loss_magnitude_max,
            ],
        },
        "model_note": (
            "This is a lightweight FAIR-inspired estimate: annualized loss is "
            "loss event frequency multiplied by loss magnitude. It is not a full "
            "FAIR Monte Carlo analysis."
        ),
    }


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((percentile / 100) * (len(ordered) - 1))))
    return ordered[index]


@tool
def fair_monte_carlo_ale(
    loss_event_frequency_min: float,
    loss_event_frequency_most_likely: float,
    loss_event_frequency_max: float,
    loss_magnitude_min: float,
    loss_magnitude_most_likely: float,
    loss_magnitude_max: float,
    iterations: int = 10_000,
) -> dict[str, Any]:
    """Run a lightweight FAIR-style Monte Carlo simulation for annual loss expectancy.

    Args:
        loss_event_frequency_min: Low annual loss event frequency estimate.
        loss_event_frequency_most_likely: Most likely annual loss event frequency estimate.
        loss_event_frequency_max: High annual loss event frequency estimate.
        loss_magnitude_min: Low loss magnitude estimate in currency units.
        loss_magnitude_most_likely: Most likely loss magnitude estimate in currency units.
        loss_magnitude_max: High loss magnitude estimate in currency units.
        iterations: Number of simulation runs, capped between 100 and 100000.

    Returns:
        Simulated annual loss expectancy distribution summary with mean, median, and percentiles.
    """
    runs = max(100, min(int(iterations), 100_000))
    results = []
    for _ in range(runs):
        frequency = random.triangular(
            loss_event_frequency_min,
            loss_event_frequency_max,
            loss_event_frequency_most_likely,
        )
        magnitude = random.triangular(
            loss_magnitude_min,
            loss_magnitude_max,
            loss_magnitude_most_likely,
        )
        results.append(max(0.0, frequency) * max(0.0, magnitude))

    return {
        "iterations": runs,
        "ale_mean": round(statistics.fmean(results), 2),
        "ale_median_p50": round(_percentile(results, 50), 2),
        "ale_p10": round(_percentile(results, 10), 2),
        "ale_p90": round(_percentile(results, 90), 2),
        "ale_p95": round(_percentile(results, 95), 2),
        "ale_min": round(min(results), 2),
        "ale_max": round(max(results), 2),
        "model_note": (
            "This is a simplified FAIR-style Monte Carlo model using triangular "
            "distributions for loss event frequency and loss magnitude. It supports "
            "business discussion, not formal actuarial certification."
        ),
    }


@tool
def rosi_calculator(
    current_ale: float,
    expected_ale_after_control: float,
    annual_control_cost: float,
) -> dict[str, Any]:
    """Calculate return on security investment from ALE reduction.

    Args:
        current_ale: Current annual loss expectancy before the security control.
        expected_ale_after_control: Expected annual loss expectancy after the control.
        annual_control_cost: Annualized cost of the proposed security control.

    Returns:
        Risk reduction, net benefit, ROSI percentage, and payback interpretation.
    """
    risk_reduction = current_ale - expected_ale_after_control
    net_benefit = risk_reduction - annual_control_cost
    rosi = None
    if annual_control_cost:
        rosi = (net_benefit / annual_control_cost) * 100
    return {
        "current_ale": round(current_ale, 2),
        "expected_ale_after_control": round(expected_ale_after_control, 2),
        "annual_control_cost": round(annual_control_cost, 2),
        "annual_risk_reduction": round(risk_reduction, 2),
        "net_annual_benefit": round(net_benefit, 2),
        "rosi_percent": None if rosi is None else round(rosi, 2),
        "decision_hint": (
            "Positive net benefit means estimated annual risk reduction exceeds "
            "annualized control cost. Negative net benefit may still be acceptable "
            "for compliance, resilience, safety, or risk appetite reasons."
        ),
    }


@tool
def qualitative_risk(likelihood: str, impact: str) -> dict[str, str]:
    """Score qualitative risk from likelihood and impact labels.

    Args:
        likelihood: rare, unlikely, possible, likely, or almost certain.
        impact: negligible, minor, moderate, major, or severe.

    Returns:
        Qualitative risk rating and rationale.
    """
    likelihood_scores = {
        "rare": 1,
        "unlikely": 2,
        "possible": 3,
        "likely": 4,
        "almost certain": 5,
    }
    impact_scores = {
        "negligible": 1,
        "minor": 2,
        "moderate": 3,
        "major": 4,
        "severe": 5,
    }
    l_key = likelihood.strip().lower()
    i_key = impact.strip().lower()
    if l_key not in likelihood_scores or i_key not in impact_scores:
        return {"error": "Use likelihood rare/unlikely/possible/likely/almost certain and impact negligible/minor/moderate/major/severe."}
    score = likelihood_scores[l_key] * impact_scores[i_key]
    rating = "low" if score <= 5 else "medium" if score <= 12 else "high" if score <= 19 else "critical"
    return {"likelihood": l_key, "impact": i_key, "score": str(score), "rating": rating}


class StreamingCLIHandler:
    """Streams model output and labels tool calls."""

    _in_tool: bool = False
    _tool_count: int = 0

    def __call__(self, **kwargs):
        data = kwargs.get("data", "")
        event = kwargs.get("event", {})
        tool_start = (
            event.get("contentBlockStart", {})
            .get("start", {})
            .get("toolUse")
        )
        tool_done = event.get("contentBlockStop") and self._in_tool
        if tool_start:
            self._tool_count += 1
            self._in_tool = True
            print(f"\n[tool #{self._tool_count}: {tool_start.get('name', 'unknown')}]", flush=True)
            return
        if tool_done:
            self._in_tool = False
            print(flush=True)
            return
        if data:
            print(data, end="", flush=True)


def make_agent(stream_to_cli: bool = True) -> Agent:
    profile = os.environ.get("AWS_PROFILE")
    session = boto3.Session(profile_name=profile, region_name=REGION)
    model = BedrockModel(model_id=MODEL_ID, boto_session=session)
    return Agent(
        model=model,
        system_prompt=(
            "You are a threat-intelligence and cyber-risk advisor. Use tools for live "
            "CVE/EUVD/CWE/CAPEC/ATT&CK/ATLAS lookups when identifiers or framework "
            "mapping is requested. Clearly separate sourced facts from inference. "
            "Use search_capec for CAPEC mapping when the user provides a CWE ID, "
            "attack behavior, or vulnerability class but not a specific CAPEC ID. "
            "When mapping to OWASP, prefer OWASP Top 10:2025 as latest and compare "
            "against 2021 when the user asks for historical or both-version context. "
            "When mapping to STRIDE, PASTA, Kill Chain, Unified Kill Chain, Security "
            "Cards, or risk calculations, state assumptions, uncertainty, and "
            "recommended next evidence. Use get_threat_model_reference for Security "
            "Cards or Unified Kill Chain details; it extracts the official PDFs to "
            "cached markdown and returns bounded excerpts. "
            "For FAIR-style questions, use fair_monte_carlo_ale when ranges are available "
            "and rosi_calculator when the user is justifying a security tool or control cost."
        ),
        tools=[
            lookup_cve,
            lookup_euvd,
            lookup_cwe,
            lookup_capec,
            search_capec,
            search_attack,
            search_atlas,
            map_owasp_top10,
            threat_model_frameworks,
            get_threat_model_reference,
            risk_calculator,
            fair_monte_carlo_ale,
            rosi_calculator,
            qualitative_risk,
        ],
        callback_handler=StreamingCLIHandler() if stream_to_cli else None,
    )


app = FastAPI()
_web_agent: Agent | None = None


@app.middleware("http")
async def _log_http_request(request: FastAPIRequest, call_next):
    start = time.perf_counter()
    LOGGER.debug("HTTP request start method=%s path=%s", request.method, request.url.path)
    try:
        response = await call_next(request)
    except Exception:
        LOGGER.exception("HTTP request failed method=%s path=%s", request.method, request.url.path)
        raise

    elapsed_ms = (time.perf_counter() - start) * 1000
    LOGGER.debug(
        "HTTP request complete method=%s path=%s status=%d elapsed_ms=%.1f",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response


class ChatRequest(BaseModel):
    message: str


def _web_chat_agent() -> Agent:
    global _web_agent
    if _web_agent is None:
        _web_agent = make_agent(stream_to_cli=False)
    return _web_agent


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


async def _stream_chat_turn(message: str):
    question = message.strip()
    if not question:
        yield _sse({"type": "error", "text": "Enter a question."})
        yield _sse({"type": "done"})
        return

    try:
        LOGGER.debug("Starting threat-intel WebUI turn message_chars=%d", len(question))
        yield _sse({"type": "stage", "stage": "agent", "text": "Running threat-intel agent."})
        async for event in _web_chat_agent().stream_async(question):
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
        LOGGER.exception("Threat-intel WebUI turn failed")
        yield _sse({"type": "error", "text": str(exc)})
        yield _sse({"type": "done"})


HTML_PAGE = """\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Threat Intel Risk Chat</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      margin: 0;
      background: #f6f7f9;
      color: #17202a;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main {
      width: min(1120px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 18px 0;
      min-height: 100vh;
      display: grid;
      grid-template-rows: auto 1fr auto;
      gap: 12px;
    }
    header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 16px;
      min-height: 34px;
    }
    h1 { margin: 0; font-size: 1.28rem; letter-spacing: 0; font-weight: 650; }
    .meta { color: #5d6673; font-size: 0.86rem; white-space: nowrap; }
    #log {
      min-height: 0;
      height: calc(100vh - 168px);
      overflow-y: auto;
      border: 1px solid #d8dde5;
      border-radius: 8px;
      background: #fff;
      padding: 14px;
    }
    .msg {
      max-width: 86%;
      margin: 0 0 12px;
      padding: 10px 12px;
      border-radius: 8px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      line-height: 1.45;
      font-size: 0.95rem;
    }
    .user {
      margin-left: auto;
      background: #e7f0ff;
      border: 1px solid #c7dbff;
      color: #12315f;
    }
    .assistant {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      color: #17202a;
      white-space: normal;
    }
    .assistant h1, .assistant h2, .assistant h3, .assistant h4, .assistant h5, .assistant h6 {
      margin: 0.35rem 0 0.25rem;
      line-height: 1.25;
      font-size: 1rem;
    }
    .assistant h1 { font-size: 1.08rem; }
    .assistant h4 { font-size: 0.96rem; }
    .assistant h5 { font-size: 0.92rem; }
    .assistant h6 { font-size: 0.9rem; color: #475569; }
    .assistant p { margin: 0.35rem 0; }
    .assistant ul, .assistant ol { margin: 0.35rem 0 0.55rem 1.25rem; padding: 0; }
    .assistant li { margin: 0.18rem 0; }
    .assistant code {
      background: #e8edf3;
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
    .assistant th { background: #eef2f7; }
    .assistant hr { border: 0; border-top: 1px solid #cbd5e1; margin: 0.75rem 0; }
    .assistant a { color: #2457a6; }
    .tool, .stage, .error {
      max-width: 100%;
      margin: 0 0 8px;
      font-size: 0.82rem;
      color: #5d6673;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .tool { color: #6b4e16; }
    .error { color: #9f1d1d; }
    form {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 10px;
      align-items: end;
    }
    textarea {
      width: 100%;
      min-height: 58px;
      max-height: 180px;
      resize: vertical;
      padding: 10px 12px;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      font: inherit;
      line-height: 1.35;
      background: #fff;
      color: #17202a;
    }
    button {
      min-width: 92px;
      height: 42px;
      border: 0;
      border-radius: 8px;
      background: #2457a6;
      color: #fff;
      font: inherit;
      font-weight: 600;
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
    @media (max-width: 720px) {
      main { width: min(100vw - 20px, 1120px); padding: 10px 0; }
      header { display: block; }
      .meta { margin-top: 4px; white-space: normal; }
      #log { height: calc(100vh - 210px); padding: 10px; }
      .msg { max-width: 100%; }
      form { grid-template-columns: 1fr; }
      button { width: 100%; }
    }
  </style>
</head>
<body>
<main>
  <header>
    <h1>Threat Intel Risk Chat</h1>
    <div class="meta">CVE/EUVD · CWE/CAPEC · ATT&CK/ATLAS · OWASP · FAIR/ROSI</div>
  </header>

  <section id="log" aria-live="polite"></section>

  <section>
    <form id="form">
      <textarea id="input" autocomplete="off" placeholder="Ask about CVEs, ATT&CK/CWE mappings, threat models, ALE, or ROSI."></textarea>
      <button id="send" type="submit">Send</button>
    </form>
    <div class="chips">
      <span class="chip" data-prompt="Tell me about CVE-2021-44228, CVE-2025-55182, CVE-2022-22965; what are they and how are they similar. How do they map to ATT&CK and CWE?">Compare CVEs</span>
      <span class="chip" data-prompt="Map a public-facing Java RCE exposure to STRIDE, Unified Kill Chain, Security Cards, and OWASP Top 10 2025.">Threat model</span>
      <span class="chip" data-prompt="Run FAIR Monte Carlo ALE and ROSI for a $120k control that reduces ALE from $500k to $180k.">FAIR + ROSI</span>
    </div>
  </section>
</main>

<script>
const log = document.getElementById("log");
const form = document.getElementById("form");
const input = document.getElementById("input");
const send = document.getElementById("send");

function add(cls, text) {
  const div = document.createElement("div");
  div.className = cls;
  div.textContent = text;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
  return div;
}

function escapeHTML(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function renderInline(markdown) {
  let html = escapeHTML(markdown);
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  html = html.replace(/\\*\\*([^*]+)\\*\\*/g, "<strong>$1</strong>");
  html = html.replace(/\\*([^*]+)\\*/g, "<em>$1</em>");
  html = html.replace(/\\[([^\\]]+)\\]\\((https?:\\/\\/[^\\s)]+)\\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  return html;
}

function splitTableRow(line) {
  let trimmed = line.trim();
  if (trimmed.startsWith("|")) trimmed = trimmed.slice(1);
  if (trimmed.endsWith("|")) trimmed = trimmed.slice(0, -1);
  return trimmed.split("|").map(cell => cell.trim());
}

function isTableSeparator(line) {
  return /^\\|?\\s*:?-{3,}:?\\s*(\\|\\s*:?-{3,}:?\\s*)+\\|?$/.test(line.trim());
}

function isPipeTableRow(line) {
  const trimmed = line.trim();
  return trimmed.includes("|") && splitTableRow(trimmed).length >= 2;
}

function renderTable(lines, start) {
  const header = splitTableRow(lines[start]);
  const rows = [];
  let index = start + 2;
  while (index < lines.length && lines[index].includes("|") && lines[index].trim()) {
    rows.push(splitTableRow(lines[index]));
    index += 1;
  }
  const thead = "<thead><tr>" + header.map(cell => "<th>" + renderInline(cell) + "</th>").join("") + "</tr></thead>";
  const tbody = "<tbody>" + rows.map(row => {
    const cells = header.map((_, i) => "<td>" + renderInline(row[i] || "") + "</td>").join("");
    return "<tr>" + cells + "</tr>";
  }).join("") + "</tbody>";
  return { html: "<table>" + thead + tbody + "</table>", next: index };
}

function renderLooseTable(lines, start) {
  const tableLines = [];
  let index = start;
  while (index < lines.length && isPipeTableRow(lines[index])) {
    tableLines.push(lines[index]);
    index += 1;
  }
  if (tableLines.length < 2) return null;
  const header = splitTableRow(tableLines[0]);
  const rows = tableLines.slice(1).map(splitTableRow);
  const thead = "<thead><tr>" + header.map(cell => "<th>" + renderInline(cell) + "</th>").join("") + "</tr></thead>";
  const tbody = "<tbody>" + rows.map(row => {
    const cells = header.map((_, i) => "<td>" + renderInline(row[i] || "") + "</td>").join("");
    return "<tr>" + cells + "</tr>";
  }).join("") + "</tbody>";
  return { html: "<table>" + thead + tbody + "</table>", next: index };
}

function normalizeMarkdown(markdown) {
  return markdown
    .replace(/([^\\n])\\s*(#{1,6}\\s+)/g, "$1\\n\\n$2")
    .replace(/([^\\n])\\s*(---+|___+|\\*\\*\\*+)\\s*(?=\\n|$)/g, "$1\\n\\n$2")
    .replace(/([^\\n])\\s*(```)/g, "$1\\n\\n$2")
    .replace(/([.!?\\)])(Let me|Now let me|I'll|I will|Next,|Good!|Great!|Excellent!|Perfect!|Excellent\\.)/g, "$1\\n\\n$2")
    .replace(/(:)(Let me|Now let me|I'll|I will|Next,)/g, "$1\\n\\n$2");
}

function repairMarkdownLines(lines) {
  const repaired = [];
  for (let i = 0; i < lines.length; i += 1) {
    const trimmed = lines[i].trim();
    if (/^#{1,6}$/.test(trimmed)) {
      let j = i + 1;
      while (j < lines.length && !lines[j].trim()) j += 1;
      if (j < lines.length) {
        repaired.push(trimmed + " " + lines[j].trim());
        i = j;
        continue;
      }
    }
    repaired.push(lines[i]);
  }
  return repaired;
}

function renderMarkdown(markdown) {
  const lines = repairMarkdownLines(normalizeMarkdown(markdown).replace(/\\r\\n?/g, "\\n").split("\\n"));
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

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith("```")) {
      flushParagraph(); closeList();
      if (inFence) {
        html.push("<pre><code>" + escapeHTML(fenceLines.join("\\n")) + "</code></pre>");
        fenceLines = [];
      }
      inFence = !inFence;
      continue;
    }
    if (inFence) { fenceLines.push(line); continue; }
    if (!trimmed) { flushParagraph(); closeList(); continue; }
    if (/^---+$/.test(trimmed) || /^___+$/.test(trimmed) || /^\\*\\*\\*+$/.test(trimmed)) {
      flushParagraph(); closeList(); html.push("<hr>"); continue;
    }
    if (i + 1 < lines.length && trimmed.includes("|") && isTableSeparator(lines[i + 1])) {
      flushParagraph(); closeList();
      const table = renderTable(lines, i);
      html.push(table.html);
      i = table.next - 1;
      continue;
    }
    if (i + 1 < lines.length && isPipeTableRow(trimmed) && isPipeTableRow(lines[i + 1])) {
      flushParagraph(); closeList();
      const table = renderLooseTable(lines, i);
      if (table) {
        html.push(table.html);
        i = table.next - 1;
        continue;
      }
    }
    const heading = trimmed.match(/^(#{1,6})\\s+(.+)$/);
    if (heading) {
      flushParagraph(); closeList();
      const level = heading[1].length;
      html.push("<h" + level + ">" + renderInline(heading[2]) + "</h" + level + ">");
      continue;
    }
    const ordered = trimmed.match(/^\\d+\\.\\s+(.+)$/);
    if (ordered) { flushParagraph(); ensureList("ol"); html.push("<li>" + renderInline(ordered[1]) + "</li>"); continue; }
    const unordered = trimmed.match(/^[-*+]\\s+(.+)$/);
    if (unordered) { flushParagraph(); ensureList("ul"); html.push("<li>" + renderInline(unordered[1]) + "</li>"); continue; }
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

function append(target, text) {
  target.dataset.markdown = (target.dataset.markdown || "") + text;
  target.innerHTML = renderMarkdown(target.dataset.markdown);
  log.scrollTop = log.scrollHeight;
}

async function streamSSE(response, assistant) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const frames = buffer.split("\\n\\n");
    buffer = frames.pop();

    for (const frame of frames) {
      const line = frame.split("\\n").find((part) => part.startsWith("data: "));
      if (!line) continue;
      const evt = JSON.parse(line.slice(6));
      if (evt.type === "token") {
        append(assistant, evt.text);
      } else if (evt.type === "tool") {
        add("tool", evt.text);
      } else if (evt.type === "stage") {
        add("stage", evt.text);
      } else if (evt.type === "error") {
        add("error", evt.text);
      }
    }
  }
}

async function ask(message) {
  add("msg user", message);
  const assistant = add("msg assistant", "");
  send.disabled = true;
  input.disabled = true;
  try {
    const resp = await fetch("/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message })
    });
    if (!resp.ok || !resp.body) {
      throw new Error(`HTTP ${resp.status}`);
    }
    await streamSSE(resp, assistant);
  } catch (err) {
    add("error", `Request failed: ${err.message}`);
  } finally {
    send.disabled = false;
    input.disabled = false;
    input.focus();
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const message = input.value.trim();
  if (!message) return;
  input.value = "";
  await ask(message);
});

input.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
    form.requestSubmit();
  }
});

document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    input.value = chip.dataset.prompt;
    input.focus();
  });
});
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    LOGGER.debug("Serving threat-intel WebUI index page")
    return HTML_PAGE


@app.post("/chat")
async def chat(req: ChatRequest) -> StreamingResponse:
    LOGGER.debug("Received /chat request message_chars=%d", len(req.message))
    return StreamingResponse(
        _stream_chat_turn(req.message),
        media_type="text/event-stream",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prompt", help="Run one threat-intel question and exit.")
    parser.add_argument("--web", action="store_true", help="Run the FastAPI/SSE browser chat UI.")
    parser.add_argument("--host", default="127.0.0.1", help="Host for --web mode.")
    parser.add_argument("--port", type=int, default=8003, help="Port for --web mode.")
    args = parser.parse_args()

    if args.web:
        print(f"Open http://{args.host}:{args.port} in your browser.")
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level="debug",
            log_config=None,
            access_log=True,
        )
        return

    agent = make_agent()

    if args.prompt:
        agent(args.prompt)
        print()
        return

    print("Threat Intel Risk Chat. Type 'quit' or Ctrl-C to exit.")
    print("Try: Tell me about CVE-2023-34362 and map it to CWE, ATT&CK, OWASP, STRIDE, and FAIR.")
    print("Try: Run FAIR Monte Carlo ALE and ROSI for a $120k tool that cuts ALE from $500k to $180k.\n")
    while True:
        try:
            user_input = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nbye")
            break
        if user_input.lower() in {"quit", "exit"}:
            print("bye")
            break
        if not user_input:
            continue
        agent(user_input)
        print("\n")


if __name__ == "__main__":
    main()
