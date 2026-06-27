"""Shared vulnerability lookup helpers for cyber-security examples."""

from __future__ import annotations

import re
from typing import Any

import requests

CVEDB_BASE_URL = "https://cvedb.shodan.io"
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
EUVD_ID_RE = re.compile(r"^EUVD-\d{4}-\d{4,}$", re.IGNORECASE)


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


def lookup_cve_record(cve_id: str, *, timeout: float = 15.0) -> dict[str, Any]:
    normalized = cve_id.strip().upper()
    if not CVE_ID_RE.match(normalized):
        return {"error": f"Invalid CVE ID: {cve_id}"}

    try:
        response = requests.get(f"{CVEDB_BASE_URL}/cve/{normalized}", timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as exc:
        return {"cve_id": normalized, "error": str(exc)}

    return summarize_cve_record(response.json())


def lookup_euvd_record(euvd_id: str, *, timeout: float = 15.0) -> dict[str, Any]:
    normalized = euvd_id.strip().upper()
    if not EUVD_ID_RE.match(normalized):
        return {"error": f"Invalid EUVD ID: {euvd_id}"}

    try:
        response = requests.get(f"{CVEDB_BASE_URL}/euvd/{normalized}", timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as exc:
        return {"euvd_id": normalized, "error": str(exc)}

    return summarize_euvd_record(response.json())
