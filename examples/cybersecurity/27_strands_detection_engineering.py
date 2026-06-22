"""
Hello World: Strands Structured Output — detection engineering from telemetry
Turns sample security events into detection hypotheses, Sigma-style rules,
hunting queries, and response actions.

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python examples/cybersecurity/27_strands_detection_engineering.py
         uv run python examples/cybersecurity/27_strands_detection_engineering.py --events ./events.jsonl
         uv run python examples/cybersecurity/27_strands_detection_engineering.py --events ./events.csv
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)
import argparse
import csv
import json
import os
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

import boto3
from pydantic import BaseModel, Field
from strands import Agent, tool
from strands.models import BedrockModel

REGION = "us-east-1"
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "openai.gpt-oss-120b-1:0")
MAX_EVENTS = 200
MAX_EVENT_CHARS = 60_000
MAX_SIGMA_EXAMPLES = 3
MAX_SIGMA_RULE_CHARS = 2_000
MAX_SIGMA_PROMPT_CHARS = 1_200
ECS_FIELDS_SOURCE = "https://raw.githubusercontent.com/elastic/ecs/refs/heads/main/generated/csv/fields.csv"
ECS_BROWSER_SOURCE = "https://github.com/elastic/ecs/blob/main/generated/csv/fields.csv"
SIGMA_REPO = "https://github.com/SigmaHQ/sigma"
SIGMA_TREE_URL = "https://api.github.com/repos/SigmaHQ/sigma/git/trees/master?recursive=1"
SIGMA_RAW_BASE = "https://raw.githubusercontent.com/SigmaHQ/sigma/master"
SIGMA_RULE_ROOTS = (
    "rules/",
    "rules-threat-hunting/",
    "rules-emerging-threats/",
    "rules-dfir/",
    "rules-compliance/",
)
SIGMA_FALLBACK_EXAMPLES = [
    {
        "path": "offline/fallback_sigma_shape.yml",
        "source": SIGMA_REPO,
        "fetched": False,
        "summary": "Offline fallback showing required Sigma sections only.",
        "rule": (
            "title: Example Sigma Rule Shape\n"
            "status: experimental\n"
            "logsource:\n"
            "  product: example\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 1\n"
            "  condition: selection\n"
            "falsepositives:\n"
            "  - Unknown\n"
            "level: medium\n"
        ),
    }
]
ECS_SECURITY_FIELD_SETS = {
    "agent",
    "base",
    "client",
    "cloud",
    "destination",
    "dns",
    "event",
    "file",
    "host",
    "http",
    "log",
    "network",
    "observer",
    "process",
    "related",
    "rule",
    "server",
    "source",
    "threat",
    "url",
    "user",
    "user_agent",
}
FALLBACK_ECS_SECURITY_FIELDS = {
    "@timestamp",
    "agent.id",
    "agent.name",
    "agent.type",
    "agent.version",
    "cloud.account.id",
    "cloud.account.name",
    "cloud.instance.id",
    "cloud.provider",
    "cloud.region",
    "cloud.service.name",
    "destination.address",
    "destination.domain",
    "destination.ip",
    "destination.port",
    "destination.user.email",
    "destination.user.id",
    "destination.user.name",
    "dns.question.name",
    "event.action",
    "event.category",
    "event.code",
    "event.dataset",
    "event.id",
    "event.kind",
    "event.module",
    "event.outcome",
    "event.provider",
    "event.reason",
    "event.type",
    "file.hash.sha256",
    "file.name",
    "file.path",
    "host.hostname",
    "host.id",
    "host.ip",
    "host.name",
    "host.os.type",
    "http.request.method",
    "http.response.status_code",
    "log.level",
    "message",
    "network.direction",
    "network.protocol",
    "network.transport",
    "network.type",
    "process.args",
    "process.command_line",
    "process.executable",
    "process.name",
    "process.parent.name",
    "process.pid",
    "related.hash",
    "related.ip",
    "related.user",
    "rule.id",
    "rule.name",
    "source.address",
    "source.domain",
    "source.geo.country_iso_code",
    "source.ip",
    "source.port",
    "source.user.email",
    "source.user.id",
    "source.user.name",
    "tags",
    "threat.indicator.ip",
    "threat.indicator.url.full",
    "url.domain",
    "url.full",
    "url.path",
    "user.email",
    "user.id",
    "user.name",
    "user.roles",
    "user_agent.original",
}
FIELD_PATTERN = r"@timestamp|[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+"
FILTER_FIELD_RE = re.compile(
    rf"`?({FIELD_PATTERN})`?\s*(?::|==|=|!=|>=|<=|>|<|\bin\b)",
    re.IGNORECASE,
)
GROUP_BY_RE = re.compile(
    rf"\bby\s+((?:`?{FIELD_PATTERN}`?\s*,?\s*)+)",
    re.IGNORECASE,
)
GROUP_FIELD_RE = re.compile(rf"`?({FIELD_PATTERN})`?")
SIGMA_METADATA_RE = re.compile(
    r"^(title|status|description|level):\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)

SAMPLE_EVENTS = [
    {
        "@timestamp": "2026-06-21T13:01:05Z",
        "event.dataset": "okta.system",
        "event.action": "user.authentication.failed",
        "event.category": ["authentication"],
        "event.outcome": "failure",
        "user.email": "alex@example.com",
        "source.ip": "198.51.100.23",
        "source.geo.country_iso_code": "US",
        "user_agent.original": "Mozilla/5.0",
    },
    {
        "@timestamp": "2026-06-21T13:01:33Z",
        "event.dataset": "okta.system",
        "event.action": "user.authentication.failed",
        "event.category": ["authentication"],
        "event.outcome": "failure",
        "user.email": "alex@example.com",
        "source.ip": "198.51.100.23",
        "source.geo.country_iso_code": "US",
        "user_agent.original": "Mozilla/5.0",
    },
    {
        "@timestamp": "2026-06-21T13:02:02Z",
        "event.dataset": "okta.system",
        "event.action": "user.authentication.succeeded",
        "event.category": ["authentication"],
        "event.outcome": "success",
        "user.email": "alex@example.com",
        "source.ip": "198.51.100.23",
        "source.geo.country_iso_code": "US",
        "user_agent.original": "Mozilla/5.0",
    },
    {
        "@timestamp": "2026-06-21T13:03:10Z",
        "event.dataset": "aws.cloudtrail",
        "event.action": "ConsoleLogin",
        "event.category": ["authentication"],
        "event.outcome": "success",
        "user.email": "alex@example.com",
        "source.ip": "198.51.100.23",
        "aws.cloudtrail.flattened.additionalEventData.MFAUsed": "No",
    },
    {
        "@timestamp": "2026-06-21T13:04:44Z",
        "event.dataset": "aws.cloudtrail",
        "event.action": "CreateAccessKey",
        "event.category": ["iam"],
        "event.outcome": "success",
        "user.email": "alex@example.com",
        "source.ip": "198.51.100.23",
        "user_agent.original": "aws-cli/2.15",
    },
    {
        "@timestamp": "2026-06-21T13:06:18Z",
        "event.dataset": "aws.cloudtrail",
        "event.action": "AttachUserPolicy",
        "event.category": ["iam"],
        "event.outcome": "success",
        "user.email": "alex@example.com",
        "source.ip": "198.51.100.23",
        "aws.cloudtrail.flattened.requestParameters.policyArn": (
            "arn:aws:iam::aws:policy/AdministratorAccess"
        ),
    },
]


class DetectionFinding(BaseModel):
    """Notable behavior found in the event sample."""

    name: str
    severity: str = Field(description="critical, high, medium, low, or informational")
    confidence: str = Field(description="high, medium, or low")
    evidence: list[str] = Field(description="Specific source-backed event facts")
    likely_tactic: str = Field(description="Likely MITRE ATT&CK tactic or analyst label")


class SigmaRuleCandidate(BaseModel):
    """Portable Sigma-style detection candidate."""

    title: str
    status: str = Field(description="experimental, test, stable, or deprecated")
    logsource: str
    detection_yaml: str = Field(description="Sigma-style YAML containing selection and condition")
    false_positives: list[str]
    tuning_notes: list[str]


class HuntingQuery(BaseModel):
    """SIEM hunting query starter."""

    platform: str = Field(
        description=(
            "Elastic KQL, Elastic ES|QL, Splunk SPL, CloudWatch Logs Insights, SQL, "
            "or generic. Elastic KQL must be a filter expression only; Elastic ES|QL "
            "should start with FROM and may use pipes."
        )
    )
    query: str
    purpose: str
    ecs_fields_used: list[str] = Field(description="ECS field names referenced by the query")


class ResponseAction(BaseModel):
    """Recommended defensive action."""

    priority: str = Field(description="high, medium, or low")
    owner: str
    action: str
    rationale: str


class DetectionPack(BaseModel):
    """Validated detection engineering output."""

    title: str
    event_window: str
    findings: list[DetectionFinding]
    sigma_rules: list[SigmaRuleCandidate]
    hunting_queries: list[HuntingQuery]
    response_actions: list[ResponseAction]
    assumptions: list[str]
    validation_plan: list[str]


def _counter_dict(counter: Counter[str]) -> dict[str, int]:
    return dict(counter.most_common(10))


def _derive_common_security_fields(rows: list[dict[str, str]]) -> list[str]:
    fields = []
    for row in rows:
        field = row.get("Field", "")
        field_set = row.get("Field_Set", "")
        level = row.get("Level", "")
        indexed = row.get("Indexed", "")
        if (
            field
            and field_set in ECS_SECURITY_FIELD_SETS
            and indexed == "true"
            and level in {"core", "extended"}
            and not field.endswith(".text")
        ):
            fields.append(field)
    return sorted(set(fields))


def _http_get_text(url: str, timeout: int = 10) -> str:
    with urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8")


@lru_cache(maxsize=1)
def load_ecs_field_reference() -> dict[str, Any]:
    """Fetch ECS fields.csv and derive security-oriented field lists."""
    try:
        csv_text = _http_get_text(ECS_FIELDS_SOURCE)
        rows = list(csv.DictReader(csv_text.splitlines()))
        all_fields = sorted(
            row["Field"] for row in rows
            if row.get("Field") and row.get("Indexed") == "true"
        )
        common_security_fields = _derive_common_security_fields(rows)
        versions = sorted({row.get("ECS_Version", "") for row in rows if row.get("ECS_Version")})
        return {
            "source": ECS_FIELDS_SOURCE,
            "browser_source": ECS_BROWSER_SOURCE,
            "fetched": True,
            "error": None,
            "ecs_versions": versions,
            "all_fields": all_fields,
            "common_security_fields": common_security_fields,
        }
    except (OSError, UnicodeDecodeError, csv.Error, URLError) as exc:
        fallback = sorted(FALLBACK_ECS_SECURITY_FIELDS)
        return {
            "source": ECS_FIELDS_SOURCE,
            "browser_source": ECS_BROWSER_SOURCE,
            "fetched": False,
            "error": str(exc),
            "ecs_versions": ["fallback"],
            "all_fields": fallback,
            "common_security_fields": fallback,
        }


def _sigma_query_tokens(topic: str) -> set[str]:
    base = set(re.findall(r"[a-z0-9]+", topic.lower()))
    if {"aws", "cloudtrail", "iam"} & base:
        base.update({"aws", "cloudtrail", "iam", "console", "access", "policy", "role"})
    if {"login", "auth", "authentication"} & base:
        base.update({"login", "logon", "auth", "authentication"})
    return base


def _score_sigma_path(path: str, tokens: set[str]) -> int:
    lowered = path.lower()
    score = sum(4 for token in tokens if token and token in lowered)
    if "/cloud/" in lowered or "/aws/" in lowered:
        score += 3
    if lowered.startswith("rules/"):
        score += 2
    if lowered.startswith("rules-threat-hunting/"):
        score += 1
    return score


def _sigma_rule_summary(rule_text: str) -> dict[str, str]:
    metadata = {
        key.lower(): value.strip().strip("'\"")
        for key, value in SIGMA_METADATA_RE.findall(rule_text)
    }
    logsource_match = re.search(
        r"^logsource:\n((?:\s+[A-Za-z0-9_.-]+:\s*.+\n?)+)",
        rule_text,
        re.MULTILINE,
    )
    if logsource_match:
        metadata["logsource"] = " ".join(
            line.strip() for line in logsource_match.group(1).splitlines()
        )
    return metadata


@lru_cache(maxsize=16)
def load_sigma_rule_examples(topic: str, limit: int = MAX_SIGMA_EXAMPLES) -> dict[str, Any]:
    """Fetch bounded exemplar rules from the official SigmaHQ repository."""
    try:
        tree = json.loads(_http_get_text(SIGMA_TREE_URL))
        tokens = _sigma_query_tokens(topic)
        candidates = [
            item["path"] for item in tree.get("tree", [])
            if item.get("type") == "blob"
            and item.get("path", "").endswith((".yml", ".yaml"))
            and item.get("path", "").startswith(SIGMA_RULE_ROOTS)
        ]
        ranked = sorted(
            candidates,
            key=lambda path: (_score_sigma_path(path, tokens), -len(path)),
            reverse=True,
        )
        examples = []
        for path in ranked[: max(limit * 4, limit)]:
            if len(examples) >= limit:
                break
            rule_text = _http_get_text(f"{SIGMA_RAW_BASE}/{path}")[:MAX_SIGMA_RULE_CHARS]
            metadata = _sigma_rule_summary(rule_text)
            examples.append(
                {
                    "path": path,
                    "source": f"{SIGMA_REPO}/blob/master/{path}",
                    "raw_source": f"{SIGMA_RAW_BASE}/{path}",
                    "fetched": True,
                    "summary": metadata,
                    "rule": rule_text,
                }
            )
        return {
            "repo": SIGMA_REPO,
            "tree_source": SIGMA_TREE_URL,
            "fetched": True,
            "topic": topic,
            "examples": examples,
        }
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, URLError) as exc:
        return {
            "repo": SIGMA_REPO,
            "tree_source": SIGMA_TREE_URL,
            "fetched": False,
            "error": str(exc),
            "topic": topic,
            "examples": SIGMA_FALLBACK_EXAMPLES[:limit],
        }


def _event_value(event: dict[str, Any], *field_names: str) -> str:
    for field_name in field_names:
        if field_name in event:
            return str(event[field_name])
    return "unknown"


def _extract_elastic_query_fields(query: str) -> list[str]:
    fields = set(FILTER_FIELD_RE.findall(query))
    for group in GROUP_BY_RE.findall(query):
        fields.update(GROUP_FIELD_RE.findall(group))
    return sorted(fields)


def load_events(path: str | None) -> list[dict[str, Any]]:
    if not path:
        return SAMPLE_EVENTS

    event_path = Path(path)
    if event_path.suffix.lower() == ".csv":
        with event_path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))[:MAX_EVENTS]

    events = []
    for line in event_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped:
            events.append(json.loads(stripped))
        if len(events) >= MAX_EVENTS:
            break
    return events


@tool
def summarize_event_sample(events_json: str) -> dict[str, Any]:
    """Summarize security events before writing detections.

    Args:
        events_json: JSON array of event objects.

    Returns:
        Counts by event type, source, user, source IP, plus example field names.
    """
    events = json.loads(events_json)
    if not isinstance(events, list):
        return {"error": "events_json must be a JSON array"}

    event_types = Counter(
        _event_value(event, "event.action", "event_type") for event in events
    )
    sources = Counter(
        _event_value(event, "event.dataset", "source") for event in events
    )
    users = Counter(
        _event_value(event, "user.email", "user.name", "user") for event in events
    )
    src_ips = Counter(
        _event_value(event, "source.ip", "client.ip", "src_ip") for event in events
    )
    fields = sorted({key for event in events if isinstance(event, dict) for key in event})
    timestamps = sorted(
        _event_value(event, "@timestamp", "timestamp")
        for event in events
        if event.get("@timestamp") or event.get("timestamp")
    )
    ecs_reference = load_ecs_field_reference()

    return {
        "event_count": len(events),
        "first_timestamp": timestamps[0] if timestamps else None,
        "last_timestamp": timestamps[-1] if timestamps else None,
        "event_types": _counter_dict(event_types),
        "sources": _counter_dict(sources),
        "users": _counter_dict(users),
        "src_ips": _counter_dict(src_ips),
        "fields": fields[:40],
        "ecs_reference": {
            "source": ecs_reference["browser_source"],
            "raw_source": ecs_reference["source"],
            "fetched": ecs_reference["fetched"],
            "versions": ecs_reference["ecs_versions"],
            "common_security_field_count": len(ecs_reference["common_security_fields"]),
            "common_security_fields_sample": ecs_reference["common_security_fields"][:120],
        },
    }


@tool
def validate_sigma_rule(rule_yaml: str) -> dict[str, Any]:
    """Run lightweight checks on a Sigma-style rule string.

    Args:
        rule_yaml: Candidate Sigma YAML text.

    Returns:
        Missing required sections and a boolean validity flag.
    """
    required = ["title:", "logsource:", "detection:", "condition:"]
    missing = [item.rstrip(":") for item in required if item not in rule_yaml]
    return {
        "valid": not missing,
        "missing_sections": missing,
        "line_count": len(rule_yaml.splitlines()),
    }


@tool
def get_sigma_rule_examples(topic: str) -> dict[str, Any]:
    """Fetch exemplar Sigma rules from the official SigmaHQ repository.

    Args:
        topic: Detection topic to match, such as AWS CloudTrail IAM login.

    Returns:
        Bounded official SigmaHQ rule examples with source URLs and parsed metadata.
    """
    return load_sigma_rule_examples(topic)


@tool
def get_ecs_security_fields() -> dict[str, Any]:
    """Fetch ECS fields.csv and return security-oriented ECS field names.

    Args:
        None.

    Returns:
        ECS source metadata plus common security fields derived from ECS field sets.
    """
    reference = load_ecs_field_reference()
    return {
        "source": reference["browser_source"],
        "raw_source": reference["source"],
        "fetched": reference["fetched"],
        "error": reference["error"],
        "ecs_versions": reference["ecs_versions"],
        "all_field_count": len(reference["all_fields"]),
        "common_security_field_count": len(reference["common_security_fields"]),
        "common_security_fields": reference["common_security_fields"][:250],
    }


@tool
def validate_elastic_query(query: str) -> dict[str, Any]:
    """Check Elastic KQL or ES|QL query fields against common ECS fields.

    Args:
        query: Candidate Elastic KQL or ES|QL query.

    Returns:
        ECS fields used, fields outside the bundled ECS reference, and a validity hint.
    """
    reference = load_ecs_field_reference()
    ecs_fields = set(reference["all_fields"])
    fields = _extract_elastic_query_fields(query)
    unknown = [
        field for field in fields
        if field not in ecs_fields
        and not field.startswith("aws.cloudtrail.flattened.")
    ]
    return {
        "valid": not unknown,
        "ecs_versions": reference["ecs_versions"],
        "ecs_fields_source": reference["browser_source"],
        "ecs_raw_fields_source": reference["source"],
        "ecs_fields_fetched": reference["fetched"],
        "ecs_fields_used": fields,
        "unknown_or_integration_specific_fields": unknown,
        "note": (
            "aws.cloudtrail.flattened.* is integration-specific, not a core ECS field; "
            "prefer ECS fields when possible and call out integration fields explicitly."
        ),
    }


def make_agent(*, include_reference_tools: bool = False) -> Agent:
    profile = os.environ.get("AWS_PROFILE")
    session = boto3.Session(profile_name=profile, region_name=REGION)
    model = BedrockModel(model_id=MODEL_ID, boto_session=session)
    tools = []
    tool_guidance = (
        "Reference context from local helper functions is already included in the "
        "prompt. Use it directly and finish with the required structured output."
    )
    if include_reference_tools:
        tools = [
            summarize_event_sample,
            get_sigma_rule_examples,
            validate_sigma_rule,
            get_ecs_security_fields,
            validate_elastic_query,
        ]
        tool_guidance = (
            "Use summarize_event_sample before writing detections. Before drafting "
            "Sigma-style candidates, call get_sigma_rule_examples for relevant "
            "official SigmaHQ examples and use them as format/style references, not "
            "as replacements for source-grounded logic. Use validate_sigma_rule on "
            "each Sigma-style candidate. When writing Elastic KQL or ES|QL, call "
            "get_ecs_security_fields to fetch current ECS fields, include "
            "ecs_fields_used, and run validate_elastic_query before finalizing."
        )
    return Agent(
        model=model,
        system_prompt=(
            "You are a detection engineer. "
            f"{tool_guidance} "
            "Ground findings in the supplied events only. Prefer practical detections "
            "that defenders can tune, test, and deploy."
        ),
        tools=tools,
        callback_handler=None,
    )


def reference_topic(summary: dict[str, Any]) -> str:
    terms = []
    terms.extend(summary.get("sources", {}).keys())
    terms.extend(summary.get("event_types", {}).keys())
    return " ".join(terms)[:300] or "security telemetry detection"


def compact_reference_context(events_json: str) -> dict[str, Any]:
    summary = summarize_event_sample(events_json)
    topic = reference_topic(summary)
    sigma_examples = load_sigma_rule_examples(topic, MAX_SIGMA_EXAMPLES)
    ecs_reference = load_ecs_field_reference()
    elastic_validation_examples = [
        {
            "platform": "Elastic KQL",
            "query": 'event.dataset: "aws.cloudtrail" and event.action: "CreateAccessKey" and source.ip: *',
            "validation": validate_elastic_query(
                'event.dataset: "aws.cloudtrail" and event.action: "CreateAccessKey" and source.ip: *'
            ),
        },
        {
            "platform": "Elastic ES|QL",
            "query": (
                'FROM logs-* | WHERE event.action == "ConsoleLogin" '
                'AND user.email == "alex@example.com" | STATS count = COUNT() BY source.ip'
            ),
            "validation": validate_elastic_query(
                'FROM logs-* | WHERE event.action == "ConsoleLogin" '
                'AND user.email == "alex@example.com" | STATS count = COUNT() BY source.ip'
            ),
        },
    ]

    return {
        "event_summary": {
            "event_count": summary["event_count"],
            "first_timestamp": summary["first_timestamp"],
            "last_timestamp": summary["last_timestamp"],
            "event_types": summary["event_types"],
            "sources": summary["sources"],
            "users": summary["users"],
            "src_ips": summary["src_ips"],
            "fields": summary["fields"],
        },
        "ecs_reference": {
            "source": ecs_reference["browser_source"],
            "raw_source": ecs_reference["source"],
            "fetched": ecs_reference["fetched"],
            "versions": ecs_reference["ecs_versions"],
            "all_field_count": len(ecs_reference["all_fields"]),
            "common_security_field_count": len(ecs_reference["common_security_fields"]),
            "relevant_fields": [
                field for field in (
                    "@timestamp",
                    "event.action",
                    "event.category",
                    "event.dataset",
                    "event.outcome",
                    "source.ip",
                    "source.geo.country_iso_code",
                    "user.email",
                    "user_agent.original",
                )
                if field in ecs_reference["all_fields"]
            ],
        },
        "sigma_reference": {
            "repo": sigma_examples["repo"],
            "fetched": sigma_examples["fetched"],
            "topic": sigma_examples["topic"],
            "examples": [
                {
                    "path": example["path"],
                    "source": example["source"],
                    "summary": example["summary"],
                    "rule_excerpt": example["rule"][:MAX_SIGMA_PROMPT_CHARS],
                }
                for example in sigma_examples["examples"]
            ],
        },
        "prevalidated_elastic_queries": elastic_validation_examples,
        "sigma_validation_rule": (
            "Sigma candidates must include title:, logsource:, detection:, and a "
            "condition: line inside detection."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", help="Path to JSONL or CSV security events.")
    parser.add_argument(
        "--agent-tools",
        action="store_true",
        help=(
            "Let the agent call reference/validation tools itself. Default preloads "
            "references locally because structured output is more reliable with only "
            "the final output tool available."
        ),
    )
    args = parser.parse_args()

    events = load_events(args.events)
    events_json = json.dumps(events, indent=2, ensure_ascii=False)[:MAX_EVENT_CHARS]
    reference_context = compact_reference_context(events_json)
    prompt = (
        "Build a detection engineering pack from these security events. "
        "Use the included official SigmaHQ excerpts only as rule-shape references. "
        "Include at least two Sigma-style candidates, and make each candidate pass "
        "the included Sigma validation rule. Include Elastic KQL and Elastic ES|QL "
        "hunting queries where useful, using ECS-standard fields from the included "
        "ECS reference. Elastic KQL queries must be filter expressions only with no "
        "pipes or FROM clause. Elastic ES|QL queries must start with FROM and may use "
        "pipes. Do not invent event fields that are not in the event sample or ECS "
        "reference.\n\n"
        "Reference context:\n"
        f"{json.dumps(reference_context, indent=2, ensure_ascii=False)}\n\n"
        "Security events:\n"
        f"{events_json}"
    )
    result = make_agent(include_reference_tools=args.agent_tools)(
        prompt,
        structured_output_model=DetectionPack,
    )
    print(json.dumps(result.structured_output.model_dump(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
