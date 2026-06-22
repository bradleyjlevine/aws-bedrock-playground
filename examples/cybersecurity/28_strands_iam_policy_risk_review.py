"""
Hello World: Strands Structured Output — IAM policy risk review
Reviews an IAM policy document for risky permissions and least-privilege fixes.

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python examples/cybersecurity/28_strands_iam_policy_risk_review.py
         uv run python examples/cybersecurity/28_strands_iam_policy_risk_review.py --policy ./policy.json
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
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import boto3
from pydantic import BaseModel, Field
from strands import Agent, tool
from strands.models import BedrockModel

REGION = "us-east-1"
MODEL_ID = "openai.gpt-oss-120b-1:0"

PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:CreatePolicyVersion",
    "iam:PassRole",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "sts:AssumeRole",
}

SAMPLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "BroadAdminForAutomation",
            "Effect": "Allow",
            "Action": ["iam:*", "lambda:*", "s3:*"],
            "Resource": "*",
        },
        {
            "Sid": "PassAnyRole",
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*",
        },
    ],
}


class PolicyRisk(BaseModel):
    """Risk found in an IAM policy statement."""

    severity: str = Field(description="critical, high, medium, low, or informational")
    statement_sid: str | None
    issue: str
    evidence: str
    impact: str


class PolicyFix(BaseModel):
    """Least-privilege remediation."""

    priority: str = Field(description="high, medium, or low")
    change: str
    rationale: str
    example_policy_fragment: dict[str, Any] | None = None


class IAMPolicyReview(BaseModel):
    """Validated IAM policy review output."""

    title: str
    overall_risk: str = Field(description="critical, high, medium, low, or informational")
    executive_summary: str
    risks: list[PolicyRisk]
    least_privilege_fixes: list[PolicyFix]
    compensating_controls: list[str]
    questions_for_owner: list[str]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _matches_any(action: str, patterns: set[str]) -> bool:
    normalized = action.lower()
    return any(
        fnmatch(normalized, pattern.lower()) or fnmatch(pattern.lower(), normalized)
        for pattern in patterns
    )


def load_policy(path: str | None) -> dict[str, Any]:
    if not path:
        return SAMPLE_POLICY
    return json.loads(Path(path).read_text(encoding="utf-8"))


@tool
def summarize_iam_policy(policy_json: str) -> dict[str, Any]:
    """Summarize IAM policy risk signals for an analyst.

    Args:
        policy_json: IAM policy JSON document.

    Returns:
        Statement counts, wildcard findings, sensitive actions, and explicit denies.
    """
    policy = json.loads(policy_json)
    statements = _as_list(policy.get("Statement"))
    findings = []
    allow_count = 0
    deny_count = 0
    sensitive_actions: list[dict[str, Any]] = []

    for index, statement in enumerate(statements):
        sid = statement.get("Sid") or f"statement_{index + 1}"
        effect = statement.get("Effect", "")
        actions = [str(action) for action in _as_list(statement.get("Action"))]
        resources = [str(resource) for resource in _as_list(statement.get("Resource"))]

        if effect == "Allow":
            allow_count += 1
        if effect == "Deny":
            deny_count += 1
        if effect == "Allow" and any(action == "*" or action.endswith(":*") for action in actions):
            findings.append({"sid": sid, "type": "wildcard_action", "actions": actions})
        if effect == "Allow" and "*" in resources:
            findings.append({"sid": sid, "type": "wildcard_resource", "actions": actions})

        matched = [
            action for action in actions
            if action == "*" or _matches_any(action, PRIVILEGE_ESCALATION_ACTIONS)
        ]
        if effect == "Allow" and matched:
            sensitive_actions.append({"sid": sid, "actions": matched, "resources": resources})

    return {
        "statement_count": len(statements),
        "allow_count": allow_count,
        "deny_count": deny_count,
        "findings": findings,
        "sensitive_actions": sensitive_actions,
    }


@tool
def suggest_iam_condition_keys(action: str) -> list[str]:
    """Suggest condition keys that often help scope risky IAM actions.

    Args:
        action: IAM action name such as iam:PassRole or s3:PutObject.

    Returns:
        Candidate IAM condition keys to consider.
    """
    normalized = action.lower()
    if normalized == "iam:passrole":
        return ["iam:PassedToService", "aws:PrincipalArn", "aws:ResourceTag/<tag-key>"]
    if normalized.startswith("s3:"):
        return ["s3:prefix", "s3:x-amz-server-side-encryption", "aws:ResourceTag/<tag-key>"]
    if normalized.startswith("lambda:"):
        return ["lambda:FunctionArn", "aws:RequestTag/<tag-key>", "aws:PrincipalArn"]
    if normalized.startswith("sts:"):
        return ["aws:PrincipalArn", "aws:PrincipalOrgID", "sts:ExternalId"]
    return ["aws:PrincipalArn", "aws:RequestedRegion", "aws:ResourceTag/<tag-key>"]


def make_agent() -> Agent:
    profile = os.environ.get("AWS_PROFILE")
    session = boto3.Session(profile_name=profile, region_name=REGION)
    model = BedrockModel(model_id=MODEL_ID, boto_session=session)
    return Agent(
        model=model,
        system_prompt=(
            "You are an AWS IAM security reviewer. Use summarize_iam_policy first. "
            "Use suggest_iam_condition_keys when recommending scoped alternatives for "
            "risky actions. Be specific about least-privilege changes and avoid claims "
            "not supported by the policy."
        ),
        tools=[summarize_iam_policy, suggest_iam_condition_keys],
        callback_handler=None,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", help="Path to an IAM policy JSON document.")
    args = parser.parse_args()

    policy = load_policy(args.policy)
    policy_json = json.dumps(policy, indent=2, ensure_ascii=False)
    result = make_agent()(
        "Review this IAM policy for privilege escalation and least-privilege risk. "
        "Return practical fixes with example policy fragments where useful.\n\n"
        + policy_json,
        structured_output_model=IAMPolicyReview,
    )
    print(json.dumps(result.structured_output.model_dump(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
