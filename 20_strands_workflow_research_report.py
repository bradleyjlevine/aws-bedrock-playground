"""
Hello World: Strands Workflow Tool — parallel cyber research report
Uses the community workflow tool to create dependent research tasks, start them,
and inspect workflow status.

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python 20_strands_workflow_research_report.py
"""
import os

import boto3
from strands import Agent
from strands.models import BedrockModel
from strands_tools import workflow

REGION = "us-east-1"
MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


def make_agent() -> Agent:
    profile = os.environ.get("AWS_PROFILE")
    session = boto3.Session(profile_name=profile, region_name=REGION)
    model = BedrockModel(model_id=MODEL_ID, boto_session=session)
    return Agent(
        model=model,
        system_prompt=(
            "You are a workflow coordinator for cyber-security research. Use the "
            "workflow tool directly to create, start, and report task status. Keep "
            "tasks narrow and dependency-aware."
        ),
        tools=[workflow],
        callback_handler=None,
    )


def main() -> None:
    agent = make_agent()
    workflow_id = "cyber_research_report"
    tasks = [
        {
            "task_id": "source_scan",
            "description": "Identify the core claims and concrete facts in the source material.",
            "system_prompt": "You extract source-backed facts and avoid speculation.",
            "priority": 5,
        },
        {
            "task_id": "threat_mapping",
            "description": "Map the facts to likely tactics, techniques, affected assets, and actor goals.",
            "dependencies": ["source_scan"],
            "system_prompt": "You map cyber facts to analyst-friendly threat models.",
            "priority": 4,
        },
        {
            "task_id": "defense_plan",
            "description": "Turn the threat mapping into prioritized defensive actions.",
            "dependencies": ["threat_mapping"],
            "system_prompt": "You write practical detection, patching, and containment guidance.",
            "priority": 3,
        },
        {
            "task_id": "executive_report",
            "description": "Combine all task outputs into a concise executive cyber research report.",
            "dependencies": ["defense_plan"],
            "system_prompt": "You produce clear executive reports with caveats and next actions.",
            "priority": 2,
        },
    ]

    print(agent.tool.workflow(action="delete", workflow_id=workflow_id))
    print(agent.tool.workflow(action="create", workflow_id=workflow_id, tasks=tasks))
    print(agent.tool.workflow(action="start", workflow_id=workflow_id))
    print(agent.tool.workflow(action="status", workflow_id=workflow_id))


if __name__ == "__main__":
    main()
