"""
Hello World: Strands Persistent Memory — local cyber briefing preferences
Shows long-term memory with explicit tools backed by ./sessions/security_memory.json.

The current installed Strands SDK in this repo does not expose the newer
MemoryManager constructor surface from the docs, so this example keeps the memory
backend as normal Strands tools. It still demonstrates cross-run recall/write.

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python 16_strands_local_memory_advisor.py
"""

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)
import json
import os
from pathlib import Path

import boto3
from strands import Agent, tool
from strands.models import BedrockModel

REGION = "us-east-1"
MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
MEMORY_FILE = Path(__file__).with_name("sessions") / "security_memory.json"


def _load_memories() -> list[dict[str, str]]:
    if not MEMORY_FILE.exists():
        return []
    return json.loads(MEMORY_FILE.read_text())


def _save_memories(memories: list[dict[str, str]]) -> None:
    MEMORY_FILE.parent.mkdir(exist_ok=True)
    MEMORY_FILE.write_text(json.dumps(memories, indent=2, ensure_ascii=False) + "\n")


@tool
def remember_preference(key: str, value: str) -> str:
    """Save a durable user preference or stable security-analysis fact.

    Args:
        key: Short memory key, e.g. "summary_style" or "primary_cloud".
        value: Preference or fact to remember.

    Returns:
        Confirmation that the memory was saved.
    """
    memories = _load_memories()
    memories = [m for m in memories if m["key"] != key]
    memories.append({"key": key, "value": value})
    _save_memories(memories)
    return f"remembered {key}={value}"


@tool
def recall_preferences(query: str) -> str:
    """Search durable user preferences and stable security-analysis facts.

    Args:
        query: Search phrase such as "style", "cloud", or "report".

    Returns:
        Matching memories as text.
    """
    words = {w.lower() for w in query.split()}
    matches = []
    for item in _load_memories():
        haystack = f"{item['key']} {item['value']}".lower()
        if not words or any(word in haystack for word in words):
            matches.append(f"- {item['key']}: {item['value']}")
    return "\n".join(matches) if matches else "No matching memories."


def make_agent() -> Agent:
    profile = os.environ.get("AWS_PROFILE")
    session = boto3.Session(profile_name=profile, region_name=REGION)
    model = BedrockModel(model_id=MODEL_ID, boto_session=session)
    return Agent(
        model=model,
        system_prompt=(
            "You are a cyber-security briefing advisor with durable memory tools. "
            "Use recall_preferences before tailoring advice. Use remember_preference "
            "when the user states a stable preference worth reusing later."
        ),
        tools=[remember_preference, recall_preferences],
        callback_handler=None,
    )


def main() -> None:
    agent = make_agent()
    turns = [
        (
            "Remember that I prefer cyber summaries in board-ready language, "
            "with a short action list and no hype."
        ),
        "Given my preferences, how should you summarize a new ransomware advisory?",
    ]
    for turn in turns:
        print(f"User: {turn}")
        print(f"Assistant: {agent(turn)}\n")
    print(f"Memory file: {MEMORY_FILE}")


if __name__ == "__main__":
    main()
