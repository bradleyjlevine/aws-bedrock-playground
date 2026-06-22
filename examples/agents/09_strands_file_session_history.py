"""
Hello World: Strands FileSessionManager — persistent conversation across runs
Uses FileSessionManager to save the agent's conversation history to disk.
Re-running the script continues from where the previous run left off.

Session files are stored in: ./sessions/hello-session/
Delete that directory to start a fresh conversation.

Demonstrates:
  - FileSessionManager with a named session_id
  - session_id / agent_id are passed to Agent so history is keyed consistently
  - Conversation context is preserved between separate Python process invocations
  - current_time tool so the agent can answer date/time questions

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)
import os
import boto3
from strands import Agent
from strands.models import BedrockModel
from strands.session import FileSessionManager
from strands_tools import current_time

REGION = "us-east-1"
MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
)
SESSION_ID = "hello-session"
AGENT_ID = "assistant"
SESSIONS_DIR = os.path.join(os.path.dirname(__file__), "sessions")

profile = os.environ.get("AWS_PROFILE")
session = boto3.Session(profile_name=profile, region_name=REGION)
model = BedrockModel(model_id=MODEL_ID, boto_session=session)

session_manager = FileSessionManager(
    session_id=SESSION_ID,
    storage_dir=SESSIONS_DIR,
)

agent = Agent(
    model=model,
    agent_id=AGENT_ID,
    system_prompt=(
        "You are a helpful assistant with a persistent memory. "
        "Remember everything the user tells you across conversations. "
        "Use current_time when asked about the date or time."
    ),
    tools=[current_time],
    session_manager=session_manager,
    callback_handler=None,
)

TURNS = [
    "My name is Alex and my favourite AWS service is Bedrock.",
    "What is my name and favourite AWS service?",
]

if __name__ == "__main__":
    session_path = os.path.join(SESSIONS_DIR, f"session_{SESSION_ID}")
    is_new = not os.path.exists(session_path)
    print(
        f"{'Starting new session' if is_new else 'Resuming existing session'}: {SESSION_ID!r}\n"
        f"Session files: {session_path}\n"
    )

    for turn in TURNS:
        print(f"User: {turn}")
        response = agent(turn)
        print(f"Assistant: {response}\n")

    print(
        "Session saved. Re-run this script — the agent will remember the conversation."
    )
