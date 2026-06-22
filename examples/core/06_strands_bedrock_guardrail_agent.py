"""
Hello World: Strands Single Agent with AWS Bedrock Guardrail
Uses the Strands Agents SDK to create a single agent backed by BedrockModel
with a guardrail applied to every inference call.

Guardrail is enforced at the model level — Strands automatically overwrites blocked
user input in conversation history so follow-up turns are not re-blocked.

Install: pip install strands-agents
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
import sys
import boto3
from strands import Agent
from strands.models import BedrockModel

REGION = "us-east-1"
MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
)

# Guardrail — ARN or short ID both accepted. Create one in the Bedrock console,
# then export BEDROCK_GUARDRAIL_ID before running this example.
GUARDRAIL_ID = os.environ.get("BEDROCK_GUARDRAIL_ID")
GUARDRAIL_VERSION = os.environ.get("BEDROCK_GUARDRAIL_VERSION", "DRAFT")

if not GUARDRAIL_ID:
    print(
        "Set BEDROCK_GUARDRAIL_ID to your guardrail ARN or short ID before running this example.",
        file=sys.stderr,
    )
    sys.exit(2)

# Pass the SSO/named profile through to Strands via a boto3 session
profile = os.environ.get("AWS_PROFILE")
session = boto3.Session(profile_name=profile, region_name=REGION)

# Guardrail params are passed as kwargs into BedrockConfig via **model_config
model = BedrockModel(
    model_id=MODEL_ID,
    boto_session=session,
    guardrail_id=GUARDRAIL_ID,
    guardrail_version=GUARDRAIL_VERSION,
    guardrail_trace="enabled",                # "enabled" | "disabled" | "enabled_full"
    guardrail_stream_processing_mode="sync",  # "sync" | "async"
    guardrail_redact_input=True,              # overwrite blocked input in history (default True)
    guardrail_redact_output=False,            # overwrite blocked output in history (default False)
)

agent = Agent(
    model=model,
    system_prompt="You are a helpful assistant. Answer concisely.",
    callback_handler=None,  # suppress streaming output; we print the result ourselves below
)

if __name__ == "__main__":
    response = agent("Say 'Hello from Strands on AWS Bedrock!' and nothing else.")

    if response.stop_reason == "guardrail_intervened":
        print("Guardrail blocked this response.")
    else:
        print(response)
