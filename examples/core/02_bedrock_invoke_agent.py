"""
Hello World: AWS Bedrock Agent
Invokes a Bedrock Agent using InvokeAgent (streaming response).
Prerequisites: Create an agent in the console, note its AGENT_ID and ALIAS_ID.
Endpoint: bedrock-agent-runtime  Auth: SigV4 (boto3 credentials)

SSO: set AWS_PROFILE=your-sso-profile-name before running, or set PROFILE below.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)
import os
import uuid
import boto3
from botocore.exceptions import ClientError

AGENT_ID = "YOUR_AGENT_ID"     # e.g. "ABCD1234EF"
ALIAS_ID = "YOUR_ALIAS_ID"     # e.g. "TSTALIASID" (default test alias)
REGION = "us-east-1"
PROFILE = os.environ.get("AWS_PROFILE")  # e.g. "my-sso-profile"

session = boto3.Session(profile_name=PROFILE, region_name=REGION)
client = session.client("bedrock-agent-runtime")

try:
    response = client.invoke_agent(
        agentId=AGENT_ID,
        agentAliasId=ALIAS_ID,
        sessionId=str(uuid.uuid4()),
        inputText="Say hello and tell me what you can help with.",
    )

    full_response = ""
    for event in response["completion"]:
        if "chunk" in event:
            full_response += event["chunk"]["bytes"].decode()

    print(f"Agent: {full_response}")

except ClientError as e:
    print(f"Error: {e}")
