"""
Hello World: AWS Bedrock Mantle — Anthropic Messages API
Uses AnthropicBedrockMantle with aws_profile= for SSO/named-profile support.
Auth falls back to default credential chain if AWS_PROFILE is not set.

Install: pip install -U "anthropic[bedrock]"
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
from anthropic import AnthropicBedrockMantle

REGION = "us-east-1"
PROFILE = os.environ.get("AWS_PROFILE")
MANTLE_DEFAULT_HEADERS = {"anthropic-workspace": "default"}

# AnthropicBedrockMantle accepts aws_profile= directly — it builds a boto3.Session
# internally and signs requests with SigV4 using those credentials.
client = AnthropicBedrockMantle(
    aws_region=REGION,
    aws_profile=PROFILE,
    default_headers=MANTLE_DEFAULT_HEADERS,
)

message = client.messages.create(
    model="anthropic.claude-haiku-4-5",
    max_tokens=64,
    messages=[{"role": "user", "content": "Say 'Hello from Bedrock Mantle!' and nothing else."}],
)

print(message.content[0].text)
