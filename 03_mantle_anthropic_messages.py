"""
Hello World: AWS Bedrock Mantle — Anthropic Messages API
Uses AnthropicBedrockMantle with aws_profile= for SSO/named-profile support.
Auth falls back to default credential chain if AWS_PROFILE is not set.

Install: pip install -U "anthropic[bedrock]"
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
"""
import os
from anthropic import AnthropicBedrockMantle
import logging

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")

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
