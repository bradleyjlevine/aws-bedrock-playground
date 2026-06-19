"""
Hello World: Strands Agent over AWS Bedrock Mantle (Anthropic Messages API)

Strands does not currently ship a dedicated Bedrock Mantle model provider. This
example keeps the Strands agent loop and tool formatting by reusing Strands'
AnthropicModel adapter, then swaps the underlying Anthropic client to the
Mantle-specific AsyncAnthropicBedrockMantle client.

SSO: aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run: uv run python 21_strands_mantle_anthropic_adapter.py
"""

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)

import os
from typing import Any

from anthropic.lib.bedrock import AsyncAnthropicBedrockMantle
from strands import Agent
from strands.models.anthropic import AnthropicModel

REGION = "us-east-1"
MODEL_ID = "anthropic.claude-haiku-4-5"
MANTLE_DEFAULT_HEADERS = {"anthropic-workspace": "default"}


class AnthropicMantleModel(AnthropicModel):
    """Strands Anthropic adapter backed by AWS Bedrock Mantle."""

    def __init__(self, *, aws_region: str, aws_profile: str | None = None, **model_config: Any) -> None:
        super().__init__(**model_config)
        self.client = AsyncAnthropicBedrockMantle(
            aws_region=aws_region,
            aws_profile=aws_profile,
            default_headers=MANTLE_DEFAULT_HEADERS,
        )


profile = os.environ.get("AWS_PROFILE")

model = AnthropicMantleModel(
    aws_region=REGION,
    aws_profile=profile,
    model_id=MODEL_ID,
    max_tokens=256,
    params={"temperature": 0.2},
)

agent = Agent(
    model=model,
    system_prompt="You are a concise assistant running through Strands on AWS Bedrock Mantle.",
    callback_handler=None,
)


if __name__ == "__main__":
    response = agent("Say 'Hello from Strands on Bedrock Mantle!' and nothing else.")
    print(response)
