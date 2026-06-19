"""
Hello World: Strands Agent over AWS Bedrock Mantle (GPT-5.4)

GPT-5.4 and GPT-5.5 use Bedrock Mantle's /openai/v1 path and the OpenAI
Responses API. Strands' built-in bedrock_mantle_config currently targets the
plain /v1 path for OSS/Nova-style OpenAI-compatible models, so this example
uses a tiny OpenAIResponsesModel subclass to point Strands at /openai/v1.

SSO: aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run: uv run python 22_strands_mantle_openai_gpt54.py
"""

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)

from typing import Any

from strands import Agent
from strands.models.openai_responses import OpenAIResponsesModel

from auth import get_mantle_token

REGION = "us-east-2"
MODEL_ID = "openai.gpt-5.4"
REQUEST_TIMEOUT_SECONDS = 45.0
MANTLE_DEFAULT_HEADERS = {"OpenAI-Project": "default"}


class BedrockMantleOpenAIResponsesModel(OpenAIResponsesModel):
    """Strands OpenAI Responses adapter backed by Bedrock Mantle /openai/v1."""

    def _resolve_client_args(self) -> dict[str, Any]:
        return {
            **self.client_args,
            "base_url": f"https://bedrock-mantle.{REGION}.api.aws/openai/v1",
            "api_key": get_mantle_token(REGION),
        }


model = BedrockMantleOpenAIResponsesModel(
    model_id=MODEL_ID,
    client_args={
        "default_headers": MANTLE_DEFAULT_HEADERS,
        "timeout": REQUEST_TIMEOUT_SECONDS,
        "max_retries": 0,
    },
    params={"max_output_tokens": 256},
)

agent = Agent(
    model=model,
    system_prompt="You are a concise assistant running through Strands on GPT-5.4 via AWS Bedrock Mantle.",
    callback_handler=None,
)


if __name__ == "__main__":
    response = agent("Say 'Hello from Strands on GPT-5.4 via Bedrock Mantle!' and nothing else.")
    print(response)
