"""
Hello World: Strands Custom Tool — @tool decorator
Defines two custom tools using the @tool decorator:
  - word_count   — counts words in a string
  - reverse_text — reverses a string

The agent is given a short paragraph and asked to use both tools on it.
The @tool decorator reads the function signature and docstring to generate
the Bedrock tool spec automatically — no manual JSON schema required.

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
"""
import os
import boto3
from strands import Agent, tool
from strands.models import BedrockModel

REGION = "us-east-1"
MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

profile = os.environ.get("AWS_PROFILE")
session = boto3.Session(profile_name=profile, region_name=REGION)
model = BedrockModel(model_id=MODEL_ID, boto_session=session)


@tool
def word_count(text: str) -> int:
    """Count the number of words in the given text.

    Args:
        text: The text to count words in.

    Returns:
        The number of words.
    """
    return len(text.split())


@tool
def reverse_text(text: str) -> str:
    """Reverse the characters in the given text.

    Args:
        text: The text to reverse.

    Returns:
        The reversed text.
    """
    return text[::-1]


agent = Agent(
    model=model,
    system_prompt=(
        "You are a text analysis assistant. "
        "When given text, use your tools to analyse it and report the results clearly."
    ),
    tools=[word_count, reverse_text],
)

SAMPLE_TEXT = (
    "AWS Bedrock makes it easy to build and scale generative AI applications "
    "using foundation models from leading AI companies."
)

if __name__ == "__main__":
    print(f"Sample text: {SAMPLE_TEXT!r}\n")
    agent(
        f"Using your tools, tell me: (1) how many words are in this text, "
        f"and (2) what the text looks like reversed. Text: '{SAMPLE_TEXT}'"
    )
