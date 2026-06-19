"""
Hello World: OpenAI Codex on AWS Bedrock
Codex uses GPT-5.5 inference via the Responses API on bedrock-mantle.
Auth: bearer tokens are minted from the boto3 credential chain
(respects AWS_PROFILE / SSO) through OpenAI's BedrockOpenAI client.

Install: pip install openai aws-bedrock-token-generator
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile

To use Codex CLI instead of this script:
  npm install -g @openai/codex
  aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
  # In ~/.codex/config.toml:
  #   model-provider = "amazon-bedrock"
  #   model = "openai.gpt-5.5"
  #   region = "us-east-2"
"""

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)
import sys

from openai import BedrockOpenAI

from auth import get_mantle_token

REGION = "us-east-2"  # GPT-5.5 is only available in us-east-2 (Ohio); GPT-5.4 also in us-east-2.
PRIMARY_MODEL = "openai.gpt-5.5"
FALLBACK_MODEL = "openai.gpt-5.4"
REQUEST_TIMEOUT_SECONDS = 45.0

# Bedrock-mantle scopes inference to a "Project" for usage attribution. The
# Bedrock console's live API examples set this header, and GPT-5.5 routing can
# require a project context.
MANTLE_DEFAULT_HEADERS = {"OpenAI-Project": "default"}


def is_gpt55_outage(exc: BaseException) -> bool:
    """Match the known intermittent Bedrock-side failure mode for GPT-5.5."""
    msg = str(exc).lower()
    return (
        "internal_server_error" in msg
        or "engine not found" in msg
        or "server had an error" in msg
        or "timed out" in msg
        or "timeout" in msg
    )


def responses_with_fallback(client, *, model=PRIMARY_MODEL, fallback=FALLBACK_MODEL, **kwargs):
    """Try GPT-5.5, falling back to GPT-5.4 on known Bedrock-side failures."""
    try:
        print(f"[request] calling {model} in {REGION}...", file=sys.stderr, flush=True)
        resp = client.responses.create(model=model, **kwargs)
    except Exception as exc:
        if not is_gpt55_outage(exc):
            raise
        print(
            f"[fallback] {model} did not return cleanly ({exc}); retrying with {fallback}.",
            file=sys.stderr,
            flush=True,
        )
        print(f"[request] calling {fallback} in {REGION}...", file=sys.stderr, flush=True)
        return client.responses.create(model=fallback, **kwargs)
    if not (getattr(resp, "output_text", None) or "").strip():
        print(
            f"[fallback] {model} returned an empty response; retrying with {fallback}.",
            file=sys.stderr,
            flush=True,
        )
        print(f"[request] calling {fallback} in {REGION}...", file=sys.stderr, flush=True)
        return client.responses.create(model=fallback, **kwargs)
    return resp


def get_token() -> str:
    print(f"[auth] minting Bedrock bearer token for {REGION}...", file=sys.stderr, flush=True)
    return get_mantle_token(REGION)


client = BedrockOpenAI(
    aws_region=REGION,
    bedrock_token_provider=get_token,
    default_headers=MANTLE_DEFAULT_HEADERS,
    timeout=REQUEST_TIMEOUT_SECONDS,
    max_retries=0,
)

# Prefer GPT-5.5; fall back to GPT-5.4 on the known intermittent
# bedrock-mantle server_error (openai/codex#27185).
response = responses_with_fallback(
    client,
    input="Write a Python one-liner that prints 'Hello, World!' using a lambda.",
)

print(response.output_text)
