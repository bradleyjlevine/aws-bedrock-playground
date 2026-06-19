"""
Hello World: AWS Bedrock Mantle — OpenAI Responses API (Amazon Nova)
Amazon Nova models support the OpenAI Responses API on the bedrock-mantle openai/v1 path.
(Claude models on this path use the Anthropic Messages API instead — see 03_mantle_anthropic_messages.py)
Auth: bearer token minted from the boto3 credential chain (respects AWS_PROFILE / SSO).

Install: pip install openai aws-bedrock-token-generator
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
"""
from openai import OpenAI
from auth import get_mantle_token

REGION = "us-east-1"

# Note: OSS/Nova models use /v1 base path. GPT-5.5 uses /openai/v1 (see 05_mantle_gpt55_codex.py)
client = OpenAI(
    base_url=f"https://bedrock-mantle.{REGION}.api.aws/v1",
    api_key=get_mantle_token(REGION),
)

response = client.responses.create(
    model="openai.gpt-oss-120b",
    input="Say 'Hello from Bedrock Mantle via OpenAI SDK!' and nothing else.",
)

print(response.output_text)
