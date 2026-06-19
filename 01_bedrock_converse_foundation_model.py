"""
Hello World: AWS Bedrock Foundation Model
Uses the Converse API (recommended over InvokeModel) with Claude Haiku 4.5.
Endpoint: bedrock-runtime  Auth: SigV4 (boto3 credentials)

SSO: set AWS_PROFILE=your-sso-profile-name before running, or set PROFILE below.
"""
import os
import boto3
from botocore.exceptions import ClientError

# Cross-region inference profile prefix (us.) improves availability
MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
REGION = "us-east-1"
PROFILE = os.environ.get("AWS_PROFILE")  # e.g. "my-sso-profile"

session = boto3.Session(profile_name=PROFILE, region_name=REGION)
client = session.client("bedrock-runtime")

try:
    response = client.converse(
        modelId=MODEL_ID,
        messages=[
            {
                "role": "user",
                "content": [{"text": "Say 'Hello from AWS Bedrock!' and nothing else."}],
            }
        ],
        inferenceConfig={"maxTokens": 64, "temperature": 0.5},
    )
    print(response["output"]["message"]["content"][0]["text"])

except ClientError as e:
    print(f"Error: {e}")
