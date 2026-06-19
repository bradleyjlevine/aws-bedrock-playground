"""
Hello World: Strands Swarm — autonomous agent handoff
Creates a three-agent swarm where agents hand off to each other based on expertise:

  triage_agent    — classifies the question and routes to the right specialist
  security_agent  — answers security-related questions
  cloud_agent     — answers AWS / cloud architecture questions

The Swarm class injects a handoff_to_agent(agent_name, message) tool into each
agent automatically. Agents hand off by calling that tool; the swarm keeps routing
until one agent produces a final answer (or max_handoffs is reached).

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
"""

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)
import os
import boto3
from strands import Agent
from strands.models import BedrockModel
from strands.multiagent import Swarm

REGION = "us-east-1"
MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

profile = os.environ.get("AWS_PROFILE")
boto_session = boto3.Session(profile_name=profile, region_name=REGION)


def make_model() -> BedrockModel:
    return BedrockModel(model_id=MODEL_ID, boto_session=boto_session)


triage_agent = Agent(
    name="triage_agent",
    model=make_model(),
    system_prompt="""You are a triage agent. Your only job is to read the user's question
and hand it off to the correct specialist using the handoff_to_agent tool:
- agent_name='security_agent' for cybersecurity, vulnerabilities, IAM, or data protection.
- agent_name='cloud_agent' for AWS services, cloud architecture, or infrastructure.
Never answer the question yourself — always hand off immediately.""",
)

security_agent = Agent(
    name="security_agent",
    model=make_model(),
    system_prompt="""You are a security expert specialising in AWS and cloud security.
Answer the user's question concisely and accurately.
If the question is actually about cloud architecture (not security),
use handoff_to_agent with agent_name='cloud_agent'.""",
)

cloud_agent = Agent(
    name="cloud_agent",
    model=make_model(),
    system_prompt="""You are an AWS cloud architect.
Answer the user's question about AWS services and architecture concisely and accurately.
If the question is actually about security (not architecture),
use handoff_to_agent with agent_name='security_agent'.""",
)

swarm = Swarm(
    nodes=[triage_agent, security_agent, cloud_agent],
    entry_point=triage_agent,
    max_handoffs=6,
)

QUESTIONS = [
    "What is the principle of least privilege and how does it apply to IAM roles?",
    "What are the key differences between Amazon SQS and Amazon SNS?",
]

if __name__ == "__main__":
    for question in QUESTIONS:
        print(f"Question: {question}")
        print("-" * 60)
        result = swarm(question)
        final_agent = result.node_history[-1].node_id if result.node_history else "unknown"
        final_text = result.results[final_agent].result.message["content"][0]["text"]
        print(f"\nFinal answer (from {final_agent}):\n{final_text}\n")
        print("=" * 60 + "\n")
