"""
Hello World: Strands Multi-Agent — Krebs on Security feed reader + summariser
Architecture (agents-as-tools pattern):
  - fetcher_agent   — fetches the KrebsOnSecurity RSS feed and returns raw articles
  - time_agent      — provides the current date/time for context
  - orchestrator    — calls both sub-agents, then summarises the articles

Tools used:
  - strands_tools.rss          (fetcher_agent)
  - strands_tools.current_time (time_agent)
  Sub-agents are passed directly into the orchestrator's tools list — Strands
  wraps them automatically so the orchestrator can call them like any other tool.

Install: uv sync  (strands-agents + strands-agents-tools[rss] already in pyproject.toml)
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
import boto3
from strands import Agent
from strands.models import BedrockModel
from strands_tools import rss, current_time

REGION = "us-east-1"
MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
KREBS_FEED = "https://krebsonsecurity.com/feed/"

profile = os.environ.get("AWS_PROFILE")
session = boto3.Session(profile_name=profile, region_name=REGION)


def make_model(**kwargs) -> BedrockModel:
    return BedrockModel(model_id=MODEL_ID, boto_session=session, **kwargs)


# --- Sub-agent 1: fetches the RSS feed ---
fetcher_agent = Agent(
    name="fetcher_agent",
    model=make_model(),
    system_prompt=f"""You are a feed fetcher. When asked, subscribe to and fetch
articles from the KrebsOnSecurity RSS feed at {KREBS_FEED}.
Return a structured list of articles: title, link, publication date, and summary.
Fetch at most 5 articles. Return only the raw article data — no extra commentary.""",
    tools=[rss],
    callback_handler=None,
)

# --- Sub-agent 2: provides the current date/time ---
time_agent = Agent(
    name="time_agent",
    model=make_model(),
    system_prompt="""You are a time assistant. When asked, return the current
date and time in the US/Eastern timezone. Return only the timestamp — no extra text.""",
    tools=[current_time],
    callback_handler=None,
)

# --- Orchestrator: calls both sub-agents then summarises ---
orchestrator = Agent(
    name="orchestrator",
    model=make_model(),
    system_prompt="""You are a security news briefing assistant.

When the user asks for a briefing:
1. Call time_agent to get the current date/time.
2. Call fetcher_agent to retrieve the latest articles from KrebsOnSecurity.
3. Write a concise briefing that includes:
   - The current date/time at the top
   - A numbered list of the articles, each with:
       * Title (as a link if possible)
       * 2-3 sentence summary of what the article is about
       * Why it matters from a security perspective

Keep the tone professional and factual.""",
    tools=[fetcher_agent, time_agent],  # Strands auto-wraps agents as callable tools
)


if __name__ == "__main__":
    print("Fetching KrebsOnSecurity feed and generating briefing...\n")
    orchestrator("Give me a security news briefing from KrebsOnSecurity.")
