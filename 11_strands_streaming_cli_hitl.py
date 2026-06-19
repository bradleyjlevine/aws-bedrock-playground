"""
Hello World: Strands Streaming — custom callback handler + CLI chat loop + HITL
Demonstrates:
  - Custom callback_handler that streams tokens + flags tool calls
  - Interactive CLI chat loop (type 'quit' or Ctrl-C to exit)
  - Human-in-the-loop via strands_tools.handoff_to_user: the agent pauses and
    asks for approval before calling send_email — the tool itself never blocks

Tools:
  - word_count       — runs immediately, no approval needed
  - calculator       — runs immediately, no approval needed
  - current_time     — returns the current date/time
  - handoff_to_user  — pauses agent loop for human approval (HITL)
  - send_email       — only called after handoff_to_user approval

Try: "Email alex@example.com to say the deploy is done."
     "What time is it?"

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
"""

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)
import os
import sys
import boto3
from strands import Agent, tool
from strands.models import BedrockModel
from strands_tools import handoff_to_user, current_time

REGION = "us-east-1"
MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

profile = os.environ.get("AWS_PROFILE")
session = boto3.Session(profile_name=profile, region_name=REGION)
model = BedrockModel(model_id=MODEL_ID, boto_session=session)


# ---------------------------------------------------------------------------
# Custom tools
# ---------------------------------------------------------------------------

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
def calculator(expression: str) -> str:
    """Evaluate a simple arithmetic expression and return the result.

    Supports +, -, *, /, ** and parentheses. Do NOT use for general code execution.

    Args:
        expression: A safe arithmetic expression, e.g. '(3 + 4) * 2'.

    Returns:
        The result as a string, or an error message if evaluation fails.
    """
    allowed = set("0123456789+-*/()., **")
    if not all(c in allowed for c in expression.replace(" ", "")):
        return "Error: expression contains disallowed characters."
    try:
        result = eval(expression, {"__builtins__": {}})  # noqa: S307 — guarded above
        return str(result)
    except Exception as exc:
        return f"Error: {exc}"


@tool
def send_email(recipient: str, subject: str, body: str) -> str:
    """Send an email to a recipient.

    IMPORTANT: You MUST call handoff_to_user first to get explicit human approval
    before calling this tool. Never call send_email without prior approval.

    Args:
        recipient: Email address to send to.
        subject:   Email subject line.
        body:      Email body text.

    Returns:
        A status string confirming the send.
    """
    # In a real app, this is where you'd call your email API.
    return f"sent to {recipient} (subject: {subject!r})"


# ---------------------------------------------------------------------------
# Custom callback handler
# ---------------------------------------------------------------------------

class StreamingCLIHandler:
    """Streams tokens to stdout; prints a header line when a tool is called."""

    _in_tool: bool = False
    _tool_count: int = 0

    def __call__(self, **kwargs):
        data = kwargs.get("data", "")
        complete = kwargs.get("complete", False)
        event = kwargs.get("event", {})

        tool_start = (
            event.get("contentBlockStart", {})
            .get("start", {})
            .get("toolUse")
        )
        tool_done = event.get("contentBlockStop") and self._in_tool

        if tool_start:
            self._tool_count += 1
            self._in_tool = True
            tool_name = tool_start.get("name", "unknown")
            print(f"\n[tool #{self._tool_count}: {tool_name}]", flush=True)
            return

        if tool_done:
            self._in_tool = False
            print()  # newline after tool block
            return

        if data:
            print(data, end="", flush=True)

        if complete and data:
            print("\n")


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

streaming_handler = StreamingCLIHandler()

agent = Agent(
    model=model,
    system_prompt=(
        "You are a helpful assistant with these tools: word_count, calculator, "
        "current_time, handoff_to_user, and send_email.\n\n"
        "Use word_count, calculator, and current_time freely whenever they help.\n\n"
        "For send_email you MUST follow this two-step protocol:\n"
        "  1. Call handoff_to_user with the full email draft (recipient, subject, body) "
        "and ask the user to approve or cancel.\n"
        "  2. Only call send_email if the user approves. If they cancel, do NOT retry."
    ),
    tools=[word_count, calculator, current_time, handoff_to_user, send_email],
    callback_handler=streaming_handler,
)


# ---------------------------------------------------------------------------
# CLI chat loop
# ---------------------------------------------------------------------------

def main():
    print("Strands streaming chat — type 'quit' or press Ctrl-C to exit.\n")
    while True:
        try:
            user_input = input("\nYou: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            sys.exit(0)

        if not user_input:
            continue
        if user_input.lower() in {"quit", "exit"}:
            print("Goodbye!")
            sys.exit(0)

        print("Assistant: ", end="", flush=True)
        agent(user_input)


if __name__ == "__main__":
    main()
