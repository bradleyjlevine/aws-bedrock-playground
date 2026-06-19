"""
Hello World: Strands MCP Tools — local + remote MCP tool sync
Runs a tiny local MCP server in stdio mode, optionally connects to a remote MCP
server, syncs their tools, and gives them to one Strands agent alongside native
Strands tools.

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python 17_strands_mcp_repo_tools_agent.py
Server:  uv run python 17_strands_mcp_repo_tools_agent.py --server

Optional remote MCP:
  REMOTE_MCP_URL=http://localhost:8000/mcp uv run python 17_strands_mcp_repo_tools_agent.py
  REMOTE_MCP_URL=http://localhost:8000/sse REMOTE_MCP_TRANSPORT=sse uv run python 17_strands_mcp_repo_tools_agent.py
"""
import os
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path

import boto3
from mcp import StdioServerParameters, stdio_client
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import FastMCP
from strands import Agent, tool
from strands.models import BedrockModel
from strands.tools.mcp import MCPClient
from strands_tools import current_time

REGION = "us-east-1"
MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
ROOT = Path(__file__).resolve().parent
REMOTE_MCP_URL = os.environ.get("REMOTE_MCP_URL", "").strip()
REMOTE_MCP_TRANSPORT = os.environ.get("REMOTE_MCP_TRANSPORT", "streamable-http").strip()


def run_server() -> None:
    mcp = FastMCP("aws-bedrock-playground-repo")

    @mcp.tool()
    def repo_search(pattern: str) -> str:
        """Search this repository with ripgrep and return matching lines."""
        result = subprocess.run(
            ["rg", "-n", "--", pattern, str(ROOT)],
            check=False,
            text=True,
            capture_output=True,
            timeout=10,
        )
        output = result.stdout or result.stderr or "No matches."
        return output[:12_000]

    @mcp.tool()
    def read_repo_file(relative_path: str) -> str:
        """Read a UTF-8 text file from this repository."""
        path = (ROOT / relative_path).resolve()
        if ROOT not in path.parents and path != ROOT:
            return "Error: path must stay inside the repository."
        if not path.is_file():
            return "Error: file not found."
        return path.read_text(errors="replace")[:20_000]

    mcp.run()


@tool
def word_count(text: str) -> int:
    """Count words in text.

    Args:
        text: Text to count.

    Returns:
        Number of whitespace-delimited words.
    """
    return len(text.split())


def make_agent(tools) -> Agent:
    profile = os.environ.get("AWS_PROFILE")
    session = boto3.Session(profile_name=profile, region_name=REGION)
    model = BedrockModel(model_id=MODEL_ID, boto_session=session)
    return Agent(
        model=model,
        system_prompt=(
            "You are a repo-aware assistant with native tools and MCP tools. "
            "Use current_time and word_count when useful. Use local MCP repo_search "
            "and read_repo_file to answer questions from source. If remote MCP tools "
            "are present, use them when they are better suited than local repo tools. "
            "Mention which tool family you used: native, local MCP, or remote MCP."
        ),
        tools=tools,
        callback_handler=None,
    )


def make_local_mcp_client() -> MCPClient:
    return MCPClient(
        lambda: stdio_client(
            StdioServerParameters(
                command="uv",
                args=["run", "python", str(Path(__file__).name), "--server"],
                cwd=str(ROOT),
            )
        )
    )


def make_remote_mcp_client(url: str, transport: str) -> MCPClient:
    if transport == "sse":
        return MCPClient(lambda: sse_client(url))
    if transport in {"streamable-http", "http"}:
        return MCPClient(lambda: streamable_http_client(url))
    raise ValueError("REMOTE_MCP_TRANSPORT must be 'streamable-http' or 'sse'.")


def main() -> None:
    if "--server" in sys.argv:
        run_server()
        return

    native_tools = [current_time, word_count]
    clients: list[tuple[str, MCPClient]] = [("local MCP", make_local_mcp_client())]
    if REMOTE_MCP_URL:
        clients.append(
            (
                f"remote MCP ({REMOTE_MCP_TRANSPORT}: {REMOTE_MCP_URL})",
                make_remote_mcp_client(REMOTE_MCP_URL, REMOTE_MCP_TRANSPORT),
            )
        )

    synced_tools = list(native_tools)
    tool_counts = {"native": len(native_tools)}

    with ExitStack() as stack:
        for label, client in clients:
            stack.enter_context(client)
            tools = client.list_tools_sync()
            synced_tools.extend(tools)
            tool_counts[label] = len(tools)

        agent = make_agent(synced_tools)
        response = agent(
            "Which examples in this repo demonstrate Strands agents, and what "
            "distinct feature does each one show? Also tell me how many tools you "
            "had available from each tool family."
        )
        print("Synced tool counts:")
        for label, count in tool_counts.items():
            print(f"- {label}: {count}")
        print("\nAgent response:\n")
        print(response)


if __name__ == "__main__":
    main()
