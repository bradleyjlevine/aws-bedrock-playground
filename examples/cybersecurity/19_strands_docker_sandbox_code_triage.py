"""
Hello World: Strands + DockerSandbox — bounded code/log analysis
Lets an agent inspect suspicious Python snippets through a controlled Docker sandbox.

Strands DockerSandbox attaches to an already-running container. Start one first:
  docker run --rm -it --name strands-cybersec-sandbox python:3.12-slim sleep infinity

Then run:
  uv run python examples/cybersecurity/19_strands_docker_sandbox_code_triage.py

Set STRANDS_SANDBOX_CONTAINER to use a different running container name.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)
import asyncio
import os
import subprocess
import textwrap

import boto3
from strands import Agent, tool
from strands.models import BedrockModel
from strands.sandbox.docker import DockerSandbox

REGION = "us-east-1"
MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
)
CONTAINER = os.environ.get("STRANDS_SANDBOX_CONTAINER", "strands-cybersec-sandbox")


def _container_running() -> bool:
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER],
        check=False,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip() == "true"


async def _run_in_sandbox(source: str) -> str:
    sandbox = DockerSandbox(CONTAINER, working_dir="/tmp")
    path = "/tmp/suspicious.py"
    await sandbox.write_text(path, source)
    compile_result = await sandbox.execute(f"python -m py_compile {path}")
    ast_result = await sandbox.execute(
        "python - <<'PY'\n"
        "import ast, pathlib\n"
        f"tree = ast.parse(pathlib.Path({path!r}).read_text())\n"
        "calls = []\n"
        "imports = []\n"
        "for node in ast.walk(tree):\n"
        "    if isinstance(node, ast.Import):\n"
        "        imports.extend(alias.name for alias in node.names)\n"
        "    elif isinstance(node, ast.ImportFrom):\n"
        "        imports.append(node.module or '')\n"
        "    elif isinstance(node, ast.Call):\n"
        "        name = getattr(node.func, 'id', None) or getattr(node.func, 'attr', None)\n"
        "        if name:\n"
        "            calls.append(name)\n"
        "print({'imports': sorted(set(imports)), 'calls': sorted(set(calls))})\n"
        "PY"
    )
    return (
        f"py_compile exit={compile_result.exit_code}\n{compile_result.stderr}\n"
        f"ast inventory exit={ast_result.exit_code}\n{ast_result.stdout}{ast_result.stderr}"
    )


@tool
def sandbox_python_inventory(source: str) -> str:
    """Inspect Python source in a Docker sandbox without executing the script.

    Args:
        source: Python source code to compile and statically inventory.

    Returns:
        Compile status plus imported modules and called function names.
    """
    return asyncio.run(_run_in_sandbox(source))


def make_agent() -> Agent:
    profile = os.environ.get("AWS_PROFILE")
    session = boto3.Session(profile_name=profile, region_name=REGION)
    model = BedrockModel(model_id=MODEL_ID, boto_session=session)
    return Agent(
        model=model,
        system_prompt=(
            "You are a malware triage assistant. Use sandbox_python_inventory before "
            "making claims about code. Do not ask the sandbox to execute suspicious code; "
            "static compile and inventory only. Explain risk and next safe steps."
        ),
        tools=[sandbox_python_inventory],
        callback_handler=None,
    )


def main() -> None:
    if not _container_running():
        print(
            f"Container {CONTAINER!r} is not running.\n"
            "Start it with:\n"
            "docker run --rm -it --name strands-cybersec-sandbox "
            "python:3.12-slim sleep infinity"
        )
        return

    sample = textwrap.dedent(
        """
        import base64
        import os
        import subprocess

        payload = base64.b64decode("cHJpbnQoJ2hlbGxvJyk=")
        subprocess.run(["python", "-c", payload.decode()])
        os.remove("/tmp/audit.log")
        """
    ).strip()
    print(make_agent()(f"Assess this Python snippet for security risk:\n\n```python\n{sample}\n```"))


if __name__ == "__main__":
    main()
