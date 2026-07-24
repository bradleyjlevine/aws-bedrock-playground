#!/usr/bin/env python3
"""Local validation checks that do not call AWS services."""

from __future__ import annotations

import compileall
import subprocess
import sys
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
PYTHON_SOURCES = [
    "auth.py",
    "arithmetic_utils.py",
    "cyber_source_utils.py",
    "cyber_vuln_utils.py",
    "logging_utils.py",
    "pdf_utils.py",
    "webui_interactions.py",
    "webui_markdown.py",
    "webui_theme.py",
    "examples",
]


def run_step(name: str, func: Callable[[], None]) -> None:
    print(f"[check] {name}...")
    func()


def compile_sources() -> None:
    paths = [str(ROOT / path) for path in PYTHON_SOURCES]
    if not compileall.compile_file(str(ROOT / "arithmetic_utils.py"), quiet=1):
        raise SystemExit("arithmetic_utils.py failed to compile")
    if not compileall.compile_dir(str(ROOT / "examples"), quiet=1):
        raise SystemExit("examples failed to compile")
    for path in paths:
        source = Path(path)
        if source.is_file() and source.name != "arithmetic_utils.py":
            if not compileall.compile_file(str(source), quiet=1):
                raise SystemExit(f"{source.relative_to(ROOT)} failed to compile")


def check_arithmetic_helper() -> None:
    sys.path.insert(0, str(ROOT))
    from arithmetic_utils import evaluate_arithmetic_expression

    assert evaluate_arithmetic_expression("(3 + 4) * 2") == 14
    assert evaluate_arithmetic_expression("-2 ** 3") == -8
    try:
        evaluate_arithmetic_expression('__import__("os").system("id")')
    except Exception:
        return
    raise SystemExit("arithmetic helper accepted code-shaped input")


def check_webui_assets() -> None:
    for filename in (
        "check_webui_markdown.js",
        "check_webui_interactions.js",
        "check_webui_theme.js",
    ):
        script = ROOT / "scripts" / filename
        result = subprocess.run(
            ["node", str(script)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        if result.returncode != 0:
            raise SystemExit(result.returncode)


def check_repository_conventions() -> None:
    """Catch documentation drift and accidental forks of shared WebUI code."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    examples = sorted((ROOT / "examples").rglob("*.py"))
    missing = [
        str(path.relative_to(ROOT))
        for path in examples
        if str(path.relative_to(ROOT)) not in readme
        or str(path.relative_to(ROOT)) not in agents
    ]
    if missing:
        raise SystemExit(
            "Example paths missing from README.md or AGENTS.md: " + ", ".join(missing)
        )

    webui_examples = [
        ROOT / "examples/agents/12_strands_webui_sse_hitl.py",
        ROOT / "examples/cybersecurity/13_mantle_gpt55_cybersec_webui.py",
        ROOT / "examples/cybersecurity/26_strands_elastic_waf_mcp_webui.py",
        ROOT / "examples/cybersecurity/29_strands_threat_intel_risk_chat.py",
        ROOT / "examples/agents/30_strands_remote_mcp_teaching_agent.py",
    ]
    for path in webui_examples:
        source = path.read_text(encoding="utf-8")
        if "MARKDOWN_RENDERER_JS" not in source:
            raise SystemExit(f"{path.relative_to(ROOT)} does not use shared Markdown rendering")
        if "WEBUI_INTERACTIONS_JS" not in source:
            raise SystemExit(f"{path.relative_to(ROOT)} does not use shared WebUI interactions")
        if "WEBUI_THEME_CSS" not in source:
            raise SystemExit(f"{path.relative_to(ROOT)} does not use the shared WebUI theme")
        if "function renderMarkdown(" in source:
            raise SystemExit(f"{path.relative_to(ROOT)} forks renderMarkdown()")
        if 'buffer.split("\\\\n\\\\n")' in source:
            raise SystemExit(f"{path.relative_to(ROOT)} forks SSE frame parsing")


def check_python_quality() -> None:
    for command in (
        [sys.executable, "-m", "pytest", "-q"],
        [sys.executable, "-m", "ruff", "check", "."],
    ):
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode != 0:
            raise SystemExit(result.returncode)


def main() -> None:
    run_step("compile Python source", compile_sources)
    run_step("safe arithmetic helper", check_arithmetic_helper)
    run_step("shared WebUI assets", check_webui_assets)
    run_step("repository conventions", check_repository_conventions)
    run_step("Python tests and lint", check_python_quality)
    print("[check] all checks passed")


if __name__ == "__main__":
    main()
