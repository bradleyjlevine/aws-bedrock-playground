#!/usr/bin/env python3
"""Local validation checks that do not call AWS services."""

from __future__ import annotations

import compileall
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_SOURCES = [
    "auth.py",
    "arithmetic_utils.py",
    "cyber_source_utils.py",
    "cyber_vuln_utils.py",
    "logging_utils.py",
    "pdf_utils.py",
    "webui_markdown.py",
    "examples",
]


def run_step(name: str, func) -> None:
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


def check_webui_markdown() -> None:
    script = ROOT / "scripts" / "check_webui_markdown.js"
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


def main() -> None:
    run_step("compile Python source", compile_sources)
    run_step("safe arithmetic helper", check_arithmetic_helper)
    run_step("WebUI Markdown renderer", check_webui_markdown)
    print("[check] all checks passed")


if __name__ == "__main__":
    main()
