# AWS Bedrock Playground

Hello-world examples for the main AWS Bedrock surfaces, including OpenAI GPT-5.5 and Codex (launched June 1, 2026).

## Files

| File | Model | API / Path | Notes |
|------|-------|-----------|-------|
| `01_bedrock_converse_foundation_model.py` | Claude Haiku 4.5 | Converse API · `bedrock-runtime` | Recommended for most use cases |
| `02_bedrock_invoke_agent.py` | _(your agent)_ | InvokeAgent · `bedrock-agent-runtime` | Requires a pre-created agent |
| `03_mantle_anthropic_messages.py` | Claude Haiku 4.5 | Anthropic Messages API · `bedrock-mantle` | Uses `anthropic[bedrock]` SDK |
| `04_mantle_openai_responses_oss.py` | GPT OSS 120B | OpenAI Responses API · `bedrock-mantle /v1` | OSS/Nova models use `/v1` path |
| `05_mantle_gpt55_codex.py` | GPT-5.5 | OpenAI Responses API · `bedrock-mantle /openai/v1` | Codex coding agent |
| `06_strands_bedrock_guardrail_agent.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | Single agent with Bedrock guardrail |
| `07_strands_multiagent_rss_briefing.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | Multi-agent: fetcher + time + orchestrator summarising Krebs feed |
| `08_strands_custom_tools.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | Custom tools with `@tool` decorator |
| `09_strands_file_session_history.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | Persistent conversation with `FileSessionManager` + `current_time` |
| `10_strands_swarm_handoff.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | Swarm: autonomous agent handoff (triage → specialist) |
| `11_strands_streaming_cli_hitl.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | Streaming CLI chat + `current_time` + HITL via `handoff_to_user` |
| `12_strands_webui_sse_hitl.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | FastAPI + SSE browser chat + `current_time` + HITL approval card |
| `13_mantle_gpt55_cybersec_webui.py` | GPT-5.5 / GPT-5.4 | OpenAI Responses API · `bedrock-mantle /openai/v1` | FastAPI + SSE summary UI using `AsyncBedrockOpenAI` |
| `14_strands_cybersec_triage_graph.py` | Claude Haiku 4.5 | Strands Graph · `bedrock-runtime` | Multi-agent cyber triage graph for PDF or URL inputs |
| `15_strands_structured_cybersec_brief.py` | Claude Haiku 4.5 | Strands structured output · `bedrock-runtime` | Validated Pydantic cyber briefing object from PDF or URL inputs |
| `16_strands_local_memory_advisor.py` | Claude Haiku 4.5 | Strands tools · `bedrock-runtime` | Local durable memory tools for briefing preferences |
| `17_strands_mcp_repo_tools_agent.py` | Claude Haiku 4.5 | Strands MCP · `bedrock-runtime` | Native tools + local stdio MCP + optional remote MCP tools in one agent |
| `18_nova_sonic_voice_incident_briefing.py` | Nova Sonic | Strands bidirectional streaming · `bedrock-runtime` | Voice incident briefing assistant |
| `19_strands_docker_sandbox_code_triage.py` | Claude Haiku 4.5 | Strands DockerSandbox · `bedrock-runtime` | Static Python snippet triage through a Docker sandbox |
| `20_strands_workflow_research_report.py` | Claude Haiku 4.5 | Strands workflow tool · `bedrock-runtime` | Dependent cyber research workflow with task status |
| `21_strands_mantle_anthropic_adapter.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-mantle /anthropic` | Custom Strands model adapter using `AsyncAnthropicBedrockMantle` |
| `22_strands_mantle_openai_gpt54.py` | GPT-5.4 | Strands SDK · `bedrock-mantle /openai/v1` | Custom Strands `OpenAIResponsesModel` adapter for GPT-5.4 |
| `23_strands_rss_exa_swarm.py` | Configured Bedrock model | Strands Swarm · `bedrock-runtime` + Exa MCP | RSS swarm that filters recent feed items, fetches article pages, and can use web search for detail |
| `24_pdf_to_unstructured_elements.py` | Local only | Unstructured OSS · `partition_pdf` | Shows PDF elements as JSONL with type, text, and metadata |
| `25_pdf_elements_to_prompt_chunks.py` | Local only | Unstructured OSS · `partition_pdf` | Converts PDF elements into source-attributed prompt chunks for AI models |

## Setup

```bash
uv sync
```

### Unstructured system dependencies

Files `13`-`15` and `24`-`25` use Unstructured for PDF extraction and document
partitioning. For maximum compatibility, install the native tools Unstructured
relies on for file detection, PDFs, OCR, Office documents, and other document
formats:

- [`libmagic-dev`](https://man7.org/linux/man-pages/man3/libmagic.3.html) for filetype detection
- [`poppler-utils`](https://poppler.freedesktop.org/), [`tesseract-ocr`](https://github.com/tesseract-ocr/tesseract), and `tesseract-lang` for images and PDFs
- [`libreoffice`](https://www.libreoffice.org/discover/libreoffice/) for Microsoft Office documents
- [`pandoc`](https://pandoc.org/) for `.epub`, `.odt`, and `.rtf` files

On macOS:

```bash
brew install \
  libmagic \
  poppler \
  tesseract \
  libreoffice \
  pandoc
```

## Authentication

None of these examples use long-lived API keys. Everything authenticates via your existing AWS identity — SSO session tokens, instance profiles, or the standard credential chain — so there is nothing to rotate or embed in code.

### How it works per SDK

The three SDKs in this repo each need credentials in a slightly different form:

**boto3 / Strands BedrockModel** (files 01, 02, 06–12, 14–20, 23) — native SSO/profile support built in:
```python
session = boto3.Session(profile_name=os.environ.get("AWS_PROFILE"))
```
boto3 resolves the profile, refreshes SSO tokens automatically when they expire, and handles SigV4 signing on every request.

**`anthropic[bedrock]`** (files 03, 21) — the Anthropic SDK has first-class Bedrock support, accepting a profile name directly:
```python
client = AnthropicBedrock(aws_profile=os.environ.get("AWS_PROFILE"))
```
It creates its own boto3 session under the hood, so SSO refresh works the same way. File 21 reuses Strands' `AnthropicModel` request/tool formatting and swaps its client to `AsyncAnthropicBedrockMantle`.

**`openai`** (files 04, 05, 13) — the GPT-5.5/5.4 examples use the SDK's `BedrockOpenAI` / `AsyncBedrockOpenAI` clients with refreshable token providers. The OSS example in file 04 still uses `OpenAI(base_url=...)` because those models use the plain `/v1` Mantle path. `auth.py` bridges named profiles / SSO into both patterns without any long-lived key:
```python
# auth.py
session = boto3.Session(profile_name=AWS_PROFILE)
provider = BotoSessionCredentialsProvider(session)   # adapts boto3 → botocore CredentialProvider
token = provide_token(region=region, aws_credentials_provider=provider)

# caller
client = BedrockOpenAI(
    aws_region="us-east-2",
    bedrock_token_provider=lambda: get_mantle_token("us-east-2"),
)
```
`aws-bedrock-token-generator` calls the Bedrock token endpoint using your live SigV4 credentials and returns a short-lived bearer token. `BotoSessionCredentialsProvider` is a thin adapter that lets the token generator consume a boto3 session directly, so SSO profiles and instance roles work without any extra config.
File 22 uses the same token helper through Strands' `OpenAIResponsesModel`, but points the OpenAI client at `/openai/v1` because GPT-5.4 and GPT-5.5 are not served from Mantle's plain `/v1` path.

The result: every request is signed by your current AWS identity. Tokens expire and are minted fresh per run; nothing is stored on disk.

### Quickstart

```bash
aws sso login --profile my-sso-profile
export AWS_PROFILE=my-sso-profile
uv run python 01_bedrock_converse_foundation_model.py
```

Leave `AWS_PROFILE` unset to fall back to the default credential chain (`~/.aws/credentials`, instance profile, `AWS_*` environment variables).

### IAM permissions required

| Endpoint | IAM action needed |
|----------|------------------|
| `bedrock-runtime` | `bedrock:InvokeModel`, `bedrock:Converse` |
| `bedrock-agent-runtime` | `bedrock:InvokeAgent` |
| `bedrock-mantle` | `bedrock-mantle:CreateInference` |

> **Note:** `bedrock-mantle:CreateInference` is a separate IAM action from standard Bedrock permissions — ensure your role has it before using files 03–05, 13, 21, or 22.

## bedrock-mantle path routing

The mantle endpoint uses two different base paths depending on the model:

| Path | Models |
|------|--------|
| `https://bedrock-mantle.{region}.api.aws/v1` | OSS models (`openai.gpt-oss-*`), Amazon Nova, and others |
| `https://bedrock-mantle.{region}.api.aws/openai/v1` | GPT-5.5 and GPT-5.4 only |
| `https://bedrock-mantle.{region}.api.aws/anthropic` | Claude models (used by `anthropic` SDK internally) |

## Key facts

- **GPT-5.5 / GPT-5.4** (`openai.gpt-5.5`, `openai.gpt-5.4`) — use Bedrock Mantle in `us-east-2`. Supports **Responses API only** (not Chat Completions).
- **Codex** — OpenAI's coding agent powered by GPT-5.5. Same Responses API, also configurable via Codex CLI/App/VS Code with `model-provider = "amazon-bedrock"` in `~/.codex/config.toml`.
- **bedrock-mantle** — AWS's newer inference engine (Project Mantle). Supports OpenAI Responses API and Anthropic Messages API. Recommended for new projects using these SDKs.
- **bedrock-runtime** — Original Bedrock engine. Supports Converse and InvokeModel APIs. All models available here.
- For `02_bedrock_invoke_agent.py`, create an agent in the Bedrock console first and fill in `AGENT_ID` / `ALIAS_ID`.
- For `06_strands_bedrock_guardrail_agent.py`, create a guardrail in the Bedrock console first, then set `BEDROCK_GUARDRAIL_ID` and optionally `BEDROCK_GUARDRAIL_VERSION` (defaults to `DRAFT`).
- `07_strands_multiagent_rss_briefing.py` runs three agents: `time_agent` (current_time tool), `fetcher_agent` (rss tool), and an orchestrator that calls both and writes a formatted security briefing. No extra config needed — just run it.
- `08_strands_custom_tools.py` shows the `@tool` decorator: define a Python function with a docstring, and Strands generates the Bedrock tool spec automatically.
- `09_strands_file_session_history.py` shows `FileSessionManager`: session files are written to `./sessions/`. Re-run the script and the agent picks up the previous conversation. Includes `current_time`.
- `10_strands_swarm_handoff.py` shows the `Swarm` class: a triage agent classifies each question and hands off to the right specialist. Strands injects a `handoff_to_agent` tool into every agent in the swarm automatically.
- `11_strands_streaming_cli_hitl.py` runs an interactive CLI chat loop. Includes `current_time` and a `send_email` tool gated behind `handoff_to_user` — the agent pauses and asks for approval; `send_email` only executes after the user confirms. Type `quit` to exit.
- `12_strands_webui_sse_hitl.py` runs a FastAPI server on `http://localhost:8000` with a single-page chat UI. Includes `current_time`. Tokens stream over SSE; `send_email` triggers a Strands `BeforeToolCallEvent` interrupt, the browser shows an Approve / Deny card with the drafted email, and the agent only resumes after the user clicks. Try: *"Email alex@example.com saying the deploy is done."* or *"What time is it?"*
- `13_mantle_gpt55_cybersec_webui.py` runs a FastAPI server on `http://localhost:8001`. Upload a PDF or enter a URL; PDF text is extracted locally with Unstructured (`partition_pdf`) and summarized with GPT-5.5, falling back to GPT-5.4 for known intermittent Mantle failures.
- `14_strands_cybersec_triage_graph.py` demonstrates Strands `GraphBuilder`: triage, IOC extraction, defensive planning, and final briefing nodes run as a deterministic cyber-analysis graph over a PDF or URL. PDF text extraction uses shared Unstructured helpers, and the IOC extractor can call Shodan CVEDB's `/cve/{cve_id}` and `/euvd/{euvd_id}` endpoints to enrich vulnerabilities with CVSS, EPSS, KEV status, references, affected CPEs/products, and linked CVE data.
- `15_strands_structured_cybersec_brief.py` demonstrates Strands structured output with Pydantic. It returns a validated cyber brief object with severity, confidence, indicators, recommended actions, and open questions, uses the same Unstructured PDF extraction helper, and includes the same CVEDB lookup tools for CVE/EUVD enrichment.
- `16_strands_local_memory_advisor.py` demonstrates durable memory as explicit Strands tools backed by `./sessions/security_memory.json`. The installed Strands SDK does not expose the newer `MemoryManager` constructor surface, so this example keeps memory local and transparent.
- `17_strands_mcp_repo_tools_agent.py` demonstrates syncing multiple tool families into one agent: native Strands tools, a local stdio MCP repo server, and optional remote MCP tools.
- `18_nova_sonic_voice_incident_briefing.py` demonstrates experimental bidirectional streaming with Amazon Nova Sonic. It requires Python 3.12+, microphone/speaker access, and optional audio dependencies.
- `19_strands_docker_sandbox_code_triage.py` demonstrates Strands `DockerSandbox` by statically inventorying a Python snippet inside a running container. It does not execute the suspicious script.
- `20_strands_workflow_research_report.py` demonstrates the Strands community `workflow` tool with dependent cyber-research tasks and status reporting.
- `21_strands_mantle_anthropic_adapter.py` demonstrates a small custom Strands model adapter for Bedrock Mantle's Anthropic Messages API. It keeps Strands tools/agent behavior while sending inference through `https://bedrock-mantle.{region}.api.aws/anthropic`.
- `22_strands_mantle_openai_gpt54.py` demonstrates Strands with GPT-5.4 over Bedrock Mantle's `/openai/v1` Responses API path. It keeps Strands' OpenAI Responses formatting and refreshes the Bedrock bearer token per request.
- `23_strands_rss_exa_swarm.py` demonstrates a Strands `Swarm` for RSS briefings. A feed collector uses the `rss` tool, an article researcher fetches selected source pages and can use Exa remote MCP web-search tools via `EXA_API_KEY`, and a briefing writer summarizes items from the last 14 days by default.
- `24_pdf_to_unstructured_elements.py` demonstrates the first transformation step for document AI: Unstructured partitions a PDF into typed elements such as titles, narrative text, and tables, then prints JSONL rows with source metadata.
- `25_pdf_elements_to_prompt_chunks.py` demonstrates the second transformation step: those elements are grouped into bounded prompt chunks that keep filename, page, element type, and element index metadata beside the text.

## Run examples

Most examples run directly once AWS auth is set:

```bash
uv run python 07_strands_multiagent_rss_briefing.py
uv run python 14_strands_cybersec_triage_graph.py --url https://example.com/report
uv run python 14_strands_cybersec_triage_graph.py --pdf ./report-a.pdf --pdf ./report-b.pdf --url https://example.com/advisory
uv run python 14_strands_cybersec_triage_graph.py --html ./saved-page.html
uv run python 15_strands_structured_cybersec_brief.py --pdf ./report.pdf
uv run python 15_strands_structured_cybersec_brief.py --pdf ./report-a.pdf --text ./notes.md --url https://example.com/advisory
uv run python 15_strands_structured_cybersec_brief.py --text ./article.md
uv run python 23_strands_rss_exa_swarm.py
EXA_API_KEY=... uv run python 23_strands_rss_exa_swarm.py
uv run python 23_strands_rss_exa_swarm.py --feed https://example.com/feed.xml --days 14
uv run python 24_pdf_to_unstructured_elements.py ./report.pdf --pretty --max-elements 20
uv run python 25_pdf_elements_to_prompt_chunks.py ./report.pdf --question "Summarize the key risks."
```

Some publisher sites return HTTP 403 to automated requests even with browser-like headers. For those, open the page in your browser, save it as HTML or PDF, then pass `--html` / `--pdf` to files `14` or `15`. In the web UI (`13`), upload a saved PDF.

Web examples:

```bash
uv run python 12_strands_webui_sse_hitl.py        # http://localhost:8000
uv run python 13_mantle_gpt55_cybersec_webui.py     # http://localhost:8001
```

MCP example:

```bash
uv run python 17_strands_mcp_repo_tools_agent.py
REMOTE_MCP_URL=http://localhost:8000/mcp uv run python 17_strands_mcp_repo_tools_agent.py
REMOTE_MCP_URL=http://localhost:8000/sse REMOTE_MCP_TRANSPORT=sse uv run python 17_strands_mcp_repo_tools_agent.py
```

Sandbox example:

```bash
docker run --rm -it --name strands-cybersec-sandbox python:3.12-slim sleep infinity
uv run python 19_strands_docker_sandbox_code_triage.py
```

Voice example:

```bash
uv add "strands-agents[bidi]"
uv run python 18_nova_sonic_voice_incident_briefing.py
```

Nova Sonic is available in `us-east-1`, `eu-north-1`, and `ap-northeast-1`. On macOS, PyAudio may also require PortAudio system headers.
