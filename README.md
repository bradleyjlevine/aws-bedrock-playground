# AWS Bedrock Playground

Hello-world examples for the main AWS Bedrock surfaces: Bedrock Runtime, Bedrock Agents, Bedrock Mantle, Strands Agents, MCP tools, document extraction, and voice streaming.

## Key concepts shown

| Concept | Examples | What to look for |
|---------|----------|------------------|
| Bedrock Runtime vs Bedrock Mantle | `01`, `03`-`05`, `13`, `21`, `22` | Runtime uses native Bedrock APIs such as Converse / InvokeModel. Mantle exposes OpenAI-compatible and Anthropic-compatible SDK paths with Bedrock bearer tokens. |
| OpenAI-compatible Bedrock calls | `04`, `05`, `13`, `22` | OSS models use Mantle `/v1`; GPT-5.5 / GPT-5.4 use Mantle `/openai/v1` and the Responses API. |
| Strands agents | `06`-`12`, `14`-`23`, `26`-`29` | Single agents, multi-agent orchestration, graph workflows, swarms, memory, structured output, and custom model adapters. |
| Tools | `08`, `11`, `12`, `16`, `17`, `23`, `26`-`29` | Native Strands tools, `@tool` decorators, community tools such as `current_time` / `rss`, durable local-memory tools, and externally hosted tools. |
| MCP (Model Context Protocol) | `17`, `23`, `26` | Local stdio MCP tools, remote MCP tools, Exa MCP web search, and Elastic Agent Builder MCP tools for searching WAF logs. |
| HITL (Human in the Loop) | `11`, `12` | CLI approval with `handoff_to_user` and browser approval with Strands interrupts before a sensitive `send_email` tool runs. |
| Streaming UI / SSE | `12`, `13`, `26`, `29` | Browser apps that stream tokens and status updates with FastAPI and Server-Sent Events. |
| Document extraction / RAG prep | `13`-`15`, `24`, `25`, `26`, `29` | Unstructured PDF extraction, element-level JSONL, source-attributed prompt chunks, and PDF/URL threat-report context. |
| Cyber detection / policy review | `26`-`29` | WAF log investigation, detection engineering, IAM least-privilege review, threat-intel mapping, and risk analysis. |
| Guardrails and safety controls | `06`, `11`, `12`, `19` | Bedrock guardrails, approval gates for sensitive actions, and DockerSandbox-based static code triage. |
| Voice / bidirectional streaming | `18` | Amazon Nova Sonic through Strands bidirectional streaming with microphone/speaker IO. |

## Files

| File | Model | API / Path | Notes |
|------|-------|-----------|-------|
| `examples/core/01_bedrock_converse_foundation_model.py` | Claude Haiku 4.5 | Converse API · `bedrock-runtime` | Recommended for most use cases |
| `examples/core/02_bedrock_invoke_agent.py` | _(your agent)_ | InvokeAgent · `bedrock-agent-runtime` | Requires a pre-created agent |
| `examples/mantle/03_mantle_anthropic_messages.py` | Claude Haiku 4.5 | Anthropic Messages API · `bedrock-mantle` | Uses `anthropic[bedrock]` SDK |
| `examples/mantle/04_mantle_openai_responses_oss.py` | GPT OSS 120B | OpenAI Responses API · `bedrock-mantle /v1` | OSS/Nova models use `/v1` path |
| `examples/mantle/05_mantle_gpt55_codex.py` | GPT-5.5 | OpenAI Responses API · `bedrock-mantle /openai/v1` | Codex coding agent |
| `examples/core/06_strands_bedrock_guardrail_agent.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | Single agent with Bedrock guardrail |
| `examples/agents/07_strands_multiagent_rss_briefing.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | Multi-agent: fetcher + time + orchestrator summarising Krebs feed |
| `examples/agents/08_strands_custom_tools.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | Custom tools with `@tool` decorator |
| `examples/agents/09_strands_file_session_history.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | Persistent conversation with `FileSessionManager` + `current_time` |
| `examples/agents/10_strands_swarm_handoff.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | Swarm: autonomous agent handoff (triage → specialist) |
| `examples/agents/11_strands_streaming_cli_hitl.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | Streaming CLI chat + `current_time` + HITL via `handoff_to_user` |
| `examples/agents/12_strands_webui_sse_hitl.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | FastAPI + SSE browser chat + `current_time` + HITL approval card |
| `examples/cybersecurity/13_mantle_gpt55_cybersec_webui.py` | GPT-5.5 / GPT-5.4 | OpenAI Responses API · `bedrock-mantle /openai/v1` | FastAPI + SSE summary UI using `AsyncBedrockOpenAI` |
| `examples/cybersecurity/14_strands_cybersec_triage_graph.py` | GPT OSS 120B | Strands Graph · `bedrock-runtime` | Multi-agent cyber triage graph for PDF, URL, HTML, or text inputs |
| `examples/cybersecurity/15_strands_structured_cybersec_brief.py` | GPT OSS 120B | Strands structured output · `bedrock-runtime` | Validated Pydantic cyber briefing object from PDF, URL, HTML, or text inputs |
| `examples/agents/16_strands_local_memory_advisor.py` | Claude Haiku 4.5 | Strands tools · `bedrock-runtime` | Local durable memory tools for briefing preferences |
| `examples/agents/17_strands_mcp_repo_tools_agent.py` | Claude Haiku 4.5 | Strands MCP · `bedrock-runtime` | Native tools + local stdio MCP + optional remote MCP tools in one agent |
| `examples/cybersecurity/18_nova_sonic_voice_incident_briefing.py` | Nova Sonic | Strands bidirectional streaming · `bedrock-runtime` | Voice incident briefing assistant |
| `examples/cybersecurity/19_strands_docker_sandbox_code_triage.py` | Claude Haiku 4.5 | Strands DockerSandbox · `bedrock-runtime` | Static Python snippet triage through a Docker sandbox |
| `examples/agents/20_strands_workflow_research_report.py` | Claude Haiku 4.5 | Strands workflow tool · `bedrock-runtime` | Dependent cyber research workflow with task status |
| `examples/mantle/21_strands_mantle_anthropic_adapter.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-mantle /anthropic` | Custom Strands model adapter using `AsyncAnthropicBedrockMantle` |
| `examples/mantle/22_strands_mantle_openai_gpt54.py` | GPT-5.4 | Strands SDK · `bedrock-mantle /openai/v1` | Custom Strands `OpenAIResponsesModel` adapter for GPT-5.4 |
| `examples/agents/23_strands_rss_exa_swarm.py` | Claude Sonnet 4.5 | Strands Swarm · `bedrock-runtime` + Exa MCP | RSS swarm that filters recent feed items, fetches article pages, and can use web search for detail |
| `examples/document-processing/24_pdf_to_unstructured_elements.py` | Local only | Unstructured OSS · `partition_pdf` | Shows PDF elements as JSONL with type, text, and metadata |
| `examples/document-processing/25_pdf_elements_to_prompt_chunks.py` | Local only | Unstructured OSS · `partition_pdf` | Converts PDF elements into source-attributed prompt chunks for AI models |
| `examples/cybersecurity/26_strands_elastic_waf_mcp_webui.py` | Claude Haiku 4.5 by default | Strands MCP · `bedrock-runtime` + Elastic Agent Builder MCP | FastAPI + SSE WAF investigation UI over Elastic Cloud logs; model can be overridden with `BEDROCK_MODEL_ID` |
| `examples/cybersecurity/27_strands_detection_engineering.py` | GPT OSS 120B | Strands structured output · `bedrock-runtime` | Turns JSONL/CSV security telemetry into findings, Sigma-style detections, ECS-aware Elastic hunts, and response actions using official SigmaHQ examples as references |
| `examples/cybersecurity/28_strands_iam_policy_risk_review.py` | GPT OSS 120B | Strands structured output · `bedrock-runtime` | Reviews IAM policy JSON for wildcard permissions, privilege-escalation paths, and least-privilege fixes |
| `examples/cybersecurity/29_strands_threat_intel_risk_chat.py` | Claude Haiku 4.5 | Strands SDK · `bedrock-runtime` | Interactive CLI or FastAPI/SSE WebUI threat-intel and risk chat with CVE/EUVD, CWE/CAPEC, paginated MITRE ATT&CK Enterprise and MITRE ATLAS tools, OWASP Top 10 2025/2021, cached Security Cards/Unified Kill Chain PDF references, FAIR Monte Carlo ALE, and ROSI tools |

## Setup

```bash
uv sync
```

### Unstructured system dependencies

Files `13`-`15`, `24`-`26`, and `29` use Unstructured for PDF extraction and document
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

**boto3 / Strands BedrockModel** (files 01, 02, 06–12, 14–20, 23, 26–28) — native SSO/profile support built in:
```python
session = boto3.Session(profile_name=os.environ.get("AWS_PROFILE"))
```
boto3 resolves the profile, refreshes SSO tokens automatically when they expire, and handles SigV4 signing on every request.

**`anthropic[bedrock]`** (files 03, 21) — the Anthropic SDK has first-class Bedrock support, accepting a profile name directly:
```python
client = AnthropicBedrock(aws_profile=os.environ.get("AWS_PROFILE"))
```
It creates its own boto3 session under the hood, so SSO refresh works the same way. File 21 reuses Strands' `AnthropicModel` request/tool formatting and swaps its client to `AsyncAnthropicBedrockMantle`.

**`openai`** (files 04, 05, 13, 22) — the GPT-5.5/5.4 examples use the SDK's `BedrockOpenAI` / `AsyncBedrockOpenAI` clients with refreshable token providers. The OSS example in file 04 still uses `OpenAI(base_url=...)` because those models use the plain `/v1` Mantle path. `auth.py` bridges named profiles / SSO into both patterns without any long-lived key:
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
uv run python examples/core/01_bedrock_converse_foundation_model.py
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
- **bedrock-runtime** — Original Bedrock engine. Supports Converse and InvokeModel APIs for Bedrock Runtime model IDs such as Claude, Nova, and GPT OSS (`openai.gpt-oss-120b-1:0`). GPT-5.5 / GPT-5.4 are Mantle-only in this repo.
- For `examples/core/02_bedrock_invoke_agent.py`, create an agent in the Bedrock console first and fill in `AGENT_ID` / `ALIAS_ID`.
- For `examples/core/06_strands_bedrock_guardrail_agent.py`, create a guardrail in the Bedrock console first, then set `BEDROCK_GUARDRAIL_ID` and optionally `BEDROCK_GUARDRAIL_VERSION` (defaults to `DRAFT`).
- `examples/agents/07_strands_multiagent_rss_briefing.py` runs three agents: `time_agent` (current_time tool), `fetcher_agent` (rss tool), and an orchestrator that calls both and writes a formatted security briefing. No extra config needed — just run it.
- `examples/agents/08_strands_custom_tools.py` shows the `@tool` decorator: define a Python function with a docstring, and Strands generates the Bedrock tool spec automatically.
- `examples/agents/09_strands_file_session_history.py` shows `FileSessionManager`: session files are written to `examples/agents/sessions/`. Re-run the script and the agent picks up the previous conversation. Includes `current_time`.
- `examples/agents/10_strands_swarm_handoff.py` shows the `Swarm` class: a triage agent classifies each question and hands off to the right specialist. Strands injects a `handoff_to_agent` tool into every agent in the swarm automatically.
- `examples/agents/11_strands_streaming_cli_hitl.py` runs an interactive CLI chat loop. Includes `current_time` and a `send_email` tool gated behind `handoff_to_user` — the agent pauses and asks for approval; `send_email` only executes after the user confirms. Type `quit` to exit.
- `examples/agents/12_strands_webui_sse_hitl.py` runs a FastAPI server on `http://localhost:8000` with a single-page chat UI. Includes `current_time`. Tokens stream over SSE; `send_email` triggers a Strands `BeforeToolCallEvent` interrupt, the browser shows an Approve / Deny card with the drafted email, and the agent only resumes after the user clicks. Try: *"Email alex@example.com saying the deploy is done."* or *"What time is it?"*
- `examples/cybersecurity/13_mantle_gpt55_cybersec_webui.py` runs a FastAPI server on `http://localhost:8001`. Upload a PDF or enter a URL; PDF text is extracted locally with Unstructured (`partition_pdf`) and summarized with GPT-5.5, falling back to GPT-5.4 for known intermittent Mantle failures.

  ![Example 13 GPT-5.5 cyber-security summary UI](media/2026-06-20_13-14-14_13_gpt_5_5_example.png)

- `examples/cybersecurity/14_strands_cybersec_triage_graph.py` demonstrates Strands `GraphBuilder` with GPT OSS 120B through Bedrock Runtime: triage, IOC extraction, defensive planning, and final briefing nodes run as a deterministic cyber-analysis graph over PDF, URL, saved HTML, or text inputs. PDF text extraction uses shared Unstructured helpers, and the IOC extractor can call Shodan CVEDB's `/cve/{cve_id}` and `/euvd/{euvd_id}` endpoints to enrich vulnerabilities with CVSS, EPSS, KEV status, references, affected CPEs/products, and linked CVE data.
- `examples/cybersecurity/15_strands_structured_cybersec_brief.py` demonstrates Strands structured output with GPT OSS 120B and Pydantic. It returns a validated cyber brief object with severity, confidence, indicators, recommended actions, and open questions, uses the same Unstructured PDF extraction helper, and includes the same CVEDB lookup tools for CVE/EUVD enrichment.
- `examples/agents/16_strands_local_memory_advisor.py` demonstrates durable memory as explicit Strands tools backed by `examples/agents/sessions/security_memory.json`. The installed Strands SDK does not expose the newer `MemoryManager` constructor surface, so this example keeps memory local and transparent.
- `examples/agents/17_strands_mcp_repo_tools_agent.py` demonstrates syncing multiple tool families into one agent: native Strands tools, a local stdio MCP repo server, and optional remote MCP tools.
- `examples/cybersecurity/18_nova_sonic_voice_incident_briefing.py` demonstrates experimental bidirectional streaming with Amazon Nova Sonic. It requires Python 3.12+, microphone/speaker access, and optional audio dependencies.
- `examples/cybersecurity/19_strands_docker_sandbox_code_triage.py` demonstrates Strands `DockerSandbox` by statically inventorying a Python snippet inside a running container. It does not execute the suspicious script.
- `examples/agents/20_strands_workflow_research_report.py` demonstrates the Strands community `workflow` tool with dependent cyber-research tasks and status reporting.
- `examples/mantle/21_strands_mantle_anthropic_adapter.py` demonstrates a small custom Strands model adapter for Bedrock Mantle's Anthropic Messages API. It keeps Strands tools/agent behavior while sending inference through `https://bedrock-mantle.{region}.api.aws/anthropic`.
- `examples/mantle/22_strands_mantle_openai_gpt54.py` demonstrates Strands with GPT-5.4 over Bedrock Mantle's `/openai/v1` Responses API path. It keeps Strands' OpenAI Responses formatting and refreshes the Bedrock bearer token per request.
- `examples/agents/23_strands_rss_exa_swarm.py` demonstrates a Strands `Swarm` for RSS briefings on Claude Sonnet 4.5. A feed collector uses the `rss` tool, an article researcher fetches selected source pages and can use Exa remote MCP web-search tools via `EXA_API_KEY`, and a briefing writer summarizes items from the last 14 days by default.
- `examples/document-processing/24_pdf_to_unstructured_elements.py` demonstrates the first transformation step for document AI: Unstructured partitions a PDF into typed elements such as titles, narrative text, and tables, then prints JSONL rows with source metadata.
- `examples/document-processing/25_pdf_elements_to_prompt_chunks.py` demonstrates the second transformation step: those elements are grouped into bounded prompt chunks that keep filename, page, element type, and element index metadata beside the text.
- `examples/cybersecurity/26_strands_elastic_waf_mcp_webui.py` runs a FastAPI server on `http://localhost:8002`. The browser UI accepts WAF / web-attack questions plus optional threat report PDFs or URLs, then a Strands agent uses AWS Bedrock and Elastic Agent Builder MCP tools to search Elastic Cloud logs. It shows simple investigation stages, renders the answer as Markdown, and hides detailed MCP/tool activity by default behind a **Show tool activity** toggle. AWS WAF logs are the default starting point for the demo, but the agent can discover and use related datasets when the question needs more context. Configure `ELASTIC_AGENT_BUILDER_MCP_URL` or `ELASTIC_KIBANA_URL`, plus `ELASTIC_API_KEY` or `ELASTIC_AUTH_HEADER`. Override `BEDROCK_MODEL_ID` for a different Bedrock Runtime model, or `ELASTIC_WAF_DATA_CONTEXT` if your WAF index names or field conventions differ.

  ![Example 26 WAF investigation UI](media/2026-06-20_12-12-18_26_sonnet_4_5_example_1.png)

- `examples/cybersecurity/27_strands_detection_engineering.py` demonstrates a structured detection-engineering workflow. The agent uses local tools to summarize event samples, fetch official SigmaHQ examples as style references, validate Sigma-style rule sections, fetch current Elastic ECS fields, and validate Elastic KQL/ES|QL fields before returning a typed detection pack with findings, detection logic, hunts, response actions, assumptions, and a validation plan. It includes a built-in sample and also accepts JSONL or CSV event files.
- `examples/cybersecurity/28_strands_iam_policy_risk_review.py` demonstrates structured IAM least-privilege review. The agent uses local policy-analysis tools to identify wildcard actions/resources and sensitive permissions such as `iam:PassRole`, then returns a typed risk review with practical fixes and candidate condition keys.
- `examples/cybersecurity/29_strands_threat_intel_risk_chat.py` runs an interactive threat-intel chat agent in CLI mode or with `--web` as a FastAPI/SSE browser chat on `http://127.0.0.1:8003`. It can enrich CVE/EUVD records through Shodan CVEDB, pull bounded CWE/CAPEC definition excerpts from MITRE pages, query MITRE ATT&CK Enterprise tactics/techniques/software/groups with paginated list/search tools and group/software relationship tools, query MITRE ATLAS tactics/techniques/case studies/mitigations/software with paginated list/search tools and exact record lookup, map scenarios to OWASP Top 10:2025 or 2021, generate STRIDE/PASTA/Lockheed Kill Chain/Unified Kill Chain/Security Cards prompts, extract the official Security Cards and Unified Kill Chain PDFs to cached markdown under `downloads/threat_model_refs/`, run FAIR-style Monte Carlo ALE simulations, and calculate ROSI to help justify security tool or control cost.

## Run examples

Most examples run directly once AWS auth is set:

```bash
uv run python examples/agents/07_strands_multiagent_rss_briefing.py
uv run python examples/cybersecurity/14_strands_cybersec_triage_graph.py --url https://example.com/report
uv run python examples/cybersecurity/14_strands_cybersec_triage_graph.py --pdf ./report-a.pdf --pdf ./report-b.pdf --url https://example.com/advisory
uv run python examples/cybersecurity/14_strands_cybersec_triage_graph.py --html ./saved-page.html
uv run python examples/cybersecurity/15_strands_structured_cybersec_brief.py --pdf ./report.pdf
uv run python examples/cybersecurity/15_strands_structured_cybersec_brief.py --pdf ./report-a.pdf --text ./notes.md --url https://example.com/advisory
uv run python examples/cybersecurity/15_strands_structured_cybersec_brief.py --text ./article.md
uv run python examples/agents/23_strands_rss_exa_swarm.py
EXA_API_KEY=... uv run python examples/agents/23_strands_rss_exa_swarm.py
uv run python examples/agents/23_strands_rss_exa_swarm.py --feed https://example.com/feed.xml --days 14
uv run python examples/document-processing/24_pdf_to_unstructured_elements.py ./report.pdf --pretty --max-elements 20
uv run python examples/document-processing/25_pdf_elements_to_prompt_chunks.py ./report.pdf --question "Summarize the key risks."
uv run python examples/cybersecurity/27_strands_detection_engineering.py
uv run python examples/cybersecurity/27_strands_detection_engineering.py --events ./events.jsonl
uv run python examples/cybersecurity/28_strands_iam_policy_risk_review.py
uv run python examples/cybersecurity/28_strands_iam_policy_risk_review.py --policy ./policy.json
uv run python examples/cybersecurity/29_strands_threat_intel_risk_chat.py
uv run python examples/cybersecurity/29_strands_threat_intel_risk_chat.py --prompt "Tell me about CVE-2023-34362 and map it to CWE, ATT&CK, OWASP, STRIDE, and FAIR."
uv run python examples/cybersecurity/29_strands_threat_intel_risk_chat.py --web
```

For richer Bedrock Runtime Strands examples, override the default model with
`BEDROCK_MODEL_ID`:

```bash
BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-5-20250929-v1:0 \
  uv run python examples/cybersecurity/29_strands_threat_intel_risk_chat.py --web
```

This applies to files `06`, `07`, `09`-`12`, `14`-`17`, `19`, `20`, `23`, and
`26`-`29`. The smallest hello-world examples, Mantle path-specific examples,
and Nova Sonic voice example keep fixed model IDs because their purpose or
transport is model-specific.

Each numbered example writes DEBUG logs for the current run to a `logs/`
directory beside the script, replacing the previous contents at startup. Those logs
include SDK/request lifecycle details from libraries such as botocore, httpx,
urllib3, OpenAI, Strands, and Unstructured, which is useful when checking which
calls are being made. The log files are ignored by Git.

Some publisher sites return HTTP 403 to automated requests even with browser-like headers. For those, open the page in your browser, save it as HTML or PDF, then pass `--html` / `--pdf` to files `14` or `15`. In the web UIs (`13` and `26`), upload a saved PDF.

Web examples:

```bash
uv run python examples/agents/12_strands_webui_sse_hitl.py        # http://localhost:8000
uv run python examples/cybersecurity/13_mantle_gpt55_cybersec_webui.py     # http://localhost:8001
uv run python examples/cybersecurity/26_strands_elastic_waf_mcp_webui.py    # http://localhost:8002
uv run python examples/cybersecurity/29_strands_threat_intel_risk_chat.py --web  # http://localhost:8003
```

Elastic Agent Builder MCP setup for file `26`:

```bash
export ELASTIC_KIBANA_URL=https://your-deployment.kb.us-east-1.aws.elastic.cloud
export ELASTIC_API_KEY=...

# Optional alternatives / overrides:
export ELASTIC_AGENT_BUILDER_MCP_URL=https://your-kibana.example/api/agent_builder/mcp
export ELASTIC_KIBANA_SPACE=default
export ELASTIC_WAF_DATA_CONTEXT="Start with AWS WAF data streams, but inspect related CDN and ALB logs when useful."
```

MCP example:

```bash
uv run python examples/agents/17_strands_mcp_repo_tools_agent.py
REMOTE_MCP_URL=http://localhost:8000/mcp uv run python examples/agents/17_strands_mcp_repo_tools_agent.py
REMOTE_MCP_URL=http://localhost:8000/sse REMOTE_MCP_TRANSPORT=sse uv run python examples/agents/17_strands_mcp_repo_tools_agent.py
```

Sandbox example:

```bash
docker run --rm -it --name strands-cybersec-sandbox python:3.12-slim sleep infinity
uv run python examples/cybersecurity/19_strands_docker_sandbox_code_triage.py
```

Voice example:

```bash
uv sync
uv run python examples/cybersecurity/18_nova_sonic_voice_incident_briefing.py
```

Nova Sonic is available in `us-east-1`, `eu-north-1`, and `ap-northeast-1`. On macOS, PyAudio may also require PortAudio system headers.
