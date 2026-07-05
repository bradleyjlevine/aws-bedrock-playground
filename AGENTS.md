# AGENTS.md

Guidance for AI coding agents (Claude Code, Codex, etc.) working in this repository.

## Project overview

Hello-world examples for AWS Bedrock: foundation models, agents, and the bedrock-mantle endpoint using the Anthropic and OpenAI SDKs. Python only. Dependency management via `uv`.

## Commands

```bash
uv sync                        # install dependencies
uv run python examples/<group>/<file>.py        # run a script
AWS_PROFILE=<profile> uv run python examples/<group>/<file>.py  # run with a specific SSO profile
uv run python scripts/check_examples.py         # local no-AWS validation
node scripts/check_webui_markdown.js            # validate shared WebUI Markdown rendering
```

## Project structure

```
auth.py                        # shared auth helper — DO NOT modify without reading the note below
arithmetic_utils.py            # safe arithmetic expression evaluator for calculator tools
webui_markdown.py              # shared browser-side Markdown renderer for WebUI examples
scripts/check_examples.py      # local no-AWS validation script
scripts/check_webui_markdown.js # Node QA script for WebUI Markdown rendering
examples/core/                 # Bedrock Runtime basics and guardrails
examples/mantle/               # bedrock-mantle examples and Strands mantle adapters
examples/agents/               # Strands agent, tool, MCP, swarm, workflow, and HITL examples
examples/cybersecurity/        # Cyber-security focused UIs, triage, detection, IAM, voice, sandbox examples
examples/document-processing/  # Unstructured PDF/document extraction examples
examples/core/01_bedrock_converse_foundation_model.py                 # bedrock-runtime, Converse API
examples/core/02_bedrock_invoke_agent.py              # bedrock-agent-runtime, InvokeAgent
examples/mantle/03_mantle_anthropic_messages.py   # bedrock-mantle, Anthropic Messages API
examples/mantle/04_mantle_openai_responses_oss.py      # bedrock-mantle /v1, OpenAI Responses API (OSS models)
examples/mantle/05_mantle_gpt55_codex.py              # bedrock-mantle /openai/v1, Codex / GPT-5.5
examples/core/06_strands_bedrock_guardrail_agent.py      # Strands single agent with Bedrock guardrail
examples/agents/07_strands_multiagent_rss_briefing.py # Strands multi-agent: fetcher + time + orchestrator
examples/agents/08_strands_custom_tools.py   # Strands @tool decorator
examples/agents/09_strands_file_session_history.py       # Strands FileSessionManager (persistent history)
examples/agents/10_strands_swarm_handoff.py         # Strands Swarm (autonomous handoff)
examples/agents/11_strands_streaming_cli_hitl.py     # Custom callback_handler + CLI chat loop + current_time + HITL (handoff_to_user)
examples/agents/12_strands_webui_sse_hitl.py         # FastAPI + SSE WebUI chat (browser) + current_time + HITL (interrupt hook)
examples/cybersecurity/13_mantle_gpt55_cybersec_webui.py      # FastAPI + SSE WebUI: upload PDF or URL → GPT-5.5 cyber-security summary
examples/cybersecurity/14_strands_cybersec_triage_graph.py     # Strands Graph: cyber triage over PDF/URL/HTML/text sources
examples/cybersecurity/15_strands_structured_cybersec_brief.py # Strands structured output: validated cyber brief object
examples/agents/16_strands_local_memory_advisor.py      # Strands tools: local durable memory advisor
examples/agents/17_strands_mcp_repo_tools_agent.py      # Strands MCP: native + local/remote MCP tools
examples/cybersecurity/18_nova_sonic_voice_incident_briefing.py # Nova Sonic bidirectional voice briefing
examples/cybersecurity/19_strands_docker_sandbox_code_triage.py # Strands DockerSandbox static code triage
examples/agents/20_strands_workflow_research_report.py  # Strands workflow tool for research reports
examples/mantle/21_strands_mantle_anthropic_adapter.py # Strands custom Anthropic adapter over bedrock-mantle /anthropic
examples/mantle/22_strands_mantle_openai_gpt54.py  # Strands OpenAI Responses adapter over bedrock-mantle /openai/v1
examples/agents/23_strands_rss_exa_swarm.py     # Strands Swarm: RSS + article fetching + Exa MCP web-search briefing
examples/document-processing/24_pdf_to_unstructured_elements.py # Unstructured OSS: PDF → typed elements JSONL
examples/document-processing/25_pdf_elements_to_prompt_chunks.py # Unstructured OSS: elements → source-attributed prompt chunks
examples/cybersecurity/26_strands_elastic_waf_mcp_webui.py # Strands MCP + FastAPI: WAF log search via Elastic Agent Builder MCP
examples/cybersecurity/27_strands_detection_engineering.py # Strands structured output: telemetry -> Sigma-style detections + hunts
examples/cybersecurity/28_strands_iam_policy_risk_review.py # Strands structured output: IAM policy risk + least-privilege review
examples/cybersecurity/29_strands_threat_intel_risk_chat.py # Strands CLI/WebUI chat: threat intel, paginated ATT&CK/ATLAS tools, cached PDF framework refs, FAIR ALE/ROSI risk analysis
examples/agents/30_strands_remote_mcp_teaching_agent.py # Strands MCP + optional FastAPI/SSE WebUI: tech teaching agent over AWS, Cloudflare, Microsoft, and Google docs MCP servers
examples/agents/31_bedrock_embeddings_local_rag.py # Bedrock Runtime: Titan embeddings + local in-memory RAG over text/Markdown files
examples/agents/sessions/      # Created by 09/16 at runtime; safe to delete
pyproject.toml                 # uv project config
```

## Critical facts to know before editing

### Two different bedrock-mantle base paths
- `/v1` — OSS models (`openai.gpt-oss-*`), Amazon Nova, and most third-party models (Chat Completions + Responses API)
- `/openai/v1` — GPT-5.5 and GPT-5.4 **only** (Responses API only, no Chat Completions)
- `/anthropic` — Claude models (used internally by the `anthropic` SDK)

Getting this wrong produces a 400 "Engine not found" from AWS. Do not unify them.

**GPT-5.5 / GPT-5.4 region**: only available in `us-east-2` (Ohio). Using `us-east-1`
returns "Engine not found". No model access request needed — available by default.

### auth.py — bearer token generation for bedrock-mantle
`auth.py` is only a helper for minting Bedrock Mantle bearer tokens from the active
AWS credential chain / SSO profile. File 05 constructs OpenAI's `BedrockOpenAI`
client directly, and file 13 constructs `AsyncBedrockOpenAI`; both pass
`auth.get_mantle_token(region)` as a refreshable `bedrock_token_provider`.
File 04 still uses `OpenAI(base_url=..., api_key=get_mantle_token(...))` because OSS models
route through the plain `/v1` Mantle path, while `BedrockOpenAI` derives `/openai/v1`.
This works by:
1. Creating a `boto3.Session` from `AWS_PROFILE` (or default chain)
2. Wrapping it in `BotoSessionCredentialsProvider` (botocore `CredentialProvider` interface)
3. Passing it to `aws_bedrock_token_generator.provide_token()` to mint a short-lived bearer token

The `anthropic` SDK (files 03 and 21) handles this internally via `aws_profile=` — no `auth.py` needed there.
File 21 reuses Strands' `AnthropicModel` adapter and replaces its client with
`AsyncAnthropicBedrockMantle` so Strands calls route through `/anthropic`.
File 22 reuses Strands' `OpenAIResponsesModel` adapter and overrides its OpenAI
client args so GPT-5.4 routes through `/openai/v1` with a fresh token from
`auth.get_mantle_token(region)`.

### IAM permissions
- `bedrock-runtime` and `bedrock-agent-runtime` calls work with standard `Bedrock_PowerUser` roles.
- `bedrock-mantle` requires `bedrock-mantle:CreateInference` — this is a **separate IAM action** not included in most Bedrock managed policies. Confirm the active profile has this before debugging mantle auth errors.

### GPT-5.5 supports Responses API only
`openai.gpt-5.5` does not support Chat Completions. Use `client.responses.create()`.

### SSO session expiry
If you see `TokenRetrievalError: Token has expired`, the SSO session needs a refresh:
```bash
aws sso login --profile <profile-name>
```

## Dependencies

| Package | Why |
|---------|-----|
| `boto3` | AWS SDK — all files |
| `anthropic[bedrock]` | Anthropic Messages API via bedrock-mantle |
| `openai` | OpenAI Responses/Chat Completions API via bedrock-mantle |
| `aws-bedrock-token-generator` | Mints bearer tokens from AWS credentials for bedrock-mantle |
| `strands-agents` | Strands agent framework — files 06–12, 14–20, 23, 26–30 |
| `strands-agents-tools[rss]` | Strands community tools (rss, current_time, handoff_to_user) — files 07, 09, 11, 12, 30 |
| `prompt-toolkit` | Optional — provides readline-style input for file 11 |
| `fastapi`, `uvicorn` | WebUI server for files 12, 13, 26, 29, 30 |
| `unstructured[all-docs]` | PDF/document partitioning for files 13–15 via `pdf_utils.py`; direct Unstructured demos in files 24–25; cached PDF references in file 29 |
| `pypdf` | Fallback PDF text extraction if Unstructured partitioning is unavailable |
| `defusedxml` | Hardened XML parser for MITRE CAPEC XML in file 29 |

### Local validation
Run `uv run python scripts/check_examples.py` after shared helper changes. It
compiles repository Python source, checks the safe arithmetic evaluator, and runs
the shared WebUI Markdown renderer QA. It intentionally avoids AWS calls.

### PDF extraction fallback
`pdf_utils.py` imports Unstructured lazily inside extraction calls so examples can
fall back to `pypdf` even when Unstructured is not installed or its native
runtime dependencies are unavailable. Direct Unstructured demos in files 24 and
25 still require `unstructured[all-docs]`.

## What NOT to do

### Bedrock Runtime model overrides
Richer Bedrock Runtime Strands examples should generally allow
`BEDROCK_MODEL_ID` to override the default `MODEL_ID`. This applies to files
`06`, `07`, `09`-`12`, `14`-`17`, `19`, `20`, `23`, and `26`-`31`. Keep tiny
hello-world examples, Mantle path-specific examples, and Nova Sonic fixed unless
there is a specific reason to generalize them.

### Local embeddings RAG (file 31)
File 31 uses Bedrock Runtime `InvokeModel` with Amazon Titan Text Embeddings V2
(`amazon.titan-embed-text-v2:0`) to embed local `.txt` / `.md` chunks, ranks
them in memory with cosine similarity, then answers with Converse. It has no
external vector database. `BEDROCK_MODEL_ID` controls the answer model, and
`BEDROCK_EMBEDDING_MODEL_ID` controls the embedding model.

### Remote documentation MCP teaching agent (file 30)
File 30 connects to three unauthenticated Streamable HTTP docs MCP endpoints by default:
AWS Knowledge MCP (`https://knowledge-mcp.global.api.aws`), Cloudflare Docs MCP
(`https://docs.mcp.cloudflare.com/mcp`), and Microsoft Learn MCP
(`https://learn.microsoft.com/api/mcp`). It also supports Google Developer
Knowledge MCP (`https://developerknowledge.googleapis.com/mcp`) when
`GCP_DK_MCP_API_KEY` is set, passing that value as the `X-Goog-Api-Key` header.
Google uses Strands' built-in `MCPClient` over Streamable HTTP with an
`httpx.AsyncClient` configured by `create_mcp_http_client(headers=...)`; do not
pass the key directly through deprecated `streamable_http_client(headers=...)`.
Because Google Developer Knowledge can close idle Streamable HTTP sessions during
long multi-provider agent turns, file 30 syncs Google's MCP tool schemas at
startup and exposes wrappers that open a fresh Google MCP session for each
`gcp_*` tool call. Preserve that fresh-session behavior for both CLI and WebUI
paths.
Preserve these defaults unless a provider changes its published endpoint. Keep
the endpoint overrides as environment variables and CLI flags so the example
remains easy to test when a single provider is unavailable. File 30's `--web`
mode should keep using FastAPI/SSE and the shared `webui_markdown.py` renderer
instead of forking Markdown rendering in the HTML. Keep tool calls hidden by
default behind the **Show tool calls** toggle so the teaching UI stays readable
while still exposing MCP activity when requested. In `--web` mode, open remote
MCP clients inside each `/chat` stream rather than storing MCP tool objects in
FastAPI lifespan state; remote docs servers can close idle sessions, which
causes `MCPClientInitializationError: the client session is not running` on
later turns. Preserve follow-up support by sending bounded browser transcript
history in the chat request and rebuilding the agent inside the active MCP
client context for that turn. Keep Strands ContextOffloader enabled by default
for file 30 because remote docs MCP tools can return large pages across
follow-up turns; preserve the `--no-context-offload`, `--offload-threshold`, and
`--offload-preview` controls when editing this example. File 30 defaults to
`8192` output tokens and also supports `BEDROCK_MAX_TOKENS` plus `--max-tokens`;
keep those controls because docs-grounded lessons can hit Strands' max-token
agent-loop failure with the old `4096` budget. CLI mode should stream
`agent.stream_async(...)` tokens to stdout and show only compact tool markers on
stderr so long docs-grounded runs do not look hung. Keep raw streamed response
bodies out of file 30's DEBUG log by raising the noisy transport/body loggers
above DEBUG. Do not let the agent infer that
`GCP_DK_MCP_API_KEY` is expired or invalid from generic Google MCP/tool errors;
only report that when the HTTP response or MCP tool result explicitly says the
key was rejected, invalid, or expired. Otherwise say Google docs were not
verified in that run.

### Strands @tool decorator (file 08)
The decorator reads the function's type annotations and docstring to build the Bedrock tool spec automatically. The docstring must have an `Args:` section for each parameter and a `Returns:` section.

### Vulnerability lookup tools (files 14, 15)
Files 14 and 15 define `lookup_cve` and `lookup_euvd` Strands tools backed by Shodan CVEDB's `/cve/{cve_id}` and `/euvd/{euvd_id}` endpoints. Keep the output bounded; references and CPEs are intentionally capped before returning to the model.

### Threat-intel framework tools (file 29)
File 29 uses public data sources but keeps tool outputs bounded. ATT&CK Enterprise data is loaded from official STIX and indexed into tactics, techniques, software, groups, and `uses` relationships. ATLAS data is indexed from the `mitre-atlas/atlas-data` GitHub tree and classified by path into tactics, techniques, case studies, mitigations, software/tool records, or generic records. Keep all list/search tools paginated with `limit` and `offset`, capped at a small page size, and return `next_offset` metadata. For exact ATLAS file contents, use `lookup_atlas_record(path)` rather than increasing search result sizes.

### Strands FileSessionManager (file 09)
Pass `session_manager=` and `agent_id=` to `Agent`. The session files land under `storage_dir/session_<session_id>/agents/agent_<agent_id>/messages/`. The directory persists between runs; delete it to start fresh.

### Strands Swarm (file 10)
`Swarm(nodes=[...], entry_point=...)` injects a `handoff_to_agent` tool into every agent automatically. Agents call that tool to pass control; the swarm handles routing. `SwarmResult.node_history` is a list of `SwarmNode` objects — `node_history[-1].node_id` gives the final agent's name. Do NOT look for a `.agent_name` attribute — it does not exist.

### Custom callback_handler (file 11)
Any callable `(**kwargs)` works as `callback_handler=`. Key kwargs:
- `data` (str): streamed token text
- `complete` (bool): True on the final chunk
- `event` (dict): raw stream event — check `event["contentBlockStart"]["start"]["toolUse"]` for tool calls

### WebUI streaming (file 12)
For browser/server scenarios, set `callback_handler=None` and consume `agent.stream_async(prompt)` directly — each yielded event has the same `data` / `event` shape, but you control where the bytes go. File 12 wraps each event into a JSON SSE frame (`data: {...}\n\n`) so the browser can render tokens incrementally with `fetch().body.getReader()`.

### WebUI Markdown rendering (files 12, 13, 26, 29, 30)
The browser UIs share `webui_markdown.py` for dependency-free client-side Markdown rendering. Do not paste or fork `renderMarkdown()` inside individual HTML strings; import `MARKDOWN_RENDERER_JS` and inject it into the page. When changing Markdown behavior or presentation, update the shared renderer and run `node scripts/check_webui_markdown.js`.

The QA script covers representative streamed model output: headings, paragraphs, inline code, emphasis, strikethrough, links/autolinks, blockquotes, ordered/unordered/task lists, strict and loose tables, escaped table pipes, fenced code blocks, partial streaming chunks, and HTML/script escaping.

### Human-in-the-loop (files 11, 12)
Two different mechanisms for the same pattern — the agent must get user approval before performing a sensitive action.

**File 11 (CLI):** uses `handoff_to_user` from `strands-agents-tools`. The agent calls it with the email draft before calling `send_email`; `handoff_to_user` blocks the agent loop and prompts at the terminal. The system prompt instructs the agent to follow the two-step protocol: `handoff_to_user` first, then `send_email` only on approval. Do NOT put `input()` inside a tool — it freezes the agent loop and breaks async/server contexts.

**File 12 (WebUI):** uses Strands' interrupt API, which is the right primitive for non-TTY contexts:
1. Register a `HookProvider` that listens to `BeforeToolCallEvent`.
2. In the callback, check `event.tool_use["name"]`; for the gated tool call `event.interrupt(name=..., reason=...)`. This raises `InterruptException`, which Strands catches — the agent loop stops and `AgentResult.stop_reason == "interrupt"` with `result.interrupts` populated.
3. Surface each interrupt to the user (SSE `approval_request` event). When the user decides, resume the agent by passing a list of `{"interruptResponse": {"interruptId": ..., "response": "APPROVE"|"DENY"}}` content blocks back into `agent(...)` or `agent.stream_async(...)`.
4. On resume, the `event.interrupt(...)` call inside the hook returns the user's response. Set `event.cancel_tool = "..."` on deny so the model sees a refusal message instead of the tool result.
5. Hook id is generated from `tool_use["toolUseId"]` — every tool call gets its own interrupt id, so duplicate calls don't collide.

Don't put `input()` in a tool intended to run server-side. Use the hook + interrupt pattern instead.

## What NOT to do

- For GPT-5.5 / GPT-5.4, construct `BedrockOpenAI` / `AsyncBedrockOpenAI` in the caller and pass `bedrock_token_provider` backed by `get_mantle_token(region)`. Keep `auth.py` scoped to token generation.
- Do not hardcode profile names or API keys in source files.
- Do not use `bedrock-runtime` for GPT-5.5 — it is only available via `bedrock-mantle`.
- For file 06, `BEDROCK_GUARDRAIL_ID` must be set before running — the placeholder `YOUR_GUARDRAIL_ID` will be rejected by the API. Create a guardrail in the Bedrock console first. `GUARDRAIL_VERSION` defaults to `DRAFT` which is valid for testing; use a numeric version string (e.g. `"1"`) for production.

<!-- gortex:communities:start -->
<!-- gortex:skills:start -->
## Community Skills

| Area | Description | Skill |
|------|-------------|-------|
| Build Swarm | 37 symbols | `/gortex-build-swarm` |
| Path | 30 symbols | `/gortex-path` |
| Parse Args | 22 symbols | `/gortex-parse-args` |
| Sse | 15 symbols | `/gortex-sse` |
| Remember Preference | 13 symbols | `/gortex-remember-preference` |
| Analyse | 13 symbols | `/gortex-analyse` |
| Pypdf Text From Bytes | 12 symbols | `/gortex-pypdf-text-from-bytes` |
| Make Remote Mcp Client | 10 symbols | `/gortex-make-remote-mcp-client` |
| Main | 9 symbols | `/gortex-main` |
| Urlparse | 8 symbols | `/gortex-urlparse` |
| Run In Sandbox | 7 symbols | `/gortex-run-in-sandbox` |
| Exa Web Search | 7 symbols | `/gortex-exa-web-search` |
| Responses With Fallback | 7 symbols | `/gortex-responses-with-fallback` |
| Lookup Euvd | 7 symbols | `/gortex-lookup-euvd` |
| Markdownify 13 Cybersec Summary Webui | 6 symbols | `/gortex-markdownify-13-cybersec-summary-webui` |
| Register Hooks | 6 symbols | `/gortex-register-hooks` |
| Init | 6 symbols | `/gortex-init` |
| Make Local Mcp Client | 6 symbols | `/gortex-make-local-mcp-client` |
| Summarize Cve Record 14 Cybersec Triage Graph | 6 symbols | `/gortex-summarize-cve-record-14-cybersec-triage-graph` |
| Auth Get Mantle Token | 5 symbols | `/gortex-auth-get-mantle-token` |
<!-- gortex:skills:end -->

<!-- gortex:communities:end -->
