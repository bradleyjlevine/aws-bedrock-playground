# AGENTS.md

Guidance for AI coding agents (Claude Code, Codex, etc.) working in this repository.

## Project overview

Hello-world examples for AWS Bedrock: foundation models, agents, and the bedrock-mantle endpoint using the Anthropic and OpenAI SDKs. Python only. Dependency management via `uv`.

## Commands

```bash
uv sync                        # install dependencies
uv run python <file>.py        # run a script
AWS_PROFILE=<profile> uv run python <file>.py  # run with a specific SSO profile
```

## Project structure

```
auth.py                        # shared auth helper — DO NOT modify without reading the note below
01_bedrock_converse_foundation_model.py                 # bedrock-runtime, Converse API
02_bedrock_invoke_agent.py              # bedrock-agent-runtime, InvokeAgent
03_mantle_anthropic_messages.py   # bedrock-mantle, Anthropic Messages API
04_mantle_openai_responses_oss.py      # bedrock-mantle /v1, OpenAI Responses API (OSS models)
05_mantle_gpt55_codex.py              # bedrock-mantle /openai/v1, Codex / GPT-5.5
06_strands_bedrock_guardrail_agent.py      # Strands single agent with Bedrock guardrail
07_strands_multiagent_rss_briefing.py # Strands multi-agent: fetcher + time + orchestrator
08_strands_custom_tools.py   # Strands @tool decorator
09_strands_file_session_history.py       # Strands FileSessionManager (persistent history)
10_strands_swarm_handoff.py         # Strands Swarm (autonomous handoff)
11_strands_streaming_cli_hitl.py     # Custom callback_handler + CLI chat loop + current_time + HITL (handoff_to_user)
12_strands_webui_sse_hitl.py         # FastAPI + SSE WebUI chat (browser) + current_time + HITL (interrupt hook)
13_mantle_gpt55_cybersec_webui.py      # FastAPI + SSE WebUI: upload PDF or URL → GPT-5.5 cyber-security summary
14_strands_cybersec_triage_graph.py     # Strands Graph: cyber triage over PDF/URL/HTML/text sources
15_strands_structured_cybersec_brief.py # Strands structured output: validated cyber brief object
16_strands_local_memory_advisor.py      # Strands tools: local durable memory advisor
17_strands_mcp_repo_tools_agent.py      # Strands MCP: native + local/remote MCP tools
18_nova_sonic_voice_incident_briefing.py # Nova Sonic bidirectional voice briefing
19_strands_docker_sandbox_code_triage.py # Strands DockerSandbox static code triage
20_strands_workflow_research_report.py  # Strands workflow tool for research reports
21_strands_mantle_anthropic_adapter.py # Strands custom Anthropic adapter over bedrock-mantle /anthropic
22_strands_mantle_openai_gpt54.py  # Strands OpenAI Responses adapter over bedrock-mantle /openai/v1
23_strands_rss_exa_swarm.py     # Strands Swarm: RSS + article fetching + Exa MCP web-search briefing
24_pdf_to_unstructured_elements.py # Unstructured OSS: PDF → typed elements JSONL
25_pdf_elements_to_prompt_chunks.py # Unstructured OSS: elements → source-attributed prompt chunks
sessions/                      # Created by 09 at runtime; safe to delete
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
| `strands-agents` | Strands agent framework — files 06–12 |
| `strands-agents-tools[rss]` | Strands community tools (rss, current_time, handoff_to_user) — files 07, 09, 11, 12 |
| `prompt-toolkit` | Optional — provides readline-style input for file 11 |
| `fastapi`, `uvicorn` | WebUI server for files 12, 13 |
| `unstructured[all-docs]` | PDF/document partitioning for files 13–15 via `pdf_utils.py`; direct Unstructured demos in files 24–25 |
| `pypdf` | Fallback PDF text extraction if Unstructured partitioning is unavailable |

## What NOT to do

### Strands @tool decorator (file 08)
The decorator reads the function's type annotations and docstring to build the Bedrock tool spec automatically. The docstring must have an `Args:` section for each parameter and a `Returns:` section.

### Vulnerability lookup tools (files 14, 15)
Files 14 and 15 define `lookup_cve` and `lookup_euvd` Strands tools backed by Shodan CVEDB's `/cve/{cve_id}` and `/euvd/{euvd_id}` endpoints. Keep the output bounded; references and CPEs are intentionally capped before returning to the model.

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
