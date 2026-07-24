"""
Hello World: Strands Streaming WebUI + Human-in-the-Loop
Browser chat UI that streams over Server-Sent Events (SSE) and pauses for
user approval before any send_email tool call.

Architecture:
  GET  /            — serves a self-contained HTML chat page
  POST /chat        — body {"message": "..."}; streams SSE events:
                        token              — incremental model output
                        tool               — non-HITL tool started
                        approval_request   — agent wants to call send_email; UI shows buttons
                        done               — turn completed
  POST /approve     — body {"interrupt_id": "...", "approve": true|false};
                        resumes the paused agent and re-streams continuation

HITL mechanism:
  A BeforeToolCallEvent hook intercepts send_email, calls event.interrupt(),
  which raises InterruptException. Strands stops the agent loop and returns
  AgentResult.stop_reason == "interrupt" with the pending Interrupt(s).
  The server emits an approval_request SSE event and remembers the interrupt.
  The browser POSTs /approve with the user's decision; the server resumes
  the agent by passing back an interruptResponse content block. The agent's
  hook receives the response from event.interrupt(); on "DENY" it sets
  cancel_tool=... so the model sees the tool was refused.

Install: uv sync
SSO:     aws sso login --profile my-sso-profile && export AWS_PROFILE=my-sso-profile
Run:     uv run python examples/agents/12_strands_webui_sse_hitl.py
         Then open http://localhost:8000

Try:     "Email alex@example.com to say the deploy is done."
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from logging_utils import configure_script_logging, install_http_request_logging_middleware
from webui_interactions import WEBUI_INTERACTIONS_JS
from webui_markdown import MARKDOWN_RENDERER_JS
from webui_theme import WEBUI_THEME_CSS

LOGGER = configure_script_logging(__file__)
import json
import os
from typing import Any

from arithmetic_utils import evaluate_arithmetic_expression
import boto3
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
from strands import Agent, tool
from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry
from strands.models import BedrockModel
from strands_tools import current_time

REGION = "us-east-1"
MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
)

profile = os.environ.get("AWS_PROFILE")
session = boto3.Session(profile_name=profile, region_name=REGION)
model = BedrockModel(model_id=MODEL_ID, boto_session=session)


# ---------------------------------------------------------------------------
# Tools
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

    Args:
        expression: A safe arithmetic expression, e.g. '(3 + 4) * 2'.

    Returns:
        The result as a string, or an error message if evaluation fails.
    """
    try:
        result = evaluate_arithmetic_expression(expression)
        return str(result)
    except Exception as exc:
        return f"Error: {exc}"


@tool
def send_email(recipient: str, subject: str, body: str) -> str:
    """Send an email. Pauses for user approval via the WebUI HITL hook.

    Args:
        recipient: Email address to send to.
        subject:   Email subject line.
        body:      Email body text.

    Returns:
        A status string.
    """
    # In a real app, call your email provider here. The hook (below) intercepts
    # this tool BEFORE it runs and raises an interrupt for human approval.
    # If we get here, approval was granted.
    return f"sent to {recipient} (subject: {subject!r})"


# ---------------------------------------------------------------------------
# Human-in-the-loop hook
# ---------------------------------------------------------------------------

class EmailApprovalHook(HookProvider):
    """Pauses agent execution and waits for human approval before send_email runs."""

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(BeforeToolCallEvent, self._gate)

    def _gate(self, event: BeforeToolCallEvent) -> None:
        if event.tool_use["name"] != "send_email":
            return
        # event.interrupt() raises InterruptException on first call (pause the agent).
        # When the agent is resumed with the user's response, this same call returns it.
        decision = event.interrupt(
            name="approve_send_email",
            reason={"tool": "send_email", "input": event.tool_use["input"]},
        )
        if decision != "APPROVE":
            event.cancel_tool = "user denied approval — do not retry without new instructions"


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

agent = Agent(
    model=model,
    system_prompt=(
        "You are a helpful assistant with four tools: word_count, calculator, "
        "current_time, and send_email.\n\n"
        "Use word_count, calculator, and current_time freely.\n\n"
        "send_email is a HUMAN-IN-THE-LOOP tool — every call is paused for user "
        "approval via the WebUI. If the tool returns a 'user denied approval' message, "
        "you MUST NOT retry it. Tell the user it was not sent and ask what they want to do."
    ),
    tools=[word_count, calculator, current_time, send_email],
    hooks=[EmailApprovalHook()],
    callback_handler=None,
)


# ---------------------------------------------------------------------------
# Web app
# ---------------------------------------------------------------------------

app = FastAPI()
install_http_request_logging_middleware(app, LOGGER)


# Track which interrupt_ids are currently awaiting a decision so /approve
# can reject stale or duplicate calls.
pending_interrupts: set[str] = set()


class ChatRequest(BaseModel):
    message: str


class ApproveRequest(BaseModel):
    interrupt_id: str
    approve: bool


HTML_PAGE = """\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='14' fill='%230b4d66'/><path d='M20 33l8 8 17-19' fill='none' stroke='white' stroke-width='6' stroke-linecap='round' stroke-linejoin='round'/></svg>">
  <title>Strands Bedrock Chat (HITL)</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #16233a;
      --muted: #657089;
      --line: #dbe2ee;
      --paper: #ffffff;
      --canvas: #eef3f8;
      --accent: #176b87;
      --accent-deep: #0b4d66;
      --approval: #fff7df;
      --approval-line: #e6b84a;
      --danger: #b43a45;
    }
    *, *::before, *::after { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      background:
        linear-gradient(90deg, rgba(23, 107, 135, 0.035) 1px, transparent 1px),
        linear-gradient(rgba(23, 107, 135, 0.035) 1px, transparent 1px),
        var(--canvas);
      background-size: 24px 24px;
      font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main {
      width: min(920px, calc(100vw - 32px));
      min-height: 100vh;
      margin: 0 auto;
      padding: 24px 0;
      display: grid;
      grid-template-rows: auto minmax(320px, 1fr) auto;
      gap: 14px;
    }
    header {
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 20px;
    }
    .eyebrow {
      margin: 0 0 4px;
      color: var(--accent);
      font: 700 0.72rem/1.2 ui-monospace, SFMono-Regular, Menlo, monospace;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }
    h1 { margin: 0; font-size: clamp(1.45rem, 3vw, 2.15rem); letter-spacing: -0.035em; }
    .lede { max-width: 630px; margin: 7px 0 0; color: var(--muted); line-height: 1.5; }
    .status {
      flex: 0 0 auto;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 7px 10px;
      border: 1px solid #b9d7df;
      border-radius: 999px;
      background: #f4fcfd;
      color: var(--accent-deep);
      font-size: 0.78rem;
      font-weight: 700;
    }
    .status::before {
      content: "";
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #20a46b;
      box-shadow: 0 0 0 3px rgba(32, 164, 107, 0.13);
    }
    #log {
      min-height: 0;
      overflow-y: auto;
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 18px;
      background: rgba(255, 255, 255, 0.94);
      box-shadow: 0 18px 50px rgba(35, 53, 83, 0.08);
    }
    .empty {
      height: 100%;
      min-height: 260px;
      display: grid;
      place-content: center;
      text-align: center;
      color: var(--muted);
    }
    .empty strong { color: var(--ink); font-size: 1.05rem; }
    .empty p { max-width: 440px; margin: 7px auto 0; line-height: 1.5; }
    .msg {
      max-width: 86%;
      margin: 0 0 12px;
      padding: 11px 13px;
      border-radius: 12px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      line-height: 1.45;
    }
    .user {
      margin-left: auto;
      background: #e6f3f7;
      border: 1px solid #c2e0e8;
      color: #123f50;
    }
    .assistant {
      background: #f7f9fc;
      border: 1px solid #e2e7f0;
      color: var(--ink);
      white-space: normal;
    }
    .assistant h1, .assistant h2, .assistant h3, .assistant h4, .assistant h5, .assistant h6 {
      margin: 0.35rem 0 0.25rem; line-height: 1.25; font-size: 1rem;
    }
    .assistant h1 { font-size: 1.08rem; }
    .assistant h4 { font-size: 0.96rem; }
    .assistant h5 { font-size: 0.92rem; }
    .assistant h6 { font-size: 0.9rem; color: #6e6e73; }
    .assistant p { margin: 0.35rem 0; }
    .assistant ul, .assistant ol { margin: 0.35rem 0 0.55rem 1.25rem; padding: 0; }
    .assistant li { margin: 0.18rem 0; }
    .assistant code {
      background: #e8edf3; border-radius: 4px; padding: 0.05rem 0.22rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.9em;
    }
    .assistant pre {
      overflow-x: auto; background: #111827; color: #f9fafb;
      border-radius: 6px; padding: 0.7rem; white-space: pre;
    }
    .assistant pre code { background: transparent; color: inherit; padding: 0; }
    .assistant table {
      width: 100%; border-collapse: collapse; margin: 0.55rem 0;
      font-size: 0.88rem; display: block; overflow-x: auto;
    }
    .assistant th, .assistant td {
      border: 1px solid #cbd5e1; padding: 0.4rem 0.5rem;
      text-align: left; vertical-align: top;
    }
    .assistant th { background: #eef2f7; }
    .assistant hr { border: 0; border-top: 1px solid #cbd5e1; margin: 0.75rem 0; }
    .assistant blockquote {
      margin: 0.5rem 0; padding: 0.2rem 0 0.2rem 0.75rem;
      border-left: 3px solid #cbd5e1; color: #475569;
    }
    .assistant del { color: #64748b; }
    .assistant input[type="checkbox"] { margin-right: 0.35rem; vertical-align: -0.1rem; }
    .assistant a { color: #0066cc; }
    .activity {
      margin: 0 0 12px;
      color: var(--muted);
      font-size: 0.8rem;
    }
    .activity summary { width: fit-content; cursor: pointer; font-weight: 650; }
    .tool { margin: 6px 0 0 12px; color: var(--muted); font-family: ui-monospace, monospace; }
    .error {
      max-width: 100%;
      color: #8e2630;
      background: #fff0f1;
      border: 1px solid #f1c5ca;
    }
    .approval {
      max-width: 100%;
      background: var(--approval);
      border: 1px solid var(--approval-line);
      border-radius: 14px;
      padding: 16px;
      margin: 0 0 14px;
      box-shadow: 0 8px 24px rgba(126, 88, 13, 0.09);
    }
    .approval-title { display: flex; justify-content: space-between; gap: 10px; }
    .approval-label {
      color: #77520a;
      font: 700 0.7rem/1.2 ui-monospace, monospace;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .approval pre {
      background: rgba(255,255,255,0.74);
      border: 1px solid rgba(198, 151, 50, 0.28);
      padding: 11px;
      border-radius: 8px;
      overflow-x: auto;
      font-size: 0.85rem;
      margin: 10px 0;
    }
    .approval-buttons { display: flex; gap: 0.5rem; margin-top: 0.5rem; }
    .approval-buttons button { padding: 0.4rem 1rem; border: 0; border-radius: 6px;
                               cursor: pointer; font: inherit; }
    .btn-approve { background: var(--accent-deep); color: #fff; }
    .btn-deny { background: transparent; border: 1px solid #d18b91 !important; color: var(--danger); }
    .composer {
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--paper);
      box-shadow: 0 10px 32px rgba(35, 53, 83, 0.07);
    }
    #form { display: grid; grid-template-columns: 1fr auto; gap: 10px; align-items: end; }
    #input {
      width: 100%;
      min-height: 54px;
      max-height: 150px;
      resize: vertical;
      padding: 10px 12px;
      border: 1px solid #c9d3e2;
      border-radius: 9px;
      color: var(--ink);
      background: #fbfcfe;
      font: inherit;
      line-height: 1.4;
    }
    button {
      min-height: 42px;
      padding: 0.65rem 1.15rem;
      border: 0;
      border-radius: 9px;
      background: var(--accent-deep);
      color: #fff;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      transition: transform 120ms ease, background 120ms ease;
    }
    button:hover:not(:disabled) { transform: translateY(-1px); background: var(--accent); }
    button:disabled { background: #9aa7b8; cursor: not-allowed; }
    button:focus-visible, #input:focus-visible, summary:focus-visible {
      outline: 3px solid rgba(23, 107, 135, 0.28);
      outline-offset: 2px;
    }
    .hint { margin: 8px 2px 0; color: var(--muted); font-size: 0.76rem; }
    .chips { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 9px; }
    .chip {
      min-height: 0;
      padding: 5px 8px;
      border: 1px solid #cbd6e4;
      background: #f8fafc;
      color: #40506a;
      font-size: 0.76rem;
      font-weight: 650;
    }
    @media (max-width: 680px) {
      main { width: min(100vw - 20px, 920px); padding: 12px 0; }
      header { display: block; }
      .status { margin-top: 10px; }
      #log { padding: 12px; }
      .msg { max-width: 100%; }
      #form { grid-template-columns: 1fr; }
      #send { width: 100%; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { scroll-behavior: auto !important; transition: none !important; }
    }
""" + WEBUI_THEME_CSS + """
  </style>
</head>
<body class="webui-shell">
<main class="ui-shell">
  <header class="ui-header">
    <div>
      <p class="eyebrow">Approval desk / Bedrock + Strands</p>
      <h1>Human-in-the-loop agent</h1>
      <p class="lede">Delegate everyday work. Sensitive actions pause here for a clear human decision before anything is sent.</p>
    </div>
    <div class="status" id="status" role="status">Ready</div>
  </header>
  <section id="log" class="ui-panel" aria-live="polite" aria-label="Conversation">
    <div class="empty" id="empty">
      <div>
        <strong>Start with a request</strong>
        <p>Ask for the time, run a calculation, or draft an email. Email delivery always requires your approval.</p>
      </div>
    </div>
  </section>
  <section class="composer ui-composer" aria-label="Message composer">
    <form id="form">
      <textarea id="input" autocomplete="off" placeholder="What should the agent do?" aria-label="Message" autofocus></textarea>
      <button id="send" type="submit">Send</button>
    </form>
    <div class="chips" aria-label="Example requests">
      <button class="chip" type="button" data-prompt="What time is it in Tokyo?">Check a time</button>
      <button class="chip" type="button" data-prompt="Calculate (42 + 18) * 3.">Run a calculation</button>
      <button class="chip" type="button" data-prompt="Email alex@example.com saying the deploy is done.">Draft an email</button>
    </div>
    <p class="hint">Press ⌘ Enter or Ctrl Enter to send.</p>
  </section>
</main>

<script>
""" + MARKDOWN_RENDERER_JS + """
""" + WEBUI_INTERACTIONS_JS + """
const log = document.getElementById("log");
const form = document.getElementById("form");
const input = document.getElementById("input");
const send = document.getElementById("send");
const status = document.getElementById("status");
const empty = document.getElementById("empty");

function add(cls, text) {
  empty?.remove();
  return WebUI.addMessage(log, "msg " + cls, text);
}

function appendMarkdown(target, text) {
  WebUI.appendMarkdown(log, target, text);
}

function addApprovalCard(interruptId, reason) {
  empty?.remove();
  const card = document.createElement("div");
  card.className = "msg approval";
  const args = reason && reason.input ? reason.input : {};
  card.innerHTML =
    '<div class="approval-title"><strong>Review email before sending</strong><span class="approval-label">Approval required</span></div>' +
    "<pre>" +
    "To:      " + escapeHTML(args.recipient || "") + "\\n" +
    "Subject: " + escapeHTML(args.subject   || "") + "\\n" +
    "Body:    " + escapeHTML(args.body      || "") +
    "</pre>" +
    '<div class="approval-buttons">' +
    '<button class="btn-approve">Approve and send</button>' +
    '<button class="btn-deny">Do not send</button>' +
    "</div>";
  log.appendChild(card);
  log.scrollTop = log.scrollHeight;

  const [approveBtn, denyBtn] = card.querySelectorAll("button");
  return new Promise((resolve) => {
    const finish = (decision) => {
      approveBtn.disabled = denyBtn.disabled = true;
      approveBtn.style.opacity = decision ? "1" : "0.5";
      denyBtn.style.opacity    = decision ? "0.5" : "1";
      resolve(decision);
    };
    approveBtn.onclick = () => finish(true);
    denyBtn.onclick    = () => finish(false);
  });
}

async function streamSSE(response, assistantBubble) {
  let pendingApproval = null;

  for await (const evt of WebUI.events(response)) {
      if (evt.type === "token") {
        status.textContent = "Responding";
        appendMarkdown(assistantBubble, evt.text);
      } else if (evt.type === "tool") {
        let activity = log.querySelector(".activity:last-of-type");
        if (!activity) {
          activity = document.createElement("details");
          activity.className = "activity";
          activity.innerHTML = "<summary>Show tool activity</summary>";
          log.appendChild(activity);
        }
        const item = document.createElement("div");
        item.className = "tool";
        item.textContent = evt.name;
        activity.appendChild(item);
      } else if (evt.type === "approval_request") {
        status.textContent = "Waiting for approval";
        pendingApproval = addApprovalCard(evt.interrupt_id, evt.reason);
        const approved = await pendingApproval;
        // Resume the agent and stream the continuation into the same bubble
        const continuation = await fetch("/approve", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ interrupt_id: evt.interrupt_id, approve: approved })
        });
        await streamSSE(continuation, assistantBubble);
      } else if (evt.type === "done") {
        // handled by outer caller
      } else if (evt.type === "error") {
        const error = add("msg error", "Could not complete the request: " + evt.text);
        error.setAttribute("role", "alert");
      }
  }
}

WebUI.bindComposer(form, input, async (message) => {
  send.disabled = true;
  input.disabled = true;
  status.textContent = "Working";
  add("msg user", message);
  const assistant = add("msg assistant", "");
  try {
    const resp = await fetch("/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message })
    });
    await streamSSE(resp, assistant);
  } catch (err) {
    console.error("Chat request failed", err);
    const error = add("msg error", "Connection failed. Check that the server is running, then try again.");
    error.setAttribute("role", "alert");
  } finally {
    send.disabled = false;
    input.disabled = false;
    status.textContent = "Ready";
    input.focus();
  }
});
WebUI.bindPromptChips(input);
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Streaming helpers
# ---------------------------------------------------------------------------

def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


async def _run_and_stream(prompt):
    """Run the agent (or resume it) and yield SSE frames.

    `prompt` is either a string (new turn) or a list of interruptResponse
    content blocks (resuming after an interrupt).
    """
    last_result = None
    try:
        async for event in agent.stream_async(prompt):
            data = event.get("data")
            if data:
                yield _sse({"type": "token", "text": data})
                continue

            raw = event.get("event", {})
            tool_use = (
                raw.get("contentBlockStart", {})
                .get("start", {})
                .get("toolUse")
            )
            if tool_use:
                name = tool_use.get("name", "unknown")
                # Don't show send_email as a generic tool — it'll surface as approval_request
                if name != "send_email":
                    yield _sse({"type": "tool", "name": name})

            if "result" in event:
                last_result = event["result"]
    except Exception as exc:
        yield _sse({"type": "error", "text": str(exc)})
        return

    # If the agent paused on an interrupt, surface each one as approval_request.
    if last_result is not None and getattr(last_result, "stop_reason", None) == "interrupt":
        for interrupt in last_result.interrupts:
            pending_interrupts.add(interrupt.id)
            yield _sse({
                "type": "approval_request",
                "interrupt_id": interrupt.id,
                "name": interrupt.name,
                "reason": interrupt.reason,
            })
        return

    yield _sse({"type": "done"})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return HTML_PAGE


@app.post("/chat")
async def chat(req: ChatRequest) -> StreamingResponse:
    return StreamingResponse(
        _run_and_stream(req.message),
        media_type="text/event-stream",
    )


@app.post("/approve")
async def approve(req: ApproveRequest) -> StreamingResponse:
    if req.interrupt_id not in pending_interrupts:
        raise HTTPException(status_code=404, detail="unknown or already-resolved interrupt_id")
    pending_interrupts.discard(req.interrupt_id)
    decision = "APPROVE" if req.approve else "DENY"

    resume_prompt = [
        {"interruptResponse": {"interruptId": req.interrupt_id, "response": decision}}
    ]
    return StreamingResponse(
        _run_and_stream(resume_prompt),
        media_type="text/event-stream",
    )


if __name__ == "__main__":
    print("Open http://localhost:8000 in your browser.")
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="debug",
        log_config=None,
        access_log=True,
    )
