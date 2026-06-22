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

from logging_utils import configure_script_logging

LOGGER = configure_script_logging(__file__)
import json
import os
import time
from typing import Any

import boto3
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
from strands import Agent, tool
from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry
from strands.models import BedrockModel
from strands_tools import current_time

REGION = "us-east-1"
MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

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


@app.middleware("http")
async def _log_http_request(request: Request, call_next):
    start = time.perf_counter()
    LOGGER.debug("HTTP request start method=%s path=%s", request.method, request.url.path)
    try:
        response = await call_next(request)
    except Exception:
        LOGGER.exception("HTTP request failed method=%s path=%s", request.method, request.url.path)
        raise

    elapsed_ms = (time.perf_counter() - start) * 1000
    LOGGER.debug(
        "HTTP request complete method=%s path=%s status=%d elapsed_ms=%.1f",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response


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
  <title>Strands Bedrock Chat (HITL)</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           max-width: 760px; margin: 2rem auto; padding: 0 1rem; color: #1d1d1f; }
    h1 { font-size: 1.4rem; }
    #log { border: 1px solid #d2d2d7; border-radius: 8px; padding: 1rem;
           height: 60vh; overflow-y: auto; background: #fafafa; }
    .msg { margin: 0.6rem 0; white-space: pre-wrap; line-height: 1.4; }
    .user { color: #0066cc; }
    .assistant { color: #1d1d1f; }
    .tool { color: #8e8e93; font-style: italic; font-size: 0.85rem; }
    .approval { background: #fff4d6; border: 1px solid #f0c040; border-radius: 8px;
                padding: 0.75rem 1rem; margin: 0.6rem 0; }
    .approval pre { background: #fff; padding: 0.5rem; border-radius: 4px;
                    overflow-x: auto; font-size: 0.85rem; margin: 0.4rem 0; }
    .approval-buttons { display: flex; gap: 0.5rem; margin-top: 0.5rem; }
    .approval-buttons button { padding: 0.4rem 1rem; border: 0; border-radius: 6px;
                               cursor: pointer; font: inherit; }
    .btn-approve { background: #34c759; color: #fff; }
    .btn-deny    { background: #ff3b30; color: #fff; }
    #form { display: flex; gap: 0.5rem; margin-top: 1rem; }
    #input { flex: 1; padding: 0.6rem; border: 1px solid #d2d2d7;
             border-radius: 6px; font: inherit; }
    button { padding: 0.6rem 1.2rem; border: 0; border-radius: 6px;
             background: #0066cc; color: #fff; font: inherit; cursor: pointer; }
    button:disabled { background: #aaa; cursor: not-allowed; }
  </style>
</head>
<body>
  <h1>Strands Bedrock Chat — Human in the Loop</h1>
  <p style="color:#6e6e73;">
    Try: <em>"Email alex@example.com saying the deploy is done."</em>
    or <em>"What time is it?"</em><br>
    The agent will draft the email and ask you to approve or deny before sending.
  </p>
  <div id="log"></div>
  <form id="form">
    <input id="input" autocomplete="off" placeholder="Type a message..." autofocus>
    <button id="send" type="submit">Send</button>
  </form>

<script>
const log = document.getElementById("log");
const form = document.getElementById("form");
const input = document.getElementById("input");
const send = document.getElementById("send");

function add(cls, text) {
  const div = document.createElement("div");
  div.className = "msg " + cls;
  div.textContent = text;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
  return div;
}

function addApprovalCard(interruptId, reason) {
  const card = document.createElement("div");
  card.className = "msg approval";
  const args = reason && reason.input ? reason.input : {};
  card.innerHTML =
    "<strong>Approval required: send_email</strong>" +
    "<pre>" +
    "To:      " + (args.recipient || "") + "\\n" +
    "Subject: " + (args.subject   || "") + "\\n" +
    "Body:    " + (args.body      || "") +
    "</pre>" +
    '<div class="approval-buttons">' +
    '<button class="btn-approve">Approve & Send</button>' +
    '<button class="btn-deny">Deny</button>' +
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
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let pendingApproval = null;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\\n\\n");
    buffer = lines.pop();
    for (const line of lines) {
      if (!line.startsWith("data: ")) continue;
      const evt = JSON.parse(line.slice(6));
      if (evt.type === "token") {
        assistantBubble.textContent += evt.text;
        log.scrollTop = log.scrollHeight;
      } else if (evt.type === "tool") {
        add("tool", "[tool: " + evt.name + "]");
      } else if (evt.type === "approval_request") {
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
        add("tool", "Error: " + evt.text);
      }
    }
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const message = input.value.trim();
  if (!message) return;
  input.value = "";
  send.disabled = true;
  add("user", "You: " + message);
  const assistant = add("assistant", "Assistant: ");
  try {
    const resp = await fetch("/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message })
    });
    await streamSSE(resp, assistant);
  } finally {
    send.disabled = false;
    input.focus();
  }
});
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
