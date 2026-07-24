#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { TextDecoder, TextEncoder } = require("node:util");

const source = fs.readFileSync("webui_interactions.py", "utf8");
const match = source.match(/WEBUI_INTERACTIONS_JS = r"""([\s\S]*?)\n"""(?:\n)?$/);
assert(match, "Could not extract WEBUI_INTERACTIONS_JS from webui_interactions.py");

const context = {
  TextDecoder,
  Uint8Array,
  Event: class Event {
    constructor(type, options = {}) {
      this.type = type;
      this.bubbles = Boolean(options.bubbles);
    }
  },
  document: {
    createElement(tagName) {
      return {
        tagName,
        className: "",
        dataset: {},
        attributes: {},
        textContent: "",
        innerHTML: "",
        setAttribute(name, value) {
          this.attributes[name] = value;
        },
      };
    },
  },
  renderMarkdown(markdown) {
    return `<p>${markdown}</p>`;
  },
};
context.window = context;
vm.createContext(context);
vm.runInContext(match[1], context);

const ui = context.WebUI;
assert(ui, "WebUI namespace was not created");
for (const name of [
  "scrollToEnd",
  "addMessage",
  "appendMarkdown",
  "renderMarkdown",
  "setStatus",
  "setBusy",
  "bindPromptChips",
  "bindComposer",
  "events",
]) {
  assert.equal(typeof ui[name], "function", `WebUI.${name} is missing`);
}

const container = {
  children: [],
  scrollTop: 0,
  scrollHeight: 42,
  appendChild(child) {
    this.children.push(child);
  },
};
const message = ui.addMessage(container, "msg assistant", "hello", { role: "status" });
assert.equal(message.textContent, "hello");
assert.equal(message.attributes.role, "status");
assert.equal(container.scrollTop, 42);

ui.appendMarkdown(container, message, "**one**");
ui.appendMarkdown(container, message, " two");
assert.equal(message.dataset.markdown, "**one** two");
assert.equal(message.innerHTML, "<p>**one** two</p>");

function responseFromChunks(chunks) {
  const encoded = chunks.map((chunk) => new TextEncoder().encode(chunk));
  let index = 0;
  return {
    ok: true,
    status: 200,
    body: {
      getReader() {
        return {
          async read() {
            if (index >= encoded.length) return { done: true };
            return { value: encoded[index++], done: false };
          },
        };
      },
    },
  };
}

(async () => {
  const response = responseFromChunks([
    'data: {"type":"token","text":"hel',
    'lo"}\n\ndata: {"type":"stage",',
    '"text":"done"}\r\n\r\n',
  ]);
  const events = [];
  for await (const event of ui.events(response)) events.push(event);
  assert.deepEqual(
    JSON.parse(JSON.stringify(events)),
    [
      { type: "token", text: "hello" },
      { type: "stage", text: "done" },
    ],
  );

  await assert.rejects(
    async () => {
      for await (const _event of ui.events({ ok: false, status: 503 })) {
        // The iterator must fail before yielding.
      }
    },
    /HTTP 503/,
  );
  console.log("WebUI interaction checks passed.");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
