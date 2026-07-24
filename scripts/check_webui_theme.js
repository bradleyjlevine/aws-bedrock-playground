#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");

const source = fs.readFileSync("webui_theme.py", "utf8");
const match = source.match(/WEBUI_THEME_CSS = r"""([\s\S]*?)\n"""(?:\n)?$/);
assert(match, "Could not extract WEBUI_THEME_CSS from webui_theme.py");

const css = match[1];
for (const selector of [
  ".webui-shell",
  ".ui-shell",
  ".ui-header",
  ".ui-eyebrow",
  ".ui-panel",
  ".ui-composer",
  "button.chip",
  "button.chip:hover",
  ":focus-visible",
  "prefers-reduced-motion",
]) {
  assert(css.includes(selector), `Shared theme is missing ${selector}`);
}
for (const token of [
  "--ui-ink",
  "--ui-muted",
  "--ui-line",
  "--ui-paper",
  "--ui-canvas",
  "--ui-accent",
  "--ui-accent-deep",
]) {
  assert(css.includes(token), `Shared theme is missing ${token}`);
}

console.log("WebUI theme checks passed.");
