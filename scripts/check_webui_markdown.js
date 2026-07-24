#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const rendererSource = fs.readFileSync("webui_markdown.py", "utf8");
const rendererMatch = rendererSource.match(/MARKDOWN_RENDERER_JS = r"""([\s\S]*?)\n"""(?:\n)?$/);
assert(rendererMatch, "Could not extract MARKDOWN_RENDERER_JS from webui_markdown.py");

const context = {};
vm.createContext(context);
vm.runInContext(rendererMatch[1], context);
assert.equal(typeof context.renderMarkdown, "function");

function render(markdown) {
  return context.renderMarkdown(markdown);
}

const comprehensive = `# Executive Summary

Plain text with **critical** impact, _emphasis_, ~~removed text~~, \`inline <code>\`,
[AWS Bedrock](https://aws.amazon.com/bedrock), [query](https://example.com/report?a=1&b=2),
and https://example.com/report?c=3&d=4.

> Quote line
> - quoted item

- [x] Contain WAF noise
- [ ] Tune managed rules

1. First action
2. Second action

| Vector | Count | Notes |
|:---|---:|:---:|
| RCE \\| deserialization | 3 | \`pipe | in code\` |
| C:\\Temp\\logs | 1 | Windows path |

Loose | Table
alpha | beta

\`\`\`json
{"payload":"<script>alert(1)</script>"}
\`\`\`

---
`;

const html = render(comprehensive);
assert(html.includes("<h1>Executive Summary</h1>"));

const nestedHeadings = render(`## Executive Summary

### Key Threat Trends`);
assert(nestedHeadings.includes("<h2>Executive Summary</h2>"));
assert(nestedHeadings.includes("<h3>Key Threat Trends</h3>"));
assert(!nestedHeadings.includes("# Executive Summary"));
assert(html.includes("<strong>critical</strong>"));
assert(html.includes("<em>emphasis</em>"));
assert(html.includes("<del>removed text</del>"));
assert(html.includes("<code>inline &lt;code&gt;</code>"));
assert(html.includes('<a href="https://aws.amazon.com/bedrock" target="_blank" rel="noopener noreferrer">AWS Bedrock</a>'));
assert(html.includes('<a href="https://example.com/report?a=1&amp;b=2" target="_blank" rel="noopener noreferrer">query</a>'));
assert(html.includes('<a href="https://example.com/report?c=3&amp;d=4" target="_blank" rel="noopener noreferrer">https://example.com/report?c=3&amp;d=4</a>'));
assert(html.includes("<blockquote>"));
assert(html.includes("<ul>"));
assert(html.includes('<input type="checkbox" disabled checked> Contain WAF noise'));
assert(html.includes('<input type="checkbox" disabled> Tune managed rules'));
assert(html.includes("<ol>"));
assert(html.includes("<table>"));
assert(html.includes('style="text-align:right"'));
assert(html.includes('style="text-align:center"'));
assert(html.includes("<td>RCE | deserialization</td>"));
assert(html.includes("<td>C:\\Temp\\logs</td>"));
assert(html.includes("<code>pipe | in code</code>"));
assert(html.includes('<pre><code class="language-json">'));
assert(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
assert(!html.includes("<script>alert"));
assert(html.includes("<hr>"));

const partialStream = render("#\nFindings\n\n```python\nprint('x')");
assert(partialStream.includes("<h1>Findings</h1>"));
assert(partialStream.includes('<pre><code class="language-python">print(&#39;x&#39;)</code></pre>'));

const unsafe = render('[bad](javascript:alert(1)) <img src=x onerror=alert(1)>');
assert(!unsafe.includes('href="javascript:'));
assert(!unsafe.includes("<img"));
assert(unsafe.includes("&lt;img src=x onerror=alert(1)&gt;"));

const pages = [
  "examples/agents/12_strands_webui_sse_hitl.py",
  "examples/cybersecurity/13_mantle_gpt55_cybersec_webui.py",
  "examples/cybersecurity/26_strands_elastic_waf_mcp_webui.py",
  "examples/cybersecurity/29_strands_threat_intel_risk_chat.py",
];

for (const page of pages) {
  const source = fs.readFileSync(page, "utf8");
  assert(source.includes("MARKDOWN_RENDERER_JS"), page + " does not inject the shared renderer");
  assert(!source.includes("function renderMarkdown(markdown)"), page + " still has a local renderer copy");
  assert(source.includes("blockquote"), page + " is missing blockquote styling");
  assert(source.includes('input[type="checkbox"]'), page + " is missing task-list checkbox styling");
}

console.log("WebUI markdown renderer checks passed.");
