"""Shared browser-side Markdown renderer for the WebUI examples."""

MARKDOWN_RENDERER_JS = r"""
function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function restorePlaceholders(text, placeholders) {
  return text.replace(/\u0000(\d+)\u0000/g, (_, index) => placeholders[Number(index)] || "");
}

function renderInline(markdown) {
  const placeholders = [];
  let text = String(markdown).replace(/`([^`\n]+)`/g, (_, code) => {
    const token = "\u0000" + placeholders.length + "\u0000";
    placeholders.push("<code>" + escapeHTML(code) + "</code>");
    return token;
  });

  let html = escapeHTML(text);
  html = html.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, (_, label, url) => {
    return '<a href="' + url + '" target="_blank" rel="noopener noreferrer">' + label + "</a>";
  });
  html = html.replace(/(^|[\s(])((?:https?:\/\/)[^\s<]+[^<.,;:!?)\]\s])/g, (_, prefix, url) => {
    return prefix + '<a href="' + url + '" target="_blank" rel="noopener noreferrer">' + url + "</a>";
  });
  html = html.replace(/~~([^~]+)~~/g, "<del>$1</del>");
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/__([^_]+)__/g, "<strong>$1</strong>");
  html = html.replace(/(^|[^\w*])\*([^*\n]+)\*(?!\w)/g, "$1<em>$2</em>");
  html = html.replace(/(^|[^\w_])_([^_\n]+)_(?!\w)/g, "$1<em>$2</em>");
  return restorePlaceholders(html, placeholders);
}

function splitTableRow(line) {
  let trimmed = String(line).trim();
  if (trimmed.startsWith("|")) trimmed = trimmed.slice(1);
  if (trimmed.endsWith("|") && !trimmed.endsWith("\\|")) trimmed = trimmed.slice(0, -1);

  const cells = [];
  let cell = "";
  let inCode = false;

  for (let i = 0; i < trimmed.length; i += 1) {
    const char = trimmed[i];
    if (char === "\\") {
      if (trimmed[i + 1] === "|") {
        cell += "|";
        i += 1;
      } else {
        cell += char;
      }
      continue;
    }
    if (char === "`") {
      inCode = !inCode;
      cell += char;
      continue;
    }
    if (char === "|" && !inCode) {
      cells.push(cell.trim());
      cell = "";
      continue;
    }
    cell += char;
  }

  cells.push(cell.trim());
  return cells;
}

function isTableSeparator(line) {
  const cells = splitTableRow(line);
  return cells.length >= 2 && cells.every(cell => /^:?-{3,}:?$/.test(cell.trim()));
}

function isPipeTableRow(line) {
  const trimmed = String(line).trim();
  return trimmed.includes("|") && splitTableRow(trimmed).length >= 2;
}

function tableAlignments(separator) {
  return splitTableRow(separator).map(cell => {
    const trimmed = cell.trim();
    if (trimmed.startsWith(":") && trimmed.endsWith(":")) return "center";
    if (trimmed.endsWith(":")) return "right";
    return "left";
  });
}

function tableCell(tag, value, align) {
  const style = align && align !== "left" ? ' style="text-align:' + align + '"' : "";
  return "<" + tag + style + ">" + renderInline(value || "") + "</" + tag + ">";
}

function renderTable(lines, start) {
  const header = splitTableRow(lines[start]);
  const align = tableAlignments(lines[start + 1]);
  const rows = [];
  let index = start + 2;
  while (index < lines.length && lines[index].trim() && isPipeTableRow(lines[index])) {
    rows.push(splitTableRow(lines[index]));
    index += 1;
  }
  const thead = "<thead><tr>" + header.map((cell, i) => tableCell("th", cell, align[i])).join("") + "</tr></thead>";
  const tbody = "<tbody>" + rows.map(row => {
    return "<tr>" + header.map((_, i) => tableCell("td", row[i] || "", align[i])).join("") + "</tr>";
  }).join("") + "</tbody>";
  return { html: "<table>" + thead + tbody + "</table>", next: index };
}

function renderLooseTable(lines, start) {
  const tableLines = [];
  let index = start;
  while (index < lines.length && lines[index].trim() && isPipeTableRow(lines[index])) {
    tableLines.push(lines[index]);
    index += 1;
  }
  if (tableLines.length < 2) return null;
  const header = splitTableRow(tableLines[0]);
  const rows = tableLines.slice(1).map(splitTableRow);
  const thead = "<thead><tr>" + header.map(cell => tableCell("th", cell)).join("") + "</tr></thead>";
  const tbody = "<tbody>" + rows.map(row => {
    return "<tr>" + header.map((_, i) => tableCell("td", row[i] || "")).join("") + "</tr>";
  }).join("") + "</tbody>";
  return { html: "<table>" + thead + tbody + "</table>", next: index };
}

function normalizeMarkdown(markdown) {
  return String(markdown)
    .replace(/\r\n?/g, "\n")
    .replace(/([^#\n])\s*(#{1,6}\s+)/g, "$1\n\n$2")
    .replace(/([^\n])\s*(---+|___+|\*\*\*+)\s*(?=\n|$)/g, "$1\n\n$2")
    .replace(/([^\n])\s*(```)/g, "$1\n\n$2")
    .replace(/([.!?\)])(Let me|Now let me|I'll|I will|Next,|Good!|Great!|Excellent!|Perfect!|Excellent\.)/g, "$1\n\n$2")
    .replace(/(:)(Let me|Now let me|I'll|I will|Next,)/g, "$1\n\n$2");
}

function repairMarkdownLines(lines) {
  const repaired = [];
  for (let i = 0; i < lines.length; i += 1) {
    const trimmed = lines[i].trim();
    if (/^#{1,6}$/.test(trimmed)) {
      let j = i + 1;
      while (j < lines.length && !lines[j].trim()) j += 1;
      if (j < lines.length) {
        repaired.push(trimmed + " " + lines[j].trim());
        i = j;
        continue;
      }
    }
    repaired.push(lines[i]);
  }
  return repaired;
}

function renderMarkdown(markdown) {
  const lines = repairMarkdownLines(normalizeMarkdown(markdown).split("\n"));
  const html = [];
  let paragraph = [];
  let listType = null;
  let inFence = false;
  let fenceLanguage = "";
  let fenceLines = [];

  function flushParagraph() {
    if (!paragraph.length) return;
    html.push("<p>" + renderInline(paragraph.join(" ")) + "</p>");
    paragraph = [];
  }

  function closeList() {
    if (!listType) return;
    html.push("</" + listType + ">");
    listType = null;
  }

  function ensureList(type) {
    if (listType === type) return;
    closeList();
    html.push("<" + type + ">");
    listType = type;
  }

  function flushFence() {
    const className = /^[A-Za-z0-9_-]+$/.test(fenceLanguage) ? ' class="language-' + fenceLanguage + '"' : "";
    html.push("<pre><code" + className + ">" + escapeHTML(fenceLines.join("\n")) + "</code></pre>");
    fenceLanguage = "";
    fenceLines = [];
  }

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const trimmed = line.trim();
    const fence = trimmed.match(/^```([A-Za-z0-9_-]+)?\s*$/);
    if (fence) {
      flushParagraph();
      closeList();
      if (inFence) {
        flushFence();
      } else {
        fenceLanguage = fence[1] || "";
      }
      inFence = !inFence;
      continue;
    }

    if (inFence) {
      fenceLines.push(line);
      continue;
    }

    if (!trimmed) {
      flushParagraph();
      closeList();
      continue;
    }

    if (/^---+$/.test(trimmed) || /^___+$/.test(trimmed) || /^\*\*\*+$/.test(trimmed)) {
      flushParagraph();
      closeList();
      html.push("<hr>");
      continue;
    }

    if (trimmed.startsWith(">")) {
      flushParagraph();
      closeList();
      const quoteLines = [];
      while (i < lines.length && lines[i].trim().startsWith(">")) {
        quoteLines.push(lines[i].trim().replace(/^>\s?/, ""));
        i += 1;
      }
      i -= 1;
      html.push("<blockquote>" + renderMarkdown(quoteLines.join("\n")) + "</blockquote>");
      continue;
    }

    if (i + 1 < lines.length && trimmed.includes("|") && isTableSeparator(lines[i + 1])) {
      flushParagraph();
      closeList();
      const table = renderTable(lines, i);
      html.push(table.html);
      i = table.next - 1;
      continue;
    }

    if (i + 1 < lines.length && isPipeTableRow(trimmed) && isPipeTableRow(lines[i + 1])) {
      flushParagraph();
      closeList();
      const table = renderLooseTable(lines, i);
      if (table) {
        html.push(table.html);
        i = table.next - 1;
        continue;
      }
    }

    const heading = trimmed.match(/^(#{1,6})\s+(.+?)\s*#*$/);
    if (heading) {
      flushParagraph();
      closeList();
      const level = heading[1].length;
      html.push("<h" + level + ">" + renderInline(heading[2]) + "</h" + level + ">");
      continue;
    }

    const ordered = trimmed.match(/^\d+\.\s+(.+)$/);
    if (ordered) {
      flushParagraph();
      ensureList("ol");
      html.push("<li>" + renderInline(ordered[1]) + "</li>");
      continue;
    }

    const unordered = trimmed.match(/^[-*+]\s+(.+)$/);
    if (unordered) {
      flushParagraph();
      ensureList("ul");
      const task = unordered[1].match(/^\[([ xX])\]\s+(.+)$/);
      if (task) {
        const checked = task[1].toLowerCase() === "x" ? " checked" : "";
        html.push('<li><input type="checkbox" disabled' + checked + "> " + renderInline(task[2]) + "</li>");
      } else {
        html.push("<li>" + renderInline(unordered[1]) + "</li>");
      }
      continue;
    }

    closeList();
    paragraph.push(trimmed);
  }

  if (inFence) flushFence();
  flushParagraph();
  closeList();
  return html.join("");
}
"""
