"""Shared dependency-free browser interactions for the FastAPI/SSE examples."""

WEBUI_INTERACTIONS_JS = r"""
window.WebUI = Object.freeze({
  scrollToEnd(container) {
    if (container) container.scrollTop = container.scrollHeight;
  },

  addMessage(container, className, text = "", options = {}) {
    const element = document.createElement(options.tagName || "div");
    element.className = className;
    element.textContent = text;
    if (options.role) element.setAttribute("role", options.role);
    container.appendChild(element);
    this.scrollToEnd(container);
    return element;
  },

  appendMarkdown(container, target, text) {
    target.dataset.markdown = (target.dataset.markdown || "") + (text || "");
    target.innerHTML = renderMarkdown(target.dataset.markdown);
    this.scrollToEnd(container);
    return target.dataset.markdown;
  },

  renderMarkdown(container, target, markdown) {
    target.dataset.markdown = markdown || "";
    target.innerHTML = renderMarkdown(target.dataset.markdown);
    this.scrollToEnd(container);
    return target.dataset.markdown;
  },

  setStatus(element, text, state = "") {
    if (!element) return;
    element.textContent = text;
    if (state) element.dataset.state = state;
    else delete element.dataset.state;
  },

  setBusy(button, input, busy, labels = {}) {
    if (button) {
      button.disabled = busy;
      if (busy && labels.busy) button.textContent = labels.busy;
      if (!busy && labels.idle) button.textContent = labels.idle;
    }
    if (input) input.disabled = busy;
  },

  bindPromptChips(input, selector = ".chip", root = document) {
    root.querySelectorAll(selector).forEach((chip) => {
      chip.addEventListener("click", () => {
        input.value = chip.dataset.prompt || chip.textContent.trim();
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.focus();
      });
    });
  },

  bindComposer(form, input, submit, options = {}) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const message = input.value.trim();
      if (!message) return;
      if (options.clear !== false) input.value = "";
      await submit(message);
    });
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        form.requestSubmit();
      }
    });
  },

  async *events(response) {
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    if (!response.body) throw new Error("Response did not include a readable stream");

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    function takeFrame() {
      const lf = buffer.indexOf("\n\n");
      const crlf = buffer.indexOf("\r\n\r\n");
      if (lf < 0 && crlf < 0) return null;
      const useCrlf = crlf >= 0 && (lf < 0 || crlf < lf);
      const index = useCrlf ? crlf : lf;
      const width = useCrlf ? 4 : 2;
      const frame = buffer.slice(0, index);
      buffer = buffer.slice(index + width);
      return frame;
    }

    while (true) {
      const { value, done } = await reader.read();
      buffer += decoder.decode(value || new Uint8Array(), { stream: !done });

      let frame;
      while ((frame = takeFrame()) !== null) {
        const data = frame
          .split(/\r?\n/)
          .filter((line) => line.startsWith("data:"))
          .map((line) => line.slice(5).replace(/^ /, ""))
          .join("\n");
        if (!data) continue;
        yield JSON.parse(data);
      }
      if (done) break;
    }

    const trailing = buffer.trim();
    if (trailing) {
      const data = trailing
        .split(/\r?\n/)
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).replace(/^ /, ""))
        .join("\n");
      if (data) yield JSON.parse(data);
    }
  },
});
"""
