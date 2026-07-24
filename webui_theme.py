"""Shared visual system for the browser-based Bedrock playground examples."""

WEBUI_THEME_CSS = r"""
.webui-shell {
  --ui-ink: #16233a;
  --ui-muted: #56647a;
  --ui-line: #dbe2ee;
  --ui-paper: #ffffff;
  --ui-canvas: #eef3f8;
  --ui-accent: #176b87;
  --ui-accent-deep: #0b4d66;
  --ui-success: #20885f;
  --ui-warning: #9a6808;
  --ui-danger: #b43a45;
  margin: 0;
  max-width: none;
  min-height: 100vh;
  padding: 0;
  color: var(--ui-ink);
  background:
    linear-gradient(90deg, rgba(23, 107, 135, 0.035) 1px, transparent 1px),
    linear-gradient(rgba(23, 107, 135, 0.035) 1px, transparent 1px),
    var(--ui-canvas);
  background-size: 24px 24px;
  font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
.webui-shell *, .webui-shell *::before, .webui-shell *::after { box-sizing: border-box; }
.webui-shell .ui-shell {
  width: min(1120px, calc(100vw - 32px));
  max-width: none;
  margin: 0 auto;
  padding: 24px 0;
}
.webui-shell .ui-header {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 20px;
  margin: 0 0 14px;
  padding: 0;
  border: 0;
}
.webui-shell .ui-eyebrow {
  margin: 0 0 4px;
  color: var(--ui-accent);
  font: 700 0.72rem/1.2 ui-monospace, SFMono-Regular, Menlo, monospace;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}
.webui-shell .ui-header h1 {
  margin: 0;
  color: var(--ui-ink);
  font-size: clamp(1.45rem, 3vw, 2.15rem);
  letter-spacing: -0.035em;
}
.webui-shell .ui-subtitle {
  max-width: 720px;
  margin: 7px 0 0;
  color: var(--ui-muted);
  line-height: 1.5;
}
.webui-shell .lede { color: var(--ui-muted); }
.webui-shell .ui-panel,
.webui-shell .ui-composer {
  border: 1px solid var(--ui-line);
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.94);
  box-shadow: 0 18px 50px rgba(35, 53, 83, 0.08);
}
.webui-shell #log.ui-panel { border-radius: 16px; }
.webui-shell .ui-composer { padding: 12px; }
.webui-shell button:not(.secondary) {
  border-radius: 9px;
  background: var(--ui-accent-deep);
}
.webui-shell button:hover:not(:disabled):not(.secondary) {
  background: var(--ui-accent);
}
.webui-shell button.chip {
  min-width: 0;
  min-height: 30px;
  height: auto;
  border: 1px solid #cbd6e4;
  border-radius: 999px;
  background: #f2f6fa;
  color: #314158;
  font-size: 0.82rem;
  font-weight: 650;
  line-height: 1.35;
}
.webui-shell button.chip:hover:not(:disabled) {
  border-color: #9fb2c7;
  background: #e5edf5;
  color: #24364d;
}
.webui-shell .divider { color: var(--ui-muted); }
.webui-shell button:focus-visible,
.webui-shell input:focus-visible,
.webui-shell textarea:focus-visible,
.webui-shell summary:focus-visible {
  outline: 3px solid rgba(23, 107, 135, 0.28);
  outline-offset: 2px;
}
@media (max-width: 720px) {
  .webui-shell .ui-shell {
    width: min(100vw - 20px, 1120px);
    padding: 12px 0;
  }
  .webui-shell .ui-header { display: block; }
}
@media (prefers-reduced-motion: reduce) {
  .webui-shell *, .webui-shell *::before, .webui-shell *::after {
    scroll-behavior: auto !important;
    transition: none !important;
  }
}
"""
