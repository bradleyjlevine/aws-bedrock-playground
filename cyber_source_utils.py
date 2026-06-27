"""Shared source-loading helpers for cyber-security examples."""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from urllib.parse import urljoin, urlparse

import markdownify
import requests
from bs4 import BeautifulSoup

from pdf_utils import extract_pdf_text_from_path

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Upgrade-Insecure-Requests": "1",
}


class UnsafeURL(ValueError):
    """Raised when a user-supplied URL is unsafe for server-side fetching."""


def html_to_markdown(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg"]):
        tag.decompose()
    return markdownify.markdownify(str(soup), heading_style="ATX").strip()


def browser_headers_for(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}/" if parsed.scheme and parsed.netloc else url
    return {**BROWSER_HEADERS, "Referer": origin}


def _blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    return any(
        (
            ip.is_loopback,
            ip.is_private,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        )
    )


def _validate_public_host(hostname: str) -> None:
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise UnsafeURL(f"Could not resolve URL host: {hostname}") from exc
        addresses = list({ipaddress.ip_address(info[4][0]) for info in infos})

    if not addresses:
        raise UnsafeURL(f"Could not resolve URL host: {hostname}")

    blocked = [str(ip) for ip in addresses if _blocked_ip(ip)]
    if blocked:
        raise UnsafeURL(
            "Refusing to fetch URL because its host resolves to a non-public address: "
            + ", ".join(blocked)
        )


def validate_public_http_url(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise UnsafeURL("Only http:// and https:// URLs can be fetched.")
    if not parsed.hostname:
        raise UnsafeURL("URL must include a hostname.")
    if parsed.username or parsed.password:
        raise UnsafeURL("URLs with embedded credentials are not allowed.")
    _validate_public_host(parsed.hostname)
    return parsed.geturl()


def fetch_url_markdown(url: str, *, timeout: float = 25.0, max_redirects: int = 5) -> str:
    """Fetch a public HTTP(S) page and convert it to Markdown.

    The fetcher validates the original URL and every redirect target before
    requesting it, which keeps WebUI examples from acting as SSRF probes for
    localhost, link-local, private, reserved, or non-HTTP(S) destinations.
    """
    current_url = validate_public_http_url(url)
    session = requests.Session()
    session.trust_env = False

    for _ in range(max_redirects + 1):
        response = session.get(
            current_url,
            timeout=timeout,
            headers=browser_headers_for(current_url),
            allow_redirects=False,
        )

        if 300 <= response.status_code < 400 and response.headers.get("Location"):
            current_url = validate_public_http_url(
                urljoin(current_url, response.headers["Location"])
            )
            continue

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 403:
                raise ValueError(
                    "The site returned HTTP 403 Forbidden. It is likely blocking "
                    "automated fetches. Open the page in a browser, save it as HTML "
                    "or PDF, then use the local upload/file option."
                ) from exc
            raise
        return html_to_markdown(response.text)

    raise UnsafeURL(f"Too many redirects while fetching URL: {url}")


def load_one_source(kind: str, value: str, index: int, *, max_chars: int) -> str:
    label = f"Source {index}: {kind} - {value}"
    if kind == "PDF":
        text = extract_pdf_text_from_path(value)
        if not text:
            raise ValueError(f"No text could be extracted from the PDF: {value}")
        return f"{label}\n\n{text[:max_chars]}"

    if kind == "HTML":
        html = Path(value).read_text(errors="replace")
        text = html_to_markdown(html)
        return f"{label}\n\n{text[:max_chars]}"

    if kind == "TEXT":
        text = Path(value).read_text(errors="replace")
        return f"{label}\n\n{text[:max_chars]}"

    if kind == "URL":
        text = fetch_url_markdown(value)
        return f"{label}\n\n{text[:max_chars]}"

    raise ValueError(f"Unsupported source kind: {kind}")


def load_sources(
    pdf_paths: list[str] | None,
    urls: list[str] | None,
    html_paths: list[str] | None,
    text_paths: list[str] | None,
    *,
    max_chars: int,
) -> str:
    source_specs: list[tuple[str, str]] = []
    source_specs.extend(("PDF", path) for path in pdf_paths or [])
    source_specs.extend(("URL", item) for item in urls or [])
    source_specs.extend(("HTML", path) for path in html_paths or [])
    source_specs.extend(("TEXT", path) for path in text_paths or [])

    if not source_specs:
        raise ValueError("Pass --pdf, --url, --html, or --text at least once.")

    sections = [
        load_one_source(kind, value, index, max_chars=max_chars)
        for index, (kind, value) in enumerate(source_specs, start=1)
    ]
    return "\n\n---\n\n".join(sections)


def load_source(
    pdf_path: str | None,
    url: str | None,
    html_path: str | None,
    text_path: str | None,
    *,
    max_chars: int,
) -> str:
    """Backward-compatible single-source loader."""
    if pdf_path:
        return load_one_source("PDF", pdf_path, 1, max_chars=max_chars).replace(
            f"Source 1: PDF - {pdf_path}", f"Source: {pdf_path}", 1
        )
    if html_path:
        return load_one_source("HTML", html_path, 1, max_chars=max_chars).replace(
            f"Source 1: HTML - {html_path}", f"Source: {html_path}", 1
        )
    if text_path:
        return load_one_source("TEXT", text_path, 1, max_chars=max_chars).replace(
            f"Source 1: TEXT - {text_path}", f"Source: {text_path}", 1
        )
    if url:
        return load_one_source("URL", url, 1, max_chars=max_chars).replace(
            f"Source 1: URL - {url}", f"Source: {url}", 1
        )
    raise ValueError("Pass --pdf, --url, --html, or --text.")
