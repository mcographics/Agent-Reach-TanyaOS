"""Read-only, bounded internet actions for the TanyaOS capability adapter.

Upstream Agent Reach remains the installer/doctor. This fork adds structured
reads without shell strings, account cookies, cloud inference, or installation.
Fetched text is external evidence, never an instruction or verified fact.
"""
from __future__ import annotations

import argparse
import http.client
import importlib.util
import ipaddress
import json
import socket
import ssl
import time
import sys
from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin, urlsplit

from agent_reach.utils.url import normalize_public_http_url

MAX_BYTES = 2 * 1024 * 1024
MAX_TEXT = 20000


class ReachError(RuntimeError):
    """A bounded, user-visible read failure."""


def _resolve_public(host: str, port: int) -> str:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    except OSError:
        raise ReachError("The public host could not be resolved.") from None
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ReachError("Private, local and reserved network addresses are not allowed.")
    return sorted(addresses)[0]


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, address, port, timeout):
        super().__init__(host, port=port, timeout=timeout)
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class _PinnedHTTPS(_PinnedHTTP):
    def connect(self):
        super().connect()
        try:
            self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)
        except Exception:
            self.close()
            raise


def fetch_public(url: str) -> tuple[bytes, str, str]:
    """GET public content; validate every redirect and pin DNS to the connection."""
    started = time.monotonic()
    for _attempt in range(5):
        url = normalize_public_http_url(url)
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in {80, 443}:
            raise ReachError("Only standard public web ports are supported.")
        remaining = 30 - (time.monotonic() - started)
        if remaining <= 0:
            raise ReachError("The public read exceeded its time budget.")
        address = _resolve_public(parsed.hostname, port)
        connection_type = _PinnedHTTPS if parsed.scheme == "https" else _PinnedHTTP
        connection = connection_type(parsed.hostname, address, port, min(10, remaining))
        try:
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            connection.request("GET", path, headers={
                "User-Agent": "TanyaOS-AgentReach/1.0 (public read-only research)",
                "Accept": "text/html,application/json,application/xml,text/plain,*/*;q=0.1",
                "Accept-Encoding": "identity",
            })
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                if not location:
                    raise ReachError("The site returned a redirect without a destination.")
                url = urljoin(url, location)
                continue
            if response.status >= 400:
                raise ReachError(f"The public site returned HTTP {response.status}.")
            size = response.getheader("Content-Length")
            if size and int(size) > MAX_BYTES:
                raise ReachError("The response exceeds the 2 MiB read limit.")
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ReachError("The response exceeds the 2 MiB read limit.")
            return body, response.getheader("Content-Type", "text/plain"), url
        finally:
            connection.close()
    raise ReachError("The site exceeded the redirect limit.")


class _ReadableHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.title = []
        self.ignored = 0
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript", "svg"}:
            self.ignored += 1
        if tag == "title":
            self.in_title = True
        if tag in {"p", "div", "br", "li", "h1", "h2", "h3", "article", "section"}:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript", "svg"}:
            self.ignored = max(0, self.ignored - 1)
        if tag == "title":
            self.in_title = False
        if tag in {"p", "div", "li", "h1", "h2", "h3", "article", "section"}:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.ignored:
            self.parts.append(data)
            if self.in_title:
                self.title.append(data)


def _text(body: bytes, content_type: str) -> str:
    # Public readers never interpret fetched markup as executable content.
    encoding = "utf-8"
    if "charset=" in content_type:
        encoding = content_type.split("charset=", 1)[1].split(";", 1)[0].strip(' "')
    try:
        return body.decode(encoding, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _evidence(url: str, provider: str, **fields) -> dict:
    return {"url": url, "provider": provider, "retrieved_at": time.time(),
            "trust": "external_untrusted", "instruction_authority": False, **fields}


def read_web(url: str) -> dict:
    body, mime, final_url = fetch_public(url)
    if not any(kind in mime.lower() for kind in ("text/", "html", "xml", "json")):
        raise ReachError("This is not a text page. Use Tanya's document or image reader for binary files.")
    text = _text(body, mime)
    title = ""
    if "html" in mime.lower():
        parser = _ReadableHTML()
        parser.feed(text)
        title = " ".join(parser.title).strip()[:300]
        text = "\n".join(" ".join(line.split()) for line in "".join(parser.parts).splitlines() if line.strip())
    return _evidence(final_url, "local-http-html", title=title, text=text[:MAX_TEXT],
                     truncated=len(text) > MAX_TEXT)


def read_rss(url: str, limit: int = 10) -> dict:
    import feedparser
    limit = _limit(limit)
    body, _mime, final_url = fetch_public(url)
    feed = feedparser.parse(body)
    if not feed.get("version"):
        raise ReachError("The public response is not a recognized RSS or Atom feed.")
    entries = [{"title": str(entry.get("title", ""))[:500],
                "url": str(entry.get("link", ""))[:2000],
                "published": str(entry.get("published", entry.get("updated", "")))[:100],
                "summary": str(entry.get("summary", ""))[:3000]}
               for entry in feed.entries[:limit]]
    return _evidence(final_url, "feedparser", title=str(feed.feed.get("title", ""))[:500], entries=entries)


def _limit(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 20:
        raise ReachError("Result limit must be an integer from 1 to 20.")
    return value


def web_search(query: str, limit: int = 5) -> dict:
    query = str(query or "").strip()
    if not query or len(query) > 500:
        raise ReachError("Provide a web search query of 1 to 500 characters.")
    url = "https://www.bing.com/search?" + urlencode({"q": query, "format": "rss"})
    data = read_rss(url, _limit(limit))
    data.update(provider="bing-public-search-rss", query=query)
    return data


def _github_json(path: str) -> dict:
    body, _mime, _url = fetch_public("https://api.github.com/" + path)
    return json.loads(body)


def github_repo(repo: str) -> dict:
    import re
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo or ""):
        raise ReachError("Use a public repository name in owner/repository form.")
    data = _github_json("repos/" + repo)
    if data.get("private"):
        raise ReachError("This adapter reads public repositories only.")
    return _evidence(data["html_url"], "github-public-rest", repository=data["full_name"],
                     description=data.get("description"), stars=data.get("stargazers_count"),
                     language=data.get("language"), default_branch=data.get("default_branch"),
                     license=(data.get("license") or {}).get("spdx_id"),
                     updated_at=data.get("updated_at"), topics=data.get("topics", []))


def github_search(query: str, limit: int = 5) -> dict:
    query = str(query or "").strip()
    if not query or len(query) > 500:
        raise ReachError("Provide a public GitHub search query of 1 to 500 characters.")
    data = _github_json("search/repositories?" + urlencode({"q": query, "per_page": _limit(limit)}))
    entries = [{"repository": item["full_name"], "url": item["html_url"],
                "description": item.get("description"), "stars": item.get("stargazers_count")}
               for item in data.get("items", [])]
    return _evidence("https://github.com/search?" + urlencode({"q": query, "type": "repositories"}),
                     "github-public-rest", query=query, entries=entries)


def youtube(url: str, language: str = "en") -> dict:
    from yt_dlp import YoutubeDL
    url = normalize_public_http_url(url)
    parsed = urlsplit(url)
    if parsed.hostname not in {"youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be"} or parsed.port not in {None, 443}:
        raise ReachError("Provide a public YouTube video URL.")
    import re
    if not re.fullmatch(r"[a-zA-Z0-9-]{2,20}", language):
        raise ReachError("Provide a caption language such as en or en-US.")

    class QuietLogger:
        def debug(self, message): pass
        def warning(self, message): pass
        def error(self, message): pass

    with YoutubeDL({"quiet": True, "logger": QuietLogger(), "skip_download": True,
                    "noplaylist": True, "socket_timeout": 10, "retries": 0,
                    "extractor_retries": 0, "ignoreerrors": False}) as reader:
        info = reader.extract_info(url, download=False)
    if not info or info.get("_type") in {"playlist", "multi_video"}:
        raise ReachError("Only a single public video is supported.")
    formats = (info.get("subtitles") or {}).get(language) or (info.get("automatic_captions") or {}).get(language) or []
    transcript = ""
    chosen = next((item for item in formats if item.get("ext") == "json3"), None)
    if chosen:
        body, _mime, _final = fetch_public(chosen["url"])
        captions = json.loads(body)
        transcript = "\n".join("".join(seg.get("utf8", "") for seg in event.get("segs", []))
                               for event in captions.get("events", []))[:MAX_TEXT]
    return _evidence(info.get("webpage_url", url), "yt-dlp", title=info.get("title"),
                     description=str(info.get("description", ""))[:4000], duration=info.get("duration"),
                     transcript=transcript, caption_language=language,
                     caption_status="available" if transcript else "unavailable",
                     media_downloaded=False)


def status() -> dict:
    return {"adapter": "tanyaos-read-only-v1", "cloud_inference": False,
            "credentials_used": False, "automatic_installation": False,
            "channels": {"web": {"ready": True, "provider": "local HTTP + HTML parser"},
                         "web_search": {"ready": importlib.util.find_spec("feedparser") is not None, "provider": "public Bing search RSS"},
                         "github": {"ready": True, "provider": "public GitHub REST (no authentication)"},
                         "rss": {"ready": importlib.util.find_spec("feedparser") is not None},
                         "youtube": {"ready": importlib.util.find_spec("yt_dlp") is not None}},
            "live_verified": False,
            "optional_channels": "Upstream social, browser-session and hosted-search channels are not enabled by this adapter."}


def execute(action: str, payload: dict | None = None) -> dict:
    payload = payload or {}
    actions = {"status": lambda: status(), "web": lambda: read_web(payload.get("url")),
               "web_search": lambda: web_search(payload.get("query"), payload.get("limit", 5)),
               "rss": lambda: read_rss(payload.get("url"), payload.get("limit", 10)),
               "github_repo": lambda: github_repo(payload.get("repository")),
               "github_search": lambda: github_search(payload.get("query"), payload.get("limit", 5)),
               "youtube": lambda: youtube(payload.get("url"), payload.get("language", "en"))}
    if action not in actions:
        raise ReachError("Unknown read-only Agent Reach action.")
    return actions[action]()


def main():
    parser = argparse.ArgumentParser(description="Bounded public internet reads for TanyaOS")
    parser.add_argument("action", choices=["status", "web", "web_search", "rss", "github_repo", "github_search", "youtube"])
    parser.add_argument("--url")
    parser.add_argument("--repository")
    parser.add_argument("--query")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--language", default="en")
    parser.add_argument("--request-json", action="store_true", help="Read a bounded payload from stdin")
    args = vars(parser.parse_args())
    action = args.pop("action")
    try:
        if args.pop("request_json"):
            request = sys.stdin.read(65537)
            if len(request) > 65536:
                raise ReachError("Request exceeds the input limit.")
            args = json.loads(request)
            if not isinstance(args, dict):
                raise ReachError("Request must be a JSON object.")
        print(json.dumps({"ok": True, "data": execute(action, args)}, ensure_ascii=False))
    except Exception as exc:
        error = str(exc) if isinstance(exc, (ReachError, ValueError)) else f"Public read failed ({type(exc).__name__})."
        print(json.dumps({"ok": False, "error": error}, ensure_ascii=False))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
