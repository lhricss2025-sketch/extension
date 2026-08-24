from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import sqlite3
import tempfile
import time
import uuid
import zipfile
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urljoin, urlsplit

import httpx
import jsbeautifier
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, InputFile, KeyboardButton, ReplyKeyboardMarkup, ReplyKeyboardRemove, Update
from telegram.constants import ChatAction
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

LOG = logging.getLogger("senzo_extension_bot")

BRAND = "SENZO EXTENSION INSPECTOR"
WATERMARK = "@Senzo268"
BOT_USERNAME = "@SenzoExtension_Bot"
WHATSAPP_URL = "https://whatsapp.com/channel/0029VbBdHQnKWEKtmxS7XZ09"
USER_AGENT = "SenzoExtensionBot/2.0 (+public-package-inspector)"
DEFAULT_MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_UNCOMPRESSED_BYTES = 150 * 1024 * 1024
DEFAULT_MAX_FILES = 2500
DEFAULT_MAX_FILE_BYTES = 25 * 1024 * 1024
REDIRECT_LIMIT = 5
ARCHIVE_SUFFIXES = (".crx", ".xpi", ".nex", ".zip")
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?![\w.-])", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SECRET_PATTERNS = [
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Stripe-like secret", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{12,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("assignment secret", re.compile(r"(?i)\b(api[_-]?key|secret|access[_-]?token|password|passwd|private[_-]?key)\b\s*[:=]\s*['\"]?([^\s'\";,]{6,})")),
]
REMOTE_CODE_RE = re.compile(r"(?i)(eval\s*\(|new\s+Function\s*\(|import\s*\(\s*['\"]https?://|document\.write\s*\()")
OBFUSCATION_RE = re.compile(r"(?i)(atob\s*\(|fromCharCode\s*\(|constructor\s*\[\s*['\"]constructor)")


class BotError(Exception):
    """Expected user-facing error."""


@dataclass(frozen=True)
class ResolvedSource:
    input_url: str
    canonical_url: str
    download_url: str
    store: str
    suggested_name: str


@dataclass
class DownloadedPackage:
    archive_path: Path
    archive_sha256: str
    archive_size: int
    final_url: str
    content_type: str


@dataclass
class JobResult:
    scan_id: str
    source_zip: Path
    report_path: Path
    ioc_path: Path
    secrets_path: Path
    report: dict[str, Any]


class Settings:
    def __init__(self) -> None:
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        if not token:
            raise RuntimeError("TELEGRAM_BOT_TOKEN is required")
        self.token = token
        self.db_path = Path(os.getenv("BOT_DB_PATH", "./data/senzo.sqlite3"))
        self.result_root = Path(os.getenv("RESULT_ROOT", "./data/results"))
        self.max_download_bytes = int(os.getenv("MAX_DOWNLOAD_BYTES", DEFAULT_MAX_DOWNLOAD_BYTES))
        self.max_uncompressed_bytes = int(os.getenv("MAX_UNCOMPRESSED_BYTES", DEFAULT_MAX_UNCOMPRESSED_BYTES))
        self.max_files = int(os.getenv("MAX_FILES", DEFAULT_MAX_FILES))
        self.max_file_bytes = int(os.getenv("MAX_FILE_BYTES", DEFAULT_MAX_FILE_BYTES))
        self.rate_limit_per_hour = int(os.getenv("RATE_LIMIT_PER_HOUR", "8"))
        self.parallel_jobs = int(os.getenv("PARALLEL_JOBS", "2"))
        self.request_timeout = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "30"))
        self.admin_ids = {int(v.strip()) for v in os.getenv("ADMIN_USER_IDS", "").split(",") if v.strip().isdigit()}
        extra_hosts = {v.strip().lower() for v in os.getenv("EXTRA_ALLOWED_DOWNLOAD_HOSTS", "").split(",") if v.strip()}
        self.allowed_hosts = ALLOWED_HOSTS | extra_hosts
        self.force_join_channels = parse_force_join_channels(os.getenv("FORCE_JOIN_CHANNELS", ""))
        self.result_root.mkdir(parents=True, exist_ok=True)


ALLOWED_HOSTS = {
    "chrome.google.com", "chromewebstore.google.com", "clients2.google.com", "clients2.googleusercontent.com",
    "microsoftedge.microsoft.com", "edge.microsoft.com", "delivery.mp.microsoft.com",
    "msedgeextensions.f.tlu.dl.delivery.mp.microsoft.com", "addons.opera.com", "addons-extensions.operacdn.com",
    "addons.mozilla.org", "addons.cdn.mozilla.net", "addons.allizom.org", "addons-dev.allizom.org",
    "addons-dev-cdn.allizom.org", "addons.thunderbird.net", "addons-stage.thunderbird.net",
}


def parse_force_join_channels(raw: str) -> list[dict[str, str]]:
    channels: list[dict[str, str]] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "|" in item:
            chat_id, link = [part.strip() for part in item.split("|", 1)]
        else:
            chat_id = item
            link = f"https://t.me/{item.lstrip('@')}"
        channels.append({"chat_id": chat_id, "link": link})
    return channels


def host_allowed(host: str, allowed_hosts: set[str]) -> bool:
    host = host.lower().rstrip(".")
    return host in allowed_hosts or any(host.endswith("." + parent) for parent in allowed_hosts)


def reject_private_ip(host: str) -> None:
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise BotError(f"Could not resolve download host: {host}") from exc
    for _, _, _, _, sockaddr in addresses:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise BotError("The download host resolves to a private or unsafe network address.")


def clean_url(url: str) -> str:
    return url.rstrip(".,;:!?)\"]}'")


def validate_public_url(url: str, settings: Settings) -> tuple[str, str]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise BotError("Only absolute http(s) URLs are accepted.")
    host = parsed.hostname.lower().rstrip(".")
    if not host_allowed(host, settings.allowed_hosts):
        raise BotError("For safety, this bot only downloads from supported public extension stores/CDNs.")
    reject_private_ip(host)
    return parsed.scheme, host


def resolve_extension_url(raw_url: str, settings: Settings) -> ResolvedSource:
    url = clean_url(raw_url.strip())
    validate_public_url(url, settings)
    parsed = urlsplit(url)
    host = parsed.hostname.lower().rstrip(".")
    path = unquote(parsed.path)
    if host in {"chrome.google.com", "chromewebstore.google.com"}:
        match = re.search(r"(?:/webstore/detail|/detail)/[^/]+/([a-z]{32})(?:/|$)", path)
        if not match:
            raise BotError("That Chrome Web Store URL does not contain a valid 32-character extension ID.")
        ext_id = match.group(1)
        download = ("https://clients2.google.com/service/update2/crx?response=redirect"
                    "&os=linux&arch=x86-64&os_arch=x86-64&nacl_arch=x86-64"
                    "&prod=chromiumcrx&prodchannel=unknown&prodversion=9999.0.9999.0"
                    f"&acceptformat=crx2,crx3&x=id%3D{ext_id}%26uc")
        return ResolvedSource(url, f"https://chromewebstore.google.com/detail/{ext_id}", download, "Chrome Web Store", ext_id)
    if host == "microsoftedge.microsoft.com":
        match = re.search(r"/addons/(?:detail/)?(?:[^/]+/)?([a-z]{32})(?:/|$)", path)
        if not match:
            raise BotError("That Edge Add-ons URL does not contain a valid 32-character extension ID.")
        ext_id = match.group(1)
        download = ("https://edge.microsoft.com/extensionwebstorebase/v1/crx?response=redirect"
                    f"&x=id%3D{ext_id}%26installsource%3Dondemand%26uc")
        return ResolvedSource(url, f"https://microsoftedge.microsoft.com/addons/detail/{ext_id}", download, "Microsoft Edge Add-ons", ext_id)
    if host in {"addons.opera.com", "addons-extensions.operacdn.com"}:
        match = re.search(r"/extensions/(?:details|download)/([^/?#]+)", path, re.IGNORECASE)
        if not match:
            raise BotError("That Opera Add-ons URL does not contain a recognizable extension slug.")
        slug = match.group(1)
        return ResolvedSource(url, f"https://addons.opera.com/extensions/details/{slug}", f"https://addons.opera.com/extensions/download/{slug}/", "Opera Add-ons", slug)
    if host in {"addons.mozilla.org", "addons.allizom.org", "addons-dev.allizom.org", "addons.thunderbird.net", "addons-stage.thunderbird.net"}:
        match = re.search(r"/(?:firefox|thunderbird)/addon/([^/?#]+)", path, re.IGNORECASE) or re.search(r"/(?:addon|review)/([^/?#]+)", path, re.IGNORECASE)
        if not match:
            raise BotError("That Mozilla-family URL does not contain a recognizable add-on slug.")
        slug = match.group(1)
        product = "thunderbird" if "thunderbird" in host else "firefox"
        return ResolvedSource(url, f"https://{host}/{product}/addon/{slug}", f"https://{host}/{product}/downloads/latest/{slug}/{slug}.xpi", "Thunderbird Add-ons" if product == "thunderbird" else "Mozilla Add-ons", slug)
    if parsed.path.lower().endswith(ARCHIVE_SUFFIXES):
        return ResolvedSource(url, url, url, "Direct supported-store archive", Path(parsed.path).name or "extension.zip")
    raise BotError("Unsupported URL. Use a supported extension-store listing or direct archive URL.")


async def fetch_package(source: ResolvedSource, settings: Settings, destination: Path) -> DownloadedPackage:
    timeout = httpx.Timeout(settings.request_timeout, connect=settings.request_timeout)
    current_url = source.download_url
    async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent": USER_AGENT}, follow_redirects=False) as client:
        for _ in range(REDIRECT_LIMIT + 1):
            validate_public_url(current_url, settings)
            try:
                async with client.stream("GET", current_url) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not location:
                            raise BotError("The store returned a redirect without a destination.")
                        current_url = urljoin(current_url, location)
                        continue
                    if response.status_code != 200:
                        raise BotError(f"The public package endpoint returned HTTP {response.status_code}.")
                    length = response.headers.get("content-length")
                    if length and int(length) > settings.max_download_bytes:
                        raise BotError("The package is larger than the configured download limit.")
                    digest = hashlib.sha256()
                    total = 0
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with destination.open("wb") as output:
                        async for chunk in response.aiter_bytes(64 * 1024):
                            total += len(chunk)
                            if total > settings.max_download_bytes:
                                raise BotError("The package exceeded the configured download limit.")
                            digest.update(chunk)
                            output.write(chunk)
                    return DownloadedPackage(destination, digest.hexdigest(), total, str(response.url), response.headers.get("content-type", ""))
            except httpx.HTTPError as exc:
                raise BotError(f"Network error while downloading the public package: {exc}") from exc
        raise BotError("Too many redirects from the extension store.")


def zip_payload_offset(archive_path: Path) -> int:
    with archive_path.open("rb") as stream:
        header = stream.read(16)
    if header[:4] != b"Cr24":
        return 0
    if len(header) < 12:
        raise BotError("The CRX header is truncated.")
    version = int.from_bytes(header[4:8], "little")
    if version == 2:
        if len(header) < 16:
            raise BotError("The CRX2 header is truncated.")
        return 16 + int.from_bytes(header[8:12], "little") + int.from_bytes(header[12:16], "little")
    if version == 3:
        return 12 + int.from_bytes(header[8:12], "little")
    raise BotError(f"Unsupported CRX version: {version}.")


def safe_extract(archive_path: Path, output_dir: Path, settings: Settings) -> tuple[int, int, list[str]]:
    with archive_path.open("rb") as stream:
        stream.seek(zip_payload_offset(archive_path))
        zip_bytes = stream.read()
    if not zip_bytes.startswith(b"PK"):
        raise BotError("The downloaded file is not a recognized CRX/XPI/NEX/ZIP archive.")
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = output_dir / "payload.zip"
    payload.write_bytes(zip_bytes)
    root = (output_dir / "source").resolve()
    root.mkdir(parents=True, exist_ok=True)
    extracted_bytes = 0
    file_count = 0
    warnings: list[str] = []
    try:
        with zipfile.ZipFile(payload) as archive:
            infos = archive.infolist()
            if len(infos) > settings.max_files:
                raise BotError(f"The archive contains more than {settings.max_files} entries.")
            for info in infos:
                name = info.filename.replace("\\", "/")
                target = (root / name).resolve()
                if not str(target).startswith(str(root) + os.sep) and target != root:
                    raise BotError("The archive contains an unsafe path traversal entry.")
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise BotError("The archive contains a symbolic link, which is not accepted.")
                if info.file_size > settings.max_file_bytes:
                    raise BotError(f"Archive member is too large: {name}")
                extracted_bytes += info.file_size
                if extracted_bytes > settings.max_uncompressed_bytes:
                    raise BotError("The archive exceeds the configured uncompressed-size limit.")
                if not info.is_dir():
                    file_count += 1
                if info.compress_size and info.file_size / max(info.compress_size, 1) > 100:
                    warnings.append(f"High compression ratio: {name}")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as input_stream, target.open("wb") as output_stream:
                        shutil.copyfileobj(input_stream, output_stream, length=64 * 1024)
    except zipfile.BadZipFile as exc:
        raise BotError("The downloaded file is not a valid ZIP-based extension package.") from exc
    finally:
        payload.unlink(missing_ok=True)
    return file_count, extracted_bytes, sorted(set(warnings))


def iter_files(root: Path) -> Iterable[Path]:
    yield from (path for path in root.rglob("*") if path.is_file())


def read_json_file(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        return data if isinstance(data, dict) else None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def line_number(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def masked(value: str) -> str:
    value = value.strip().strip("'\"")
    if len(value) <= 6:
        return "•" * len(value)
    return value[:3] + "••••" + value[-2:]


def extract_iocs_and_secrets(source_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    urls: list[dict[str, Any]] = []
    domains: list[dict[str, Any]] = []
    ips: list[dict[str, Any]] = []
    emails: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []
    code_suffixes = {".js", ".mjs", ".ts", ".html", ".json", ".css", ".txt", ".xml"}
    for path in iter_files(source_root):
        if path.suffix.lower() not in code_suffixes or path.stat().st_size > 5 * 1024 * 1024:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = str(path.relative_to(source_root))
        for match in URL_RE.finditer(text):
            value = clean_url(match.group(0))
            if not value.lower().startswith(("http://", "https://")):
                continue
            urls.append({"value": value, "file": rel, "line": line_number(text, match.start())})
        for match in DOMAIN_RE.finditer(text):
            value = match.group(0).lower().rstrip(".")
            if value not in {"example.com", "localhost"}:
                domains.append({"value": value, "file": rel, "line": line_number(text, match.start())})
        for match in IP_RE.finditer(text):
            try:
                ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            ips.append({"value": match.group(0), "file": rel, "line": line_number(text, match.start())})
        for match in EMAIL_RE.finditer(text):
            emails.append({"value": match.group(0), "file": rel, "line": line_number(text, match.start())})
        for label, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                raw = match.group(0)
                value = match.group(2) if match.lastindex and match.lastindex >= 2 else raw
                secrets.append({"type": label, "file": rel, "line": line_number(text, match.start()), "masked_value": masked(value), "severity": "high" if "private" in label or "secret" in label or "token" in label else "medium"})
    def unique(items: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
        seen: set[tuple[Any, ...]] = set()
        result = []
        for item in items:
            key = tuple(item.get(k) for k in keys)
            if key not in seen:
                seen.add(key)
                result.append(item)
        return sorted(result, key=lambda x: (str(x.get("file", "")), int(x.get("line", 0))))
    return (
        {"urls": unique(urls, ("value", "file", "line")), "domains": unique(domains, ("value", "file", "line")), "ips": unique(ips, ("value", "file", "line")), "emails": unique(emails, ("value", "file", "line"))},
        {"findings": unique(secrets, ("type", "file", "line", "masked_value"))},
    )


def beautify_html(text: str) -> str:
    tokens = re.split(r"(<[^>]+>)", text)
    depth = 0
    lines: list[str] = []
    void = {"meta", "link", "img", "input", "br", "hr", "source"}
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        if token.startswith("</"):
            depth = max(depth - 1, 0)
        lines.append("  " * depth + token)
        if token.startswith("<") and not token.startswith(("</", "<!", "<?")):
            tag = re.match(r"<\s*([\w-]+)", token)
            if tag and tag.group(1).lower() not in void and not token.rstrip().endswith("/>"):
                depth += 1
    return "\n".join(lines) + "\n"


def beautify_css(text: str) -> str:
    text = re.sub(r"\s*{\s*", " {\n", text)
    text = re.sub(r"\s*}\s*", "\n}\n", text)
    text = re.sub(r";\s*", ";\n", text)
    depth = 0
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("}"):
            depth = max(depth - 1, 0)
        lines.append("  " * depth + line)
        if line.endswith("{"):
            depth += 1
    return "\n".join(lines) + "\n"


def beautify_file(path: Path, relative: Path) -> str | None:
    if path.stat().st_size > 2 * 1024 * 1024:
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False) + "\n"
        except json.JSONDecodeError:
            return None
    if suffix in {".js", ".mjs", ".ts"}:
        try:
            return jsbeautifier.beautify(text) + "\n"
        except Exception:
            return None
    if suffix == ".html":
        return beautify_html(text)
    if suffix == ".css":
        return beautify_css(text)
    return None


def risk_level(score: int) -> str:
    return "high" if score >= 8 else "medium" if score >= 4 else "low"


def resolve_manifest_name(source_root: Path, manifest: dict[str, Any] | None, fallback: str) -> str:
    name = str((manifest or {}).get("name") or fallback)
    match = re.fullmatch(r"__MSG_([^_]+)__", name)
    if not match:
        return name
    key = match.group(1).lower()
    for messages_path in source_root.glob("_locales/*/messages.json"):
        messages = read_json_file(messages_path) or {}
        for candidate, value in messages.items():
            if str(candidate).lower() == key and isinstance(value, dict) and value.get("message"):
                return str(value["message"])
    return name


def analyze_source(source_root: Path, downloaded: DownloadedPackage, resolved: ResolvedSource, file_count: int, expanded: int, warnings: list[str]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    files = sorted(iter_files(source_root))
    manifest_path = next((p for p in files if p.name.lower() == "manifest.json" and p.parent == source_root), None)
    manifest = read_json_file(manifest_path) if manifest_path else None
    if manifest_path and manifest is None:
        warnings.append("manifest.json exists but could not be parsed as UTF-8 JSON.")
    display_name = resolve_manifest_name(source_root, manifest, resolved.suggested_name)
    permissions = [str(v) for v in (manifest or {}).get("permissions", []) if isinstance(v, str)]
    hosts = [str(v) for v in (manifest or {}).get("host_permissions", []) if isinstance(v, str)]
    matches: list[str] = []
    for script in (manifest or {}).get("content_scripts", []) if isinstance((manifest or {}).get("content_scripts", []), list) else []:
        if isinstance(script, dict):
            matches.extend(str(v) for v in script.get("matches", []) if isinstance(v, str))
    ext_counts: Counter[str] = Counter()
    file_hashes: list[dict[str, Any]] = []
    static: dict[str, list[str]] = defaultdict(list)
    score = 0
    for path in files:
        raw = path.read_bytes()
        suffix = path.suffix.lower() or "[no extension]"
        ext_counts[suffix] += 1
        file_hashes.append({"path": str(path.relative_to(source_root)), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        if len(raw) <= 2 * 1024 * 1024 and suffix in {".js", ".mjs", ".ts", ".html", ".json", ".css"}:
            text = raw.decode("utf-8", errors="replace")
            if REMOTE_CODE_RE.search(text):
                static["dynamic_or_remote_code"].append(str(path.relative_to(source_root)))
            if OBFUSCATION_RE.search(text):
                static["obfuscation_indicators"].append(str(path.relative_to(source_root)))
    high = {"<all_urls>", "debugger", "nativeMessaging", "webRequestBlocking", "management", "proxy"}
    medium = {"webRequest", "cookies", "downloads", "clipboardRead", "clipboardWrite", "tabCapture", "history", "bookmarks"}
    for permission in permissions + hosts:
        score += 3 if permission in high else 2 if permission in medium or permission == "*://*/*" else 0
    if static["dynamic_or_remote_code"]:
        score += 2
    if static["obfuscation_indicators"]:
        score += 1
    if not manifest:
        warnings.append("No root manifest.json was found.")
        score += 1
    iocs, secrets = extract_iocs_and_secrets(source_root)
    report = {
        "brand": BRAND, "watermark": WATERMARK, "bot_username": BOT_USERNAME,
        "input_url": resolved.input_url, "canonical_url": resolved.canonical_url, "download_url": resolved.download_url,
        "final_url": downloaded.final_url, "store": resolved.store, "suggested_name": resolved.suggested_name, "extension_name": display_name,
        "archive": {"bytes": downloaded.archive_size, "sha256": downloaded.archive_sha256, "content_type": downloaded.content_type},
        "package": {"file_count": file_count, "uncompressed_bytes": expanded, "extensions": dict(ext_counts)},
        "manifest": manifest, "permissions": permissions, "host_permissions": hosts, "content_script_matches": matches,
        "static_indicators": {k: sorted(set(v)) for k, v in static.items()},
        "ioc_summary": {k: len(v) for k, v in iocs.items()}, "ioc_findings": iocs, "secrets_count": len(secrets["findings"]), "secret_findings": secrets["findings"],
        "risk": {"score": score, "level": risk_level(score), "note": "Heuristic static analysis only; not a malware verdict."},
        "warnings": sorted(set(warnings)), "files": file_hashes,
    }
    return report, iocs, secrets


def make_watermark(bot_name: str = BOT_USERNAME) -> str:
    return ("╭───〔 SENZO EXTENSION INSPECTOR 〕───╮\n"
            f"│ Fetched By {WATERMARK}\n"
            f"│ Bot Name: {bot_name}\n"
            "│\n"
            "│ Join Us → WhatsApp Channel\n"
            f"│ {WHATSAPP_URL}\n"
            "╰────────────────────────────────────╯\n")


def make_brand_readme(report: dict[str, Any]) -> str:
    return (f"{BRAND}\n\nFetched By {WATERMARK}\nBot Name: {BOT_USERNAME}\n\n"
            f"Extension: {report.get('extension_name', report.get('suggested_name', 'unknown'))}\n"
            f"Version: {(report.get('manifest') or {}).get('version', 'unknown')}\n"
            f"Archive SHA-256: {report['archive']['sha256']}\n"
            "\nThe original public package is preserved in original/. Beautified copies are in beautified/. "
            "Reports are advisory static analysis and must not be treated as a malware verdict.\n\n"
            f"Join Us → WhatsApp Channel\n{WHATSAPP_URL}\n")


def write_ioc_report(iocs: dict[str, Any], path: Path) -> None:
    lines = [f"{BRAND} — IOC & DOMAIN INTELLIGENCE", f"Fetched By {WATERMARK}", ""]
    for label in ("urls", "domains", "ips", "emails"):
        lines.append(f"{label.upper()} ({len(iocs[label])})")
        for item in iocs[label]:
            lines.append(f"- {item['value']} | {item['file']}:{item['line']}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_secrets_report(secrets: dict[str, Any], path: Path) -> None:
    lines = [f"{BRAND} — SECRETS SCAN", f"Fetched By {WATERMARK}", "", "Values are masked for safety.", ""]
    for item in secrets["findings"]:
        lines.append(f"- {item['type']} | {item['severity'].upper()} | {item['masked_value']} | {item['file']}:{item['line']}")
    if not secrets["findings"]:
        lines.append("No possible secret pattern was detected.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def make_package_zip(package_root: Path, artifact_root: Path, report: dict[str, Any], display_name: str) -> Path:
    safe_name = re.sub(r"[^A-Za-z0-9_. -]+", "_", display_name).strip(" ._") or "Extension"
    archive = artifact_root / f"{safe_name} By {WATERMARK}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        for path in sorted(iter_files(package_root)):
            output.write(path, path.relative_to(package_root))
        output.writestr("SENZO_WATERMARK.txt", make_watermark())
        output.writestr("README_SENZO.txt", make_brand_readme(report))
    return archive


class StatsDB:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = asyncio.Lock()
        with sqlite3.connect(self.path) as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY, username TEXT, first_name TEXT, last_name TEXT,
                language_code TEXT, phone TEXT, country_code TEXT, points INTEGER NOT NULL DEFAULT 0,
                banned INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, last_active INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS points_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, delta INTEGER NOT NULL,
                reason TEXT NOT NULL, related_user_id INTEGER, created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS referrals (
                id INTEGER PRIMARY KEY AUTOINCREMENT, referrer_id INTEGER NOT NULL, referred_id INTEGER UNIQUE NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, rewarded_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, raw_url TEXT NOT NULL, extension_name TEXT,
                version TEXT, canonical_url TEXT, final_url TEXT, archive_sha256 TEXT, source_path TEXT,
                report_path TEXT, ioc_path TEXT, secrets_path TEXT, status TEXT NOT NULL, created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER NOT NULL, action TEXT NOT NULL,
                target_id INTEGER, reason TEXT, created_at INTEGER NOT NULL
            );
            """)
            conn.commit()

    async def upsert_user(self, tg_user: Any, referral_id: int | None = None) -> tuple[bool, bool]:
        now = int(time.time())
        async with self.lock:
            with sqlite3.connect(self.path) as conn:
                exists = conn.execute("SELECT 1 FROM users WHERE user_id=?", (tg_user.id,)).fetchone() is not None
                conn.execute("INSERT INTO users(user_id,username,first_name,last_name,language_code,created_at,last_active) VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,first_name=excluded.first_name,last_name=excluded.last_name,language_code=excluded.language_code,last_active=excluded.last_active", (tg_user.id, tg_user.username, tg_user.first_name or "", tg_user.last_name or "", tg_user.language_code, now, now))
                referral_created = False
                if not exists and referral_id and referral_id != tg_user.id and conn.execute("SELECT 1 FROM users WHERE user_id=?", (referral_id,)).fetchone():
                    conn.execute("INSERT OR IGNORE INTO referrals(referrer_id,referred_id,status,created_at) VALUES(?,?,?,?)", (referral_id, tg_user.id, "pending", now))
                    referral_created = True
                conn.commit()
                return exists, referral_created

    async def set_contact(self, user_id: int, phone: str) -> None:
        country = re.sub(r"\D", "", phone)[:3] or None
        async with self.lock:
            with sqlite3.connect(self.path) as conn:
                conn.execute("UPDATE users SET phone=?, country_code=?, last_active=? WHERE user_id=?", (phone, country, int(time.time()), user_id))
                conn.commit()

    async def delete_contact(self, user_id: int) -> None:
        async with self.lock:
            with sqlite3.connect(self.path) as conn:
                conn.execute("UPDATE users SET phone=NULL,country_code=NULL,last_active=? WHERE user_id=?", (int(time.time()), user_id))
                conn.commit()

    async def get_user(self, user_id: int) -> dict[str, Any] | None:
        async with self.lock:
            with sqlite3.connect(self.path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
                return dict(row) if row else None

    async def get_points(self, user_id: int) -> int:
        user = await self.get_user(user_id)
        return int(user["points"]) if user else 0

    async def add_points(self, user_id: int, delta: int, reason: str, related_user_id: int | None = None) -> int:
        async with self.lock:
            with sqlite3.connect(self.path) as conn:
                row = conn.execute("SELECT points FROM users WHERE user_id=?", (user_id,)).fetchone()
                if not row:
                    raise BotError("User is not registered.")
                new_points = max(0, int(row[0]) + delta)
                actual_delta = new_points - int(row[0])
                conn.execute("UPDATE users SET points=?,last_active=? WHERE user_id=?", (new_points, int(time.time()), user_id))
                if actual_delta:
                    conn.execute("INSERT INTO points_ledger(user_id,delta,reason,related_user_id,created_at) VALUES(?,?,?,?,?)", (user_id, actual_delta, reason, related_user_id, int(time.time())))
                conn.commit()
                return new_points

    async def spend_point(self, user_id: int, reason: str) -> int:
        async with self.lock:
            with sqlite3.connect(self.path) as conn:
                row = conn.execute("SELECT points FROM users WHERE user_id=? AND banned=0", (user_id,)).fetchone()
                if not row or int(row[0]) < 1:
                    raise BotError("You need at least 1 point to run this scan.")
                new_points = int(row[0]) - 1
                conn.execute("UPDATE users SET points=?,last_active=? WHERE user_id=?", (new_points, int(time.time()), user_id))
                conn.execute("INSERT INTO points_ledger(user_id,delta,reason,created_at) VALUES(?,?,?,?)", (user_id, -1, reason, int(time.time())))
                conn.commit()
                return new_points

    async def complete_referral(self, referred_id: int) -> tuple[int, bool]:
        async with self.lock:
            with sqlite3.connect(self.path) as conn:
                row = conn.execute("SELECT referrer_id FROM referrals WHERE referred_id=? AND status='pending'", (referred_id,)).fetchone()
                if not row:
                    return 0, False
                referrer_id = int(row[0])
                now = int(time.time())
                conn.execute("UPDATE referrals SET status='rewarded',rewarded_at=? WHERE referred_id=?", (now, referred_id))
                for user_id, related in ((referred_id, referrer_id), (referrer_id, referred_id)):
                    conn.execute("UPDATE users SET points=points+1,last_active=? WHERE user_id=?", (now, user_id))
                    conn.execute("INSERT INTO points_ledger(user_id,delta,reason,related_user_id,created_at) VALUES(?,?,?,?,?)", (user_id, 1, "verified referral reward", related, now))
                conn.commit()
                return referrer_id, True

    async def record_scan(self, scan_id: str, user_id: int, raw_url: str, report: dict[str, Any], result: JobResult, status: str = "ok") -> None:
        manifest = report.get("manifest") or {}
        async with self.lock:
            with sqlite3.connect(self.path) as conn:
                conn.execute("INSERT OR REPLACE INTO scans(scan_id,user_id,raw_url,extension_name,version,canonical_url,final_url,archive_sha256,source_path,report_path,ioc_path,secrets_path,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (scan_id, user_id, raw_url[:2000], str(report.get("extension_name", report.get("suggested_name", "unknown"))), str(manifest.get("version", "unknown")), report.get("canonical_url"), report.get("final_url"), report.get("archive", {}).get("sha256"), str(result.source_zip), str(result.report_path), str(result.ioc_path), str(result.secrets_path), status, int(time.time())))
                conn.commit()

    async def list_scans(self, user_id: int, limit: int = 10) -> list[dict[str, Any]]:
        async with self.lock:
            with sqlite3.connect(self.path) as conn:
                conn.row_factory = sqlite3.Row
                return [dict(row) for row in conn.execute("SELECT * FROM scans WHERE user_id=? ORDER BY created_at DESC LIMIT ?", (user_id, limit)).fetchall()]

    async def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        async with self.lock:
            with sqlite3.connect(self.path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
                return dict(row) if row else None

    async def list_users(self, offset: int = 0, limit: int = 8) -> list[dict[str, Any]]:
        async with self.lock:
            with sqlite3.connect(self.path) as conn:
                conn.row_factory = sqlite3.Row
                return [dict(row) for row in conn.execute("SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()]

    async def referral_rows(self, user_id: int) -> list[dict[str, Any]]:
        async with self.lock:
            with sqlite3.connect(self.path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT r.*,u.username,u.first_name,u.last_name FROM referrals r LEFT JOIN users u ON u.user_id=r.referred_id WHERE r.referrer_id=? ORDER BY r.created_at DESC", (user_id,)).fetchall()
                return [dict(row) for row in rows]

    async def stats(self) -> dict[str, int]:
        async with self.lock:
            with sqlite3.connect(self.path) as conn:
                values = conn.execute("SELECT (SELECT COUNT(*) FROM users),(SELECT COALESCE(SUM(points),0) FROM users),(SELECT COUNT(*) FROM scans),(SELECT COUNT(*) FROM scans WHERE status='ok'),(SELECT COUNT(*) FROM referrals WHERE status='rewarded')").fetchone()
                return {"users": int(values[0]), "points": int(values[1]), "scans": int(values[2]), "successful": int(values[3]), "referrals": int(values[4])}

    async def audit(self, admin_id: int, action: str, target_id: int | None = None, reason: str = "") -> None:
        async with self.lock:
            with sqlite3.connect(self.path) as conn:
                conn.execute("INSERT INTO admin_audit(admin_id,action,target_id,reason,created_at) VALUES(?,?,?,?,?)", (admin_id, action, target_id, reason[:1000], int(time.time())))
                conn.commit()


class BotService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db = StatsDB(settings.db_path)
        self.semaphore = asyncio.Semaphore(settings.parallel_jobs)
        self.user_windows: dict[int, deque[float]] = defaultdict(deque)

    def check_rate_limit(self, user_id: int) -> None:
        now = time.time()
        window = self.user_windows[user_id]
        while window and now - window[0] >= 3600:
            window.popleft()
        if len(window) >= self.settings.rate_limit_per_hour and user_id not in self.settings.admin_ids:
            raise BotError(f"Hourly limit reached: {self.settings.rate_limit_per_hour} jobs.")
        window.append(now)

    async def process(self, raw_url: str) -> JobResult:
        async with self.semaphore:
            resolved = resolve_extension_url(raw_url, self.settings)
            scan_id = uuid.uuid4().hex[:12]
            artifact = self.settings.result_root / scan_id
            artifact.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="senzo-job-") as temp:
                work = Path(temp)
                downloaded = await fetch_package(resolved, self.settings, work / "download.bin")
                file_count, expanded, warnings = safe_extract(downloaded.archive_path, work, self.settings)
                source_root = work / "source"
                report, iocs, secrets = analyze_source(source_root, downloaded, resolved, file_count, expanded, warnings)
                package_root = artifact / "package"
                (package_root / "original").mkdir(parents=True, exist_ok=True)
                shutil.copytree(source_root, package_root / "original", dirs_exist_ok=True)
                (package_root / "beautified").mkdir(parents=True, exist_ok=True)
                beauty_count = 0
                for path in iter_files(source_root):
                    beautified = beautify_file(path, path.relative_to(source_root))
                    if beautified is not None:
                        target = package_root / "beautified" / path.relative_to(source_root)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_text(beautified, encoding="utf-8")
                        beauty_count += 1
                report["beautified_files"] = beauty_count
                report_path = artifact / "analysis.json"
                report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
                ioc_path = artifact / "ioc_domains.txt"
                write_ioc_report(iocs, ioc_path)
                secrets_path = artifact / "secrets_scan.txt"
                write_secrets_report(secrets, secrets_path)
                (package_root / "reports").mkdir(parents=True, exist_ok=True)
                shutil.copy2(report_path, package_root / "reports" / "analysis.json")
                shutil.copy2(ioc_path, package_root / "reports" / "ioc_domains.txt")
                shutil.copy2(secrets_path, package_root / "reports" / "secrets_scan.txt")
                source_zip = make_package_zip(package_root, artifact, report, str(report.get("extension_name", resolved.suggested_name)))
            return JobResult(scan_id, source_zip, report_path, ioc_path, secrets_path, report)


def premium_header(title: str) -> str:
    return f"<b>╭━━〔 {html.escape(title)} 〕━━╮</b>"


def premium_footer() -> str:
    return f"\n<code>Fetched By {WATERMARK}</code>\n<code>Bot: {BOT_USERNAME}</code>"


def main_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➜ Scan Extension", callback_data="scan"), InlineKeyboardButton("◉ My Points", callback_data="profile")],
        [InlineKeyboardButton("↗ My Referral Link", callback_data="referral"), InlineKeyboardButton("⌕ My History", callback_data="history")],
        [InlineKeyboardButton("? Help", callback_data="help"), InlineKeyboardButton("★ Join Us", callback_data="join")],
    ])


def scan_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⚡ Quick Scan", callback_data="scanmode:quick"), InlineKeyboardButton("🛡 Full Scan", callback_data="scanmode:full")],
        [InlineKeyboardButton("✦ Beautify Code", callback_data="scanmode:beautify"), InlineKeyboardButton("▣ Source ZIP", callback_data="scanmode:source")],
        [InlineKeyboardButton("⇄ Compare Version", callback_data="scanmode:compare")],
        [InlineKeyboardButton("‹ Back", callback_data="home")],
    ])


def join_keyboard(channels: list[dict[str, str]]) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(f"➜ Join Channel {i}", url=ch["link"])] for i, ch in enumerate(channels, 1)]
    rows.append([InlineKeyboardButton("✓ Verify Membership", callback_data="verify_join")])
    rows.append([InlineKeyboardButton("‹ Back", callback_data="home")])
    return InlineKeyboardMarkup(rows)


def is_admin(user_id: int, settings: Settings) -> bool:
    return user_id in settings.admin_ids


def first_url(text: str) -> str | None:
    match = URL_RE.search(text or "")
    return clean_url(match.group(0)) if match else None


def ioc_preview_message(report: dict[str, Any], limit: int = 8) -> str:
    findings = report.get("ioc_findings", {})
    lines = [premium_header("IOC & DOMAIN INTELLIGENCE"), ""]
    for label, title in (("urls", "URLs"), ("domains", "Domains"), ("ips", "IP addresses"), ("emails", "Emails")):
        items = findings.get(label, [])
        counts = Counter(str(item["value"]) for item in items)
        lines.append(f"<b>{title}:</b> <code>{len(items)}</code>")
        for value, count in counts.most_common(limit if label in {"urls", "domains"} else 4):
            source = next(item for item in items if item["value"] == value)
            suffix = f" ×{count}" if count > 1 else ""
            lines.append(f"➜ <code>{html.escape(value[:160])}</code>{suffix} · <code>{html.escape(source['file'])}:{source['line']}</code>")
        if not items:
            lines.append("  None detected")
        lines.append("")
    lines.append("Full details are available in the downloadable IOC report.")
    lines.append(premium_footer())
    return "\n".join(lines)


def secrets_preview_message(report: dict[str, Any]) -> str:
    findings = report.get("secret_findings", [])
    lines = [premium_header("SECRETS SCAN"), "", f"<b>Possible findings:</b> <code>{len(findings)}</code>", "<b>Values are masked for safety.</b>", ""]
    for item in findings[:8]:
        lines.append(f"➜ <b>{html.escape(item['type'])}</b> · <b>{html.escape(item['severity'].upper())}</b>\n  <code>{html.escape(item['masked_value'])}</code> · <code>{html.escape(item['file'])}:{item['line']}</code>")
    if not findings:
        lines.append("✓ No possible secret pattern was detected.")
    lines.append(premium_footer())
    return "\n".join(lines)


def compact_summary(report: dict[str, Any], points_left: int) -> str:
    manifest = report.get("manifest") or {}
    risk = report["risk"]
    return (f"{premium_header('SCAN COMPLETE')}\n\n"
            f"<b>Extension:</b> <code>{html.escape(str(report.get('extension_name', report.get('suggested_name', 'unknown'))))}</code>\n"
            f"<b>Version:</b> <code>{html.escape(str(manifest.get('version', 'unknown')))}</code>\n"
            f"<b>Files:</b> <code>{report['package']['file_count']}</code>\n"
            f"<b>Risk:</b> <b>{risk['level'].upper()}</b> <code>{risk['score']}</code>\n"
            f"<b>IOC items:</b> <code>{sum(report['ioc_summary'].values())}</code>\n"
            f"<b>Possible secrets:</b> <code>{report['secrets_count']}</code>\n"
            f"<b>Points remaining:</b> <code>{points_left}</code>\n"
            f"{premium_footer()}")


def result_keyboard(scan_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⌁ IOC & Domains", callback_data=f"scan:ioc:{scan_id}"), InlineKeyboardButton("⚠ Secrets Scan", callback_data=f"scan:secrets:{scan_id}")],
        [InlineKeyboardButton("▣ Download Source ZIP", callback_data=f"scan:zip:{scan_id}"), InlineKeyboardButton("▤ Full Report", callback_data=f"scan:report:{scan_id}")],
        [InlineKeyboardButton("⌕ My History", callback_data="history"), InlineKeyboardButton("➜ New Scan", callback_data="scan")],
    ])


async def force_join_missing(bot: Any, user_id: int, channels: list[dict[str, str]]) -> list[dict[str, str]]:
    missing = []
    for channel in channels:
        try:
            member = await bot.get_chat_member(channel["chat_id"], user_id)
            if member.status in {"left", "kicked"} or (member.status == "restricted" and not getattr(member, "is_member", False)):
                missing.append(channel)
        except TelegramError:
            missing.append(channel)
    return missing


async def require_membership(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    service: BotService = context.application.bot_data["service"]
    channels = service.settings.force_join_channels
    if not channels:
        return True
    user_id = update.effective_user.id
    missing = await force_join_missing(context.bot, user_id, channels)
    if missing:
        text = f"{premium_header('JOIN REQUIRED')}\n\n➜ Join every required channel, then press <b>Verify Membership</b>.\n➜ Missing channels: <code>{len(missing)}</code>{premium_footer()}"
        await update.effective_message.reply_text(text, parse_mode="HTML", reply_markup=join_keyboard(missing))
        return False
    return True


async def ensure_registered(update: Update, context: ContextTypes.DEFAULT_TYPE, payload: str | None = None) -> tuple[bool, bool]:
    service: BotService = context.application.bot_data["service"]
    referral_id = int(payload[4:]) if payload and payload.startswith("ref_") and payload[4:].isdigit() else None
    return await service.db.upsert_user(update.effective_user, referral_id)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    _, referral_created = await ensure_registered(update, context, context.args[0] if context.args else None)
    service: BotService = context.application.bot_data["service"]
    if referral_created and not service.settings.force_join_channels:
        referrer, rewarded = await service.db.complete_referral(update.effective_user.id)
        if rewarded:
            referred_points = await service.db.get_points(update.effective_user.id)
            await update.effective_message.reply_text(f"{premium_header('REFERRAL BONUS')}\n\n✓ You received <b>+1 point</b> after verified referral registration.\n➜ Available scans: <code>{referred_points}</code>{premium_footer()}", parse_mode="HTML")
            try:
                ref_points = await service.db.get_points(referrer)
                await context.bot.send_message(referrer, f"{premium_header('NEW VERIFIED REFERRAL')}\n\n✓ A new user joined through your referral link.\n✓ You received <b>+1 point</b>.\n➜ Available scans: <code>{ref_points}</code>{premium_footer()}", parse_mode="HTML")
            except TelegramError:
                LOG.warning("Could not notify referrer %s", referrer)
    user = await service.db.get_user(update.effective_user.id)
    text = (f"{premium_header(BRAND)}\n\n<b>Welcome, {html.escape(update.effective_user.first_name or 'User')}.</b>\n\n"
            "➜ Inspect public browser extensions\n➜ Beautify minified source\n➜ Detect IOCs, domains and secrets\n➜ Generate a branded source package\n\n"
            f"<b>Your Points:</b> <code>{user['points'] if user else 0}</code>\n<b>1 point = 1 successful scan</b>\n{premium_footer()}")
    await update.effective_message.reply_text(text, parse_mode="HTML", reply_markup=main_menu())


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await ensure_registered(update, context)
    text = (f"{premium_header('HELP & GUIDE')}\n\n"
            "➜ Paste a supported extension-store URL.\n➜ Choose a scan mode.\n➜ One point is spent only after a successful scan.\n➜ Original files are preserved; beautified copies are separate.\n➜ IOC and secrets results are sent separately.\n➜ Secrets are masked for safety.\n\n"
            "Use only packages you are authorized to inspect. The bot does not bypass login, CAPTCHA, or access controls."
            f"{premium_footer()}")
    await update.effective_message.reply_text(text, parse_mode="HTML", reply_markup=main_menu())


async def join_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_text(f"{premium_header('JOIN US')}\n\n➜ WhatsApp Channel\n{WHATSAPP_URL}{premium_footer()}", parse_mode="HTML", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("➜ Open WhatsApp Channel", url=WHATSAPP_URL)], [InlineKeyboardButton("‹ Back", callback_data="home")]]))


async def share_contact_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await ensure_registered(update, context)
    keyboard = ReplyKeyboardMarkup([[KeyboardButton("Share my contact", request_contact=True)]], resize_keyboard=True, one_time_keyboard=True)
    await update.effective_message.reply_text(f"{premium_header('OPTIONAL CONTACT')}\n\nShare your own contact only if you want it stored in your profile. Use /delete_my_data to remove it later.{premium_footer()}", parse_mode="HTML", reply_markup=keyboard)


async def delete_my_data_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    service: BotService = context.application.bot_data["service"]
    await service.db.delete_contact(update.effective_user.id)
    await update.effective_message.reply_text("Your optional contact data was deleted.", reply_markup=ReplyKeyboardRemove())


async def referral_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await ensure_registered(update, context)
    service: BotService = context.application.bot_data["service"]
    me = await context.bot.get_me()
    username = me.username or BOT_USERNAME.lstrip("@")
    link = f"https://t.me/{username}?start=ref_{update.effective_user.id}"
    rows = await service.db.referral_rows(update.effective_user.id)
    text = (f"{premium_header('MY REFERRAL LINK')}\n\n<code>{html.escape(link)}</code>\n\n"
            "➜ Share this link.\n➜ After the new user joins required channels and verifies membership, both users get +1 point.\n"
            f"➜ Verified referrals: <code>{len([r for r in rows if r['status'] == 'rewarded'])}</code>{premium_footer()}")
    await update.effective_message.reply_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("↗ Share Link", switch_inline_query=link)], [InlineKeyboardButton("‹ Back", callback_data="home")]]))


async def profile_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await ensure_registered(update, context)
    service: BotService = context.application.bot_data["service"]
    user = await service.db.get_user(update.effective_user.id)
    scans = await service.db.list_scans(update.effective_user.id, 100)
    refs = await service.db.referral_rows(update.effective_user.id)
    text = (f"{premium_header('MY PROFILE')}\n\n<b>Name:</b> {html.escape(str(user.get('first_name', '')))}\n"
            f"<b>Username:</b> <code>@{html.escape(user.get('username') or 'not_set')}</code>\n<b>Chat ID:</b> <code>{user['user_id']}</code>\n"
            f"<b>Points:</b> <code>{user['points']}</code>\n<b>Successful scans:</b> <code>{len(scans)}</code>\n<b>Referrals:</b> <code>{len([r for r in refs if r['status'] == 'rewarded'])}</code>{premium_footer()}")
    await update.effective_message.reply_text(text, parse_mode="HTML", reply_markup=main_menu())


async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await ensure_registered(update, context)
    service: BotService = context.application.bot_data["service"]
    scans = await service.db.list_scans(update.effective_user.id)
    if not scans:
        text = f"{premium_header('MY HISTORY')}\n\nNo scans yet.{premium_footer()}"
    else:
        lines = [premium_header("MY HISTORY"), ""]
        for scan in scans:
            stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(scan["created_at"]))
            lines.append(f"➜ <b>{html.escape(scan['extension_name'] or 'unknown')}</b> · <code>{stamp}</code>\n  ID: <code>{scan['scan_id']}</code> · {html.escape(scan['status'])}")
        lines.append(premium_footer())
        text = "\n".join(lines)
    await update.effective_message.reply_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("➜ New Scan", callback_data="scan")], [InlineKeyboardButton("‹ Back", callback_data="home")]]))


async def run_job(update: Update, context: ContextTypes.DEFAULT_TYPE, raw_url: str, mode: str = "full") -> None:
    service: BotService = context.application.bot_data["service"]
    user_id = update.effective_user.id
    if not await require_membership(update, context):
        return
    user = await service.db.get_user(user_id)
    if not user or user["banned"]:
        await update.effective_message.reply_text("Your access is currently unavailable.")
        return
    if user["points"] < 1 and user_id not in service.settings.admin_ids:
        await update.effective_message.reply_text(f"{premium_header('NOT ENOUGH POINTS')}\n\n➜ You need 1 point for a scan.\n➜ Invite a new user with /referral to earn verified referral points.{premium_footer()}", parse_mode="HTML", reply_markup=main_menu())
        return
    try:
        service.check_rate_limit(user_id)
        await update.effective_message.reply_text(f"{premium_header('SENZO SCANNING')}\n\n✓ URL validated\n➜ Downloading package...{premium_footer()}", parse_mode="HTML")
        result = await service.process(raw_url)
        points_left = user["points"] if user_id in service.settings.admin_ids else await service.db.spend_point(user_id, f"successful extension scan:{result.scan_id}")
        await service.db.record_scan(result.scan_id, user_id, raw_url, result.report, result)
        await update.effective_message.reply_text(compact_summary(result.report, points_left), parse_mode="HTML", reply_markup=result_keyboard(result.scan_id))
        await update.effective_message.reply_text(ioc_preview_message(result.report), parse_mode="HTML", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("▣ Download IOC Report", callback_data=f"scan:ioc:{result.scan_id}")]]))
        await update.effective_message.reply_text(secrets_preview_message(result.report), parse_mode="HTML", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("▣ Download Secrets Report", callback_data=f"scan:secrets:{result.scan_id}")]]))
        with result.source_zip.open("rb") as source_file:
            await update.effective_message.reply_document(InputFile(source_file, filename=result.source_zip.name), caption=f"{BRAND}\nFetched By {WATERMARK}\nBeautified source, original files, reports, and watermark included.")
    except BotError as exc:
        await update.effective_message.reply_text(f"{premium_header('SCAN FAILED')}\n\n{html.escape(str(exc))}{premium_footer()}", parse_mode="HTML")
    except Exception:
        LOG.exception("Unhandled scan failure")
        await update.effective_message.reply_text(f"{premium_header('SCAN FAILED')}\n\nAn unexpected error occurred. Check the server logs.{premium_footer()}", parse_mode="HTML")


async def analyze_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await ensure_registered(update, context)
    url = first_url(" ".join(context.args))
    if not url:
        await update.effective_message.reply_text("Usage: /analyze https://chromewebstore.google.com/detail/name/extension-id")
        return
    await run_job(update, context, url, "full")


async def source_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await ensure_registered(update, context)
    url = first_url(" ".join(context.args))
    if not url:
        await update.effective_message.reply_text("Usage: /source https://chromewebstore.google.com/detail/name/extension-id")
        return
    await run_job(update, context, url, "source")


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    service: BotService = context.application.bot_data["service"]
    await ensure_registered(update, context)
    if update.effective_user.id in service.settings.admin_ids and context.user_data.get("admin_adjust"):
        target_id, sign = context.user_data.pop("admin_adjust")
        parts = (update.effective_message.text or "").split(maxsplit=1)
        if not parts or not parts[0].lstrip("+-").isdigit():
            await update.effective_message.reply_text("Send: <amount> <reason>", parse_mode="HTML")
            return
        amount = abs(int(parts[0])) * sign
        reason = parts[1] if len(parts) > 1 else "admin adjustment"
        new_points = await service.db.add_points(target_id, amount, f"admin adjustment: {reason}")
        await service.db.audit(update.effective_user.id, "points_adjustment", target_id, reason)
        await update.effective_message.reply_text(f"Points updated. User <code>{target_id}</code> now has <code>{new_points}</code> points.", parse_mode="HTML")
        return
    if context.user_data.get("awaiting_mode"):
        mode = context.user_data.pop("awaiting_mode")
        url = first_url(update.effective_message.text or "")
        if not url:
            await update.effective_message.reply_text("Please paste a complete supported extension URL.")
            context.user_data["awaiting_mode"] = mode
            return
        await run_job(update, context, url, mode)
        return
    url = first_url(update.effective_message.text or "")
    if url:
        await run_job(update, context, url, "full")
    else:
        await update.effective_message.reply_text("Use /start and choose Scan Extension, or paste a supported extension URL.", reply_markup=main_menu())


async def handle_contact(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    contact = update.effective_message.contact
    if contact and contact.user_id == update.effective_user.id:
        service: BotService = context.application.bot_data["service"]
        await service.db.set_contact(update.effective_user.id, contact.phone_number)
        await update.effective_message.reply_text("Your voluntarily shared contact was saved. Use /delete_my_data to request deletion.")
    else:
        await update.effective_message.reply_text("Please share your own contact only.")


async def verify_join(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    service: BotService = context.application.bot_data["service"]
    missing = await force_join_missing(context.bot, update.effective_user.id, service.settings.force_join_channels)
    if missing:
        await query.message.reply_text(f"Still missing <code>{len(missing)}</code> required channel membership(s).", parse_mode="HTML", reply_markup=join_keyboard(missing))
        return
    referrer, rewarded = await service.db.complete_referral(update.effective_user.id)
    if rewarded:
        referred_points = await service.db.get_points(update.effective_user.id)
        await query.message.reply_text(f"{premium_header('REFERRAL BONUS')}\n\n✓ Verified membership completed.\n✓ You received <b>+1 point</b>.\n➜ Available scans: <code>{referred_points}</code>\n\nThis bonus was awarded because you joined through a verified referral link.{premium_footer()}", parse_mode="HTML")
        try:
            ref_points = await service.db.get_points(referrer)
            await context.bot.send_message(referrer, f"{premium_header('NEW VERIFIED REFERRAL')}\n\n✓ A new user joined through your referral link.\n✓ You received <b>+1 point</b>.\n➜ Available scans: <code>{ref_points}</code>{premium_footer()}", parse_mode="HTML")
        except TelegramError:
            LOG.warning("Could not notify referrer %s", referrer)
    else:
        await query.message.reply_text(f"{premium_header('MEMBERSHIP VERIFIED')}\n\n✓ All required channels are verified. You can now scan extensions.{premium_footer()}", parse_mode="HTML", reply_markup=main_menu())


async def admin_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    service: BotService = context.application.bot_data["service"]
    if update.effective_user.id not in service.settings.admin_ids:
        await update.effective_message.reply_text("Admin-only command.")
        return
    await update.effective_message.reply_text(f"{premium_header('SENZO ADMIN CONTROL')}\n\n➜ Protected Telegram-only administration.{premium_footer()}", parse_mode="HTML", reply_markup=InlineKeyboardMarkup([
        [InlineKeyboardButton("▦ Statistics", callback_data="admin:stats"), InlineKeyboardButton("♙ Users", callback_data="admin:users:0")],
        [InlineKeyboardButton("⚙ Limits", callback_data="admin:limits"), InlineKeyboardButton("★ Branding", callback_data="admin:branding")],
        [InlineKeyboardButton("⌁ System Health", callback_data="admin:health")],
    ]))


async def admin_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    service: BotService = context.application.bot_data["service"]
    stats = await service.db.stats()
    text = f"{premium_header('ADMIN STATISTICS')}\n\n➜ Users: <code>{stats['users']}</code>\n➜ Total points: <code>{stats['points']}</code>\n➜ Scans: <code>{stats['scans']}</code>\n➜ Successful scans: <code>{stats['successful']}</code>\n➜ Verified referrals: <code>{stats['referrals']}</code>{premium_footer()}"
    await update.callback_query.edit_message_text(text, parse_mode="HTML", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("‹ Admin Menu", callback_data="admin:home")]]))


async def admin_users(update: Update, context: ContextTypes.DEFAULT_TYPE, offset: int) -> None:
    service: BotService = context.application.bot_data["service"]
    users = await service.db.list_users(offset)
    rows = [[InlineKeyboardButton(f"👤 {(u['first_name'] or 'User')[:18]} · {u['points']} pts", callback_data=f"admin:user:{u['user_id']}")] for u in users]
    nav = []
    if offset >= 8:
        nav.append(InlineKeyboardButton("‹ Prev", callback_data=f"admin:users:{offset - 8}"))
    if len(users) == 8:
        nav.append(InlineKeyboardButton("Next ›", callback_data=f"admin:users:{offset + 8}"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton("‹ Admin Menu", callback_data="admin:home")])
    await update.callback_query.edit_message_text(f"{premium_header('ADMIN USERS')}\n\nSelect a user:{premium_footer()}", parse_mode="HTML", reply_markup=InlineKeyboardMarkup(rows))


async def admin_user(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int) -> None:
    service: BotService = context.application.bot_data["service"]
    user = await service.db.get_user(user_id)
    scans = await service.db.list_scans(user_id, 5)
    refs = await service.db.referral_rows(user_id)
    if not user:
        await update.callback_query.answer("User not found", show_alert=True)
        return
    phone = user.get("phone") or "Not provided"
    text = (f"{premium_header('ADMIN USER DETAILS')}\n\n<b>Name:</b> {html.escape(user['first_name'])} {html.escape(user['last_name'] or '')}\n"
            f"<b>Username:</b> <code>@{html.escape(user['username'] or 'not_set')}</code>\n<b>Chat ID:</b> <code>{user['user_id']}</code>\n"
            f"<b>Language:</b> <code>{html.escape(user['language_code'] or 'unknown')}</code>\n<b>Country prefix:</b> <code>{html.escape(user.get('country_code') or 'Not provided')}</code>\n<b>Phone:</b> <code>{html.escape(phone)}</code>\n"
            f"<b>Points:</b> <code>{user['points']}</code>\n<b>Verified referrals:</b> <code>{len([r for r in refs if r['status'] == 'rewarded'])}</code>\n\n<b>Recent extensions:</b>")
    for scan in scans:
        text += f"\n➜ <code>{scan['scan_id']}</code> · {html.escape(scan['extension_name'] or 'unknown')} · <code>{html.escape(scan['raw_url'][:80])}</code>"
    buttons = [[InlineKeyboardButton("＋ Add Points", callback_data=f"admin:add:{user_id}"), InlineKeyboardButton("－ Remove Points", callback_data=f"admin:remove:{user_id}")]]
    for scan in scans:
        buttons.append([InlineKeyboardButton(f"▣ {scan['scan_id']} ZIP", callback_data=f"admin:scan:zip:{scan['scan_id']}"), InlineKeyboardButton("↗ URL", callback_data=f"admin:scan:url:{scan['scan_id']}")])
    buttons.append([InlineKeyboardButton("‹ Users", callback_data="admin:users:0")])
    await update.callback_query.edit_message_text(text + premium_footer(), parse_mode="HTML", reply_markup=InlineKeyboardMarkup(buttons))


async def admin_adjust_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, sign: int) -> None:
    service: BotService = context.application.bot_data["service"]
    if update.effective_user.id not in service.settings.admin_ids:
        await update.callback_query.answer("Admin-only", show_alert=True)
        return
    context.user_data["admin_adjust"] = (user_id, sign)
    await update.callback_query.message.reply_text(f"Send: <code>amount reason</code>\nExample: <code>3 campaign reward</code>", parse_mode="HTML")


async def send_artifact(update: Update, context: ContextTypes.DEFAULT_TYPE, scan_id: str, kind: str) -> None:
    service: BotService = context.application.bot_data["service"]
    scan = await service.db.get_scan(scan_id)
    if not scan:
        await update.callback_query.answer("Scan not found", show_alert=True)
        return
    if scan["user_id"] != update.effective_user.id and not is_admin(update.effective_user.id, service.settings):
        await update.callback_query.answer("This scan is not yours", show_alert=True)
        return
    if kind not in {"zip", "report", "ioc", "secrets"}:
        await update.callback_query.answer("Unsupported artifact", show_alert=True)
        return
    path_key = {"zip": "source_path", "report": "report_path", "ioc": "ioc_path", "secrets": "secrets_path"}[kind]
    path = Path(scan[path_key])
    if not path.exists():
        await update.callback_query.answer("Artifact is no longer stored", show_alert=True)
        return
    with path.open("rb") as stream:
        await update.callback_query.message.reply_document(InputFile(stream, filename=path.name), caption=f"{BRAND}\nFetched By {WATERMARK}")


async def send_scan_url(update: Update, context: ContextTypes.DEFAULT_TYPE, scan_id: str) -> None:
    service: BotService = context.application.bot_data["service"]
    scan = await service.db.get_scan(scan_id)
    if not scan:
        await update.callback_query.answer("Scan not found", show_alert=True)
        return
    if not is_admin(update.effective_user.id, service.settings):
        await update.callback_query.answer("Admin-only", show_alert=True)
        return
    await update.callback_query.message.reply_text(f"<b>Original URL:</b>\n<code>{html.escape(scan['raw_url'])}</code>\n\n<b>Canonical URL:</b>\n<code>{html.escape(scan['canonical_url'] or '')}</code>\n\n<b>Final package URL:</b>\n<code>{html.escape(scan['final_url'] or '')}</code>", parse_mode="HTML")


async def callbacks(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    data = query.data or ""
    service: BotService = context.application.bot_data["service"]
    if data.startswith("admin:") and not is_admin(update.effective_user.id, service.settings):
        await query.answer("Admin-only", show_alert=True)
        return
    await query.answer()
    if data == "home":
        await query.edit_message_text(f"{premium_header(BRAND)}\n\nChoose an action below.{premium_footer()}", parse_mode="HTML", reply_markup=main_menu())
    elif data == "scan":
        await query.edit_message_text(f"{premium_header('SELECT SCAN MODE')}\n\nChoose the operation Senzo should perform.{premium_footer()}", parse_mode="HTML", reply_markup=scan_menu())
    elif data.startswith("scanmode:"):
        mode = data.split(":", 1)[1]
        context.user_data["awaiting_mode"] = mode
        await query.edit_message_text(f"{premium_header('PASTE EXTENSION URL')}\n\n➜ Send a public Chrome, Edge, Firefox, Opera, Thunderbird, CRX, XPI, NEX, or ZIP URL.{premium_footer()}", parse_mode="HTML", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Cancel", callback_data="home")]]))
    elif data == "verify_join":
        await verify_join(update, context)
    elif data == "referral":
        await referral_command(update, context)
    elif data == "profile":
        await profile_command(update, context)
    elif data == "history":
        await history_command(update, context)
    elif data == "help":
        await help_command(update, context)
    elif data == "join":
        await join_command(update, context)
    elif data == "admin:home":
        await query.edit_message_text(f"{premium_header('SENZO ADMIN CONTROL')}{premium_footer()}", parse_mode="HTML", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("▦ Statistics", callback_data="admin:stats"), InlineKeyboardButton("♙ Users", callback_data="admin:users:0")], [InlineKeyboardButton("⚙ Limits", callback_data="admin:limits"), InlineKeyboardButton("★ Branding", callback_data="admin:branding")], [InlineKeyboardButton("⌁ System Health", callback_data="admin:health")]]))
    elif data == "admin:stats":
        await admin_stats(update, context)
    elif data.startswith("admin:users:"):
        await admin_users(update, context, int(data.rsplit(":", 1)[1]))
    elif data.startswith("admin:user:"):
        await admin_user(update, context, int(data.rsplit(":", 1)[1]))
    elif data.startswith("admin:add:"):
        await admin_adjust_prompt(update, context, int(data.rsplit(":", 1)[1]), 1)
    elif data.startswith("admin:remove:"):
        await admin_adjust_prompt(update, context, int(data.rsplit(":", 1)[1]), -1)
    elif data.startswith("admin:scan:url:"):
        await send_scan_url(update, context, data.split(":", 3)[3])
    elif data.startswith("admin:scan:"):
        _, _, kind, scan_id = data.split(":", 3)
        await send_artifact(update, context, scan_id, kind)
    elif data == "admin:limits":
        service: BotService = context.application.bot_data["service"]
        s = service.settings
        await query.edit_message_text(f"{premium_header('CURRENT LIMITS')}\n\nDownload: <code>{s.max_download_bytes:,}</code> bytes\nExpanded: <code>{s.max_uncompressed_bytes:,}</code> bytes\nFiles: <code>{s.max_files}</code>\nHourly jobs: <code>{s.rate_limit_per_hour}</code>{premium_footer()}", parse_mode="HTML", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("‹ Admin Menu", callback_data="admin:home")]]))
    elif data == "admin:branding":
        await query.edit_message_text(f"{premium_header('BRANDING')}\n\nWatermark: <code>{WATERMARK}</code>\nBot: <code>{BOT_USERNAME}</code>\nWhatsApp: <code>{WHATSAPP_URL}</code>{premium_footer()}", parse_mode="HTML", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("‹ Admin Menu", callback_data="admin:home")]]))
    elif data == "admin:health":
        service: BotService = context.application.bot_data["service"]
        await query.edit_message_text(f"{premium_header('SYSTEM HEALTH')}\n\n✓ Telegram handlers: online\n✓ SQLite: available\n✓ Result storage: {html.escape(str(service.settings.result_root))}\n✓ Queue slots: <code>{service.settings.parallel_jobs}</code>{premium_footer()}", parse_mode="HTML", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("‹ Admin Menu", callback_data="admin:home")]]))
    elif data.startswith("scan:"):
        _, kind, scan_id = data.split(":", 2)
        await send_artifact(update, context, scan_id, kind)


async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await admin_menu(update, context)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    LOG.exception("Telegram update error", exc_info=context.error)


def build_application(settings: Settings) -> Application:
    app = ApplicationBuilder().token(settings.token).concurrent_updates(True).build()
    app.bot_data["service"] = BotService(settings)
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("analyze", analyze_command))
    app.add_handler(CommandHandler("source", source_command))
    app.add_handler(CommandHandler("referral", referral_command))
    app.add_handler(CommandHandler("profile", profile_command))
    app.add_handler(CommandHandler("history", history_command))
    app.add_handler(CommandHandler("join", join_command))
    app.add_handler(CommandHandler("share_contact", share_contact_command))
    app.add_handler(CommandHandler("delete_my_data", delete_my_data_command))
    app.add_handler(CommandHandler("admin", admin_menu))
    app.add_handler(CommandHandler("stats", stats_command))
    app.add_handler(MessageHandler(filters.CONTACT, handle_contact))
    app.add_handler(CallbackQueryHandler(callbacks))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_error_handler(error_handler)
    return app


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = Settings()
    build_application(settings).run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
