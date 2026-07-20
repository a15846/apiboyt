#!/usr/bin/env python3
"""Log in to Telegram and enable or change the account 2FA password."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import tomllib
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request
from urllib.parse import urlparse

from telethon import TelegramClient, errors, events, functions
from telethon.errors import RPCError
from telethon.sessions import MemorySession, SQLiteSession


InputFn = Callable[[str], str]
RANDOM_2FA_ALPHABET = (
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
)

TASK_LINK_PATTERN = re.compile(
    r"(?P<phone>\+[1-9]\d{7,14})\s*---\s*"
    r"(?:\[\s*)?(?P<url>https?://[^\s<>\]\)]+)",
    re.IGNORECASE,
)


class CredentialApiError(RuntimeError):
    """Raised when the credential page cannot provide fresh login data."""


class ClientSetupError(RuntimeError):
    """Raised when the Telegram Desktop client cannot be created."""


@dataclass(frozen=True)
class BatchTask:
    phone: str
    credential_url: str
    task_id: str
    login_url: str | None = None


@dataclass(frozen=True)
class WorkerSettings:
    bot_token: str
    admin_id: int
    source_chat_id: int | None
    new_password_length: int
    hint: str
    poll_interval: float
    poll_timeout: float
    state_dir: Path
    export_root: Path
    keep_artifacts: bool


class TaskLedger:
    """Small, private on-disk ledger used to deduplicate incoming task messages."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.records: dict[str, dict[str, str]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            records = payload.get("tasks", {})
            if not isinstance(records, dict):
                raise ValueError("tasks is not an object")
            self.records = {
                task_id: record
                for task_id, record in records.items()
                if isinstance(task_id, str) and isinstance(record, dict)
            }
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"无法读取任务状态文件：{self.path}") from exc

        for record in self.records.values():
            if record.get("status") in {"queued", "running"}:
                record["status"] = "interrupted"
                record["updated_at"] = utc_timestamp()
        self._save()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.parent.chmod(0o700)
        temporary_path = self.path.with_suffix(".tmp")
        temporary_path.write_text(
            json.dumps({"version": 1, "tasks": self.records}, ensure_ascii=False),
            encoding="utf-8",
        )
        temporary_path.chmod(0o600)
        temporary_path.replace(self.path)
        self.path.chmod(0o600)

    def reserve(self, task: BatchTask) -> str:
        record = self.records.get(task.task_id)
        if record and record.get("status") == "succeeded":
            return "succeeded"
        if record and record.get("status") in {"queued", "running"}:
            return "pending"

        self.records[task.task_id] = {
            "phone": mask_phone(task.phone),
            "status": "queued",
            "updated_at": utc_timestamp(),
        }
        self._save()
        return "queued"

    def mark(self, task: BatchTask, status: str, detail: str = "") -> None:
        self.records[task.task_id] = {
            "phone": mask_phone(task.phone),
            "status": status,
            "updated_at": utc_timestamp(),
            "detail": detail[:300],
        }
        self._save()


@dataclass(frozen=True)
class ExportResult:
    output_dir: Path
    session_zip: Path
    tdata_zip: Path
    session_sha256: str
    tdata_sha256: str


@dataclass(frozen=True)
class CredentialSnapshot:
    code: str | None = None
    current_password: str | None = None
    login_time: str | None = None

    def is_fresher_than(self, baseline: CredentialSnapshot | None) -> bool:
        if not self.code:
            return False
        if baseline is None or not baseline.code:
            return True
        return (self.code, self.login_time) != (baseline.code, baseline.login_time)


class _CredentialPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_label = False
        self._label_parts: list[str] = []
        self._last_label = ""
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "label":
            self._in_label = True
            self._label_parts = []
            return
        if tag != "input":
            return

        attributes = dict(attrs)
        value = attributes.get("value")
        if value is not None and self._last_label:
            self.fields[self._last_label] = value

    def handle_endtag(self, tag: str) -> None:
        if tag == "label" and self._in_label:
            self._in_label = False
            self._last_label = "".join(self._label_parts).strip().lower()

    def handle_data(self, data: str) -> None:
        if self._in_label:
            self._label_parts.append(data)


def _optional_value(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    if not text or text.strip().lower() in {"-", "none", "null", "暂无", "未获取"}:
        return None
    return text


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_task_url(url: str) -> str:
    normalized = url.strip().rstrip(".,;!\"')]")
    parsed = urlparse(normalized)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("验证码接口必须是有效的 HTTP 或 HTTPS URL。")
    return normalized


def task_fingerprint(phone: str, credential_url: str) -> str:
    value = f"{phone}\n{credential_url}".encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def classify_task_url(url: str) -> str | None:
    """Classify an administrator link without fetching it."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query_keys = {
        key.lower()
        for key in urllib_parse.parse_qs(parsed.query, keep_blank_values=True)
    }

    credential_score = 0
    login_score = 0
    if "getcode" in path or "get_code" in path:
        credential_score += 4
    if hostname.startswith("tgapi.") or "codeapi" in hostname:
        credential_score += 3
    if "id" in query_keys:
        credential_score += 2

    if "login" in hostname or "login" in path:
        login_score += 3
    if "token" in query_keys:
        login_score += 3

    if credential_score > login_score:
        return "credential"
    if login_score > credential_score:
        return "login"
    return None


def parse_batch_tasks(message: str) -> tuple[list[BatchTask], int]:
    """Group login and credential links by phone from an administrator message."""
    tasks: list[BatchTask] = []
    grouped: dict[str, dict[str, list[str]]] = {}
    phone_order: list[str] = []
    invalid = 0
    for match in TASK_LINK_PATTERN.finditer(message):
        phone = match.group("phone")
        try:
            url = normalize_task_url(match.group("url"))
        except ValueError:
            invalid += 1
            continue

        kind = classify_task_url(url)
        if kind is None:
            invalid += 1
            continue

        if phone not in grouped:
            grouped[phone] = {"credential": [], "login": []}
            phone_order.append(phone)
        if url not in grouped[phone][kind]:
            grouped[phone][kind].append(url)

    for phone in phone_order:
        credential_urls = grouped[phone]["credential"]
        login_urls = grouped[phone]["login"]
        if len(credential_urls) != 1 or len(login_urls) > 1:
            invalid += 1
            continue
        credential_url = credential_urls[0]
        tasks.append(
            BatchTask(
                phone=phone,
                credential_url=credential_url,
                task_id=task_fingerprint(phone, credential_url),
                login_url=login_urls[0] if login_urls else None,
            )
        )
    return tasks, invalid


def parse_credential_payload(body: bytes, content_type: str = "") -> CredentialSnapshot:
    text = body.decode("utf-8", "replace")
    if "json" in content_type.lower() or text.lstrip().startswith(("{", "[")):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CredentialApiError("凭据接口返回了无效 JSON。") from exc
        if not isinstance(payload, dict):
            raise CredentialApiError("凭据接口 JSON 顶层必须是对象。")
        code = _optional_value(payload.get("code") or payload.get("otp"))
        password = _optional_value(
            payload.get("current_2fa")
            or payload.get("pass2fa")
            or payload.get("2fa")
            or payload.get("password")
        )
        login_time = _optional_value(
            payload.get("login_time") or payload.get("time") or payload.get("updated_at")
        )
    else:
        parser = _CredentialPageParser()
        parser.feed(text)
        code = next(
            (
                _optional_value(value)
                for label, value in parser.fields.items()
                if "验证码" in label or "code" in label or "otp" in label
            ),
            None,
        )
        password = next(
            (
                _optional_value(value)
                for label, value in parser.fields.items()
                if "2fa" in label or "密码" in label or "password" in label
            ),
            None,
        )
        login_time = next(
            (
                _optional_value(value)
                for label, value in parser.fields.items()
                if "时间" in label or "time" in label or "updated_at" in label
            ),
            None,
        )

    normalized_code = code.strip().replace(" ", "") if code else None
    return CredentialSnapshot(
        code=normalized_code,
        current_password=password,
        login_time=login_time,
    )


class CredentialApiClient:
    def __init__(self, url: str, poll_interval: float, timeout: float) -> None:
        self.url = url
        self.poll_interval = poll_interval
        self.timeout = timeout

    def _fetch_sync(self) -> CredentialSnapshot:
        request = urllib_request.Request(
            self.url,
            headers={
                "Accept": "application/json, text/html",
                "Cache-Control": "no-cache, no-store",
                "Pragma": "no-cache",
                "User-Agent": "tg-2fa-client/1.0",
            },
        )
        try:
            with urllib_request.urlopen(request, timeout=15) as response:
                body = response.read(1024 * 1024 + 1)
                content_type = response.headers.get("Content-Type", "")
        except urllib_error.HTTPError as exc:
            raise CredentialApiError(f"凭据接口返回 HTTP {exc.code}。") from exc
        except (urllib_error.URLError, TimeoutError) as exc:
            raise CredentialApiError("无法连接凭据接口。") from exc

        if len(body) > 1024 * 1024:
            raise CredentialApiError("凭据接口响应超过 1 MiB。")
        return parse_credential_payload(body, content_type)

    async def fetch(self) -> CredentialSnapshot:
        return await asyncio.to_thread(self._fetch_sync)

    async def wait_for_fresh_code(
        self,
        baseline: CredentialSnapshot | None,
    ) -> CredentialSnapshot:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout
        last_error: CredentialApiError | None = None

        while loop.time() < deadline:
            try:
                snapshot = await self.fetch()
                last_error = None
                if snapshot.is_fresher_than(baseline):
                    return snapshot
            except CredentialApiError as exc:
                last_error = exc
            await asyncio.sleep(self.poll_interval)

        if last_error:
            raise CredentialApiError(f"等待新验证码超时；{last_error}")
        raise CredentialApiError(
            f"凭据接口在 {self.timeout:g} 秒内没有返回新的验证码。"
        )

    async def wait_for_current_password(self) -> str:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout
        last_error: CredentialApiError | None = None
        while loop.time() < deadline:
            try:
                snapshot = await self.fetch()
                last_error = None
                if snapshot.current_password:
                    return snapshot.current_password
            except CredentialApiError as exc:
                last_error = exc
            await asyncio.sleep(self.poll_interval)
        if last_error:
            raise CredentialApiError(f"等待当前 2FA 密码超时；{last_error}")
        raise CredentialApiError(
            f"凭据接口在 {self.timeout:g} 秒内没有返回当前 2FA 密码。"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="登录 Telegram 后启用或修改账号两步验证（2FA）密码。"
    )
    parser.add_argument(
        "--phone",
        help="带国家区号的手机号；也可通过 TG_PHONE 提供。",
    )
    parser.add_argument(
        "--hint",
        help="新 2FA 密码提示；未提供时会交互输入。",
    )
    parser.add_argument(
        "--email",
        help="可选的恢复邮箱；设置后 Telegram 会发送确认码。",
    )
    parser.add_argument(
        "--credential-url",
        help="验证码/当前 2FA 页面；也可通过 TG_CREDENTIAL_URL 提供。",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=None,
        help="凭据页面轮询间隔秒数，默认 2 秒。",
    )
    parser.add_argument(
        "--poll-timeout",
        type=float,
        default=None,
        help="等待新验证码的最长秒数，默认 180 秒。",
    )
    parser.add_argument(
        "--export-dir",
        help="导出 Session 协议包和 TData 包的目录。",
    )
    parser.add_argument(
        "--export-only",
        action="store_true",
        help="仅登录并导出账号协议包，不修改 2FA。",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="跳过账号确认提示。",
    )
    parser.add_argument(
        "--worker",
        action="store_true",
        help="以 Telegram Bot worker 运行，接收管理员批量任务并回传导出包。",
    )
    parser.add_argument(
        "--bot-token",
        help="Worker Bot Token；也可通过 TG_BOT_TOKEN 提供。",
    )
    parser.add_argument(
        "--admin-id",
        type=int,
        help="唯一允许投递任务和接收结果的 Telegram 用户 ID；也可通过 TG_ADMIN_ID 提供。",
    )
    parser.add_argument(
        "--source-chat-id",
        type=int,
        help="只监听指定群或频道 ID；也可通过 TG_SOURCE_CHAT_ID 提供。",
    )
    parser.add_argument(
        "--new-2fa-length",
        type=int,
        help="Worker 为每个账号随机生成的 2FA 密码长度，默认 16。",
    )
    parser.add_argument(
        "--worker-state-dir",
        default=None,
        help="Worker Bot session 和去重状态目录，默认 worker-state。",
    )
    parser.add_argument(
        "--keep-artifacts",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Worker 回传成功后保留本地导出包，默认保留。",
    )
    parser.add_argument(
        "--config",
        help="Worker TOML 配置文件；默认自动读取当前目录的 config.toml。",
    )
    return parser


def create_telegram_client(
    session_path: Path | None = None,
    *,
    receive_updates: bool = False,
) -> TelegramClient:
    if sys.version_info >= (3, 13):
        raise ClientSetupError(
            "opentele 1.15.1 暂不兼容 Python 3.13，请使用 Python 3.11 或 3.12。"
        )

    try:
        from opentele.api import API
        from opentele.tl import TelegramClient as OpenTeleTelegramClient
    except Exception as exc:
        raise ClientSetupError(
            "无法加载 opentele，请使用 Python 3.11 创建虚拟环境并安装依赖。"
        ) from exc

    unique_id = str(session_path) if session_path else "tg-2fa-memory-session"
    desktop_api = API.TelegramDesktop.Generate(system="macos", unique_id=unique_id)
    session = SQLiteSession(str(session_path)) if session_path else MemorySession()
    client = OpenTeleTelegramClient(
        session,
        api=desktop_api,
        receive_updates=receive_updates,
    )
    client._tg_2fa_api_profile = {
        "api_id": desktop_api.api_id,
        "api_hash": desktop_api.api_hash,
        "device_model": desktop_api.device_model,
        "system_version": desktop_api.system_version,
        "app_version": desktop_api.app_version,
        "lang_code": desktop_api.lang_code,
        "system_lang_code": desktop_api.system_lang_code,
        "lang_pack": desktop_api.lang_pack,
    }
    return client


def resolve_phone(
    args: argparse.Namespace,
    environ: Mapping[str, str],
    input_fn: InputFn = input,
) -> str:
    phone = args.phone or environ.get("TG_PHONE")
    if not phone:
        phone = input_fn("手机号（含国家区号，例如 +8613800138000）: ")

    phone = phone.strip().replace(" ", "")
    if not phone:
        raise ValueError("手机号不能为空。")
    return phone


def resolve_credential_url(
    args: argparse.Namespace,
    environ: Mapping[str, str],
) -> str | None:
    url = args.credential_url or environ.get("TG_CREDENTIAL_URL")
    if not url:
        return None

    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("凭据接口必须是有效的 HTTP 或 HTTPS URL。")
    if args.poll_interval <= 0 or args.poll_timeout <= 0:
        raise ValueError("轮询间隔和超时时间必须大于 0。")
    return url


def prompt_new_password(secret_fn: InputFn = getpass.getpass) -> str:
    while True:
        password = secret_fn("新的 2FA 密码: ")
        confirmation = secret_fn("再次输入新的 2FA 密码: ")
        if not password:
            print("新密码不能为空。", file=sys.stderr)
            continue
        if password != confirmation:
            print("两次输入的新密码不一致，请重试。", file=sys.stderr)
            continue
        return password


def mask_phone(phone: str | None) -> str:
    if not phone:
        return "未公开"
    if len(phone) <= 4:
        return "*" * len(phone)
    return f"{phone[:3]}{'*' * max(4, len(phone) - 5)}{phone[-2:]}"


def phone_slug(phone: str) -> str:
    slug = "".join(character for character in phone if character.isdigit())
    if not slug:
        raise ValueError("手机号中没有可用于文件名的数字。")
    return slug


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _add_file_to_zip(archive: zipfile.ZipFile, path: Path, arcname: str) -> None:
    info = zipfile.ZipInfo.from_file(path, arcname)
    info.external_attr = 0o600 << 16
    with path.open("rb") as source:
        archive.writestr(info, source.read(), compress_type=zipfile.ZIP_DEFLATED)


async def export_account_artifacts(
    client: TelegramClient,
    me: object,
    phone: str,
    current_password: str | None,
    session_path: Path,
    staging_dir: Path,
    export_root: Path,
) -> ExportResult:
    from opentele.api import UseCurrentSession

    slug = phone_slug(getattr(me, "phone", None) or phone)
    tdata_dir = staging_dir / "tdata"
    tdata_dir.mkdir(mode=0o700)

    tdesktop = await client.ToTDesktop(flag=UseCurrentSession)
    tdesktop.SaveTData(str(tdata_dir))
    client.session.save()

    if not session_path.is_file():
        raise ClientSetupError("登录成功，但没有生成 SQLite Session 文件。")

    profile = getattr(client, "_tg_2fa_api_profile", {})
    metadata = {
        "api_id": profile.get("api_id", client.api_id),
        "api_hash": profile.get("api_hash", client.api_hash),
        "app_id": profile.get("api_id", client.api_id),
        "app_hash": profile.get("api_hash", client.api_hash),
        "device_model": profile.get("device_model", "Desktop"),
        "system_version": profile.get("system_version", "macOS"),
        "app_version": profile.get("app_version", ""),
        "lang_code": profile.get("lang_code", "en"),
        "system_lang_code": profile.get("system_lang_code", "en-US"),
        "lang_pack": profile.get("lang_pack", "tdesktop"),
        "user_id": getattr(me, "id", None),
        "phone": getattr(me, "phone", None) or phone.lstrip("+"),
        "username": getattr(me, "username", None) or "",
        "premium": bool(getattr(me, "premium", False)),
        "twofa": current_password or "",
        "password": current_password or "",
        "session_file": slug,
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }

    metadata_path = staging_dir / f"{slug}.json"
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    password_path = staging_dir / "2fa.txt"
    password_path.write_text(current_password or "", encoding="utf-8")
    for private_path in (session_path, metadata_path, password_path):
        private_path.chmod(0o600)

    export_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    export_root.chmod(0o700)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = export_root / f"{slug}_{timestamp}"
    suffix = 1
    while output_dir.exists():
        output_dir = export_root / f"{slug}_{timestamp}_{suffix}"
        suffix += 1
    output_dir.mkdir(mode=0o700)

    session_zip = output_dir / f"session_{slug}.zip"
    with zipfile.ZipFile(session_zip, "w") as archive:
        _add_file_to_zip(archive, session_path, session_path.name)
        _add_file_to_zip(archive, metadata_path, metadata_path.name)
        _add_file_to_zip(archive, password_path, password_path.name)

    tdata_zip = output_dir / f"tdata_{slug}.zip"
    with zipfile.ZipFile(tdata_zip, "w") as archive:
        for path in sorted(tdata_dir.rglob("*")):
            if path.is_file():
                arcname = str(Path("tdata") / path.relative_to(tdata_dir))
                _add_file_to_zip(archive, path, arcname)
        _add_file_to_zip(archive, password_path, password_path.name)

    session_zip.chmod(0o600)
    tdata_zip.chmod(0o600)
    return ExportResult(
        output_dir=output_dir,
        session_zip=session_zip,
        tdata_zip=tdata_zip,
        session_sha256=file_sha256(session_zip),
        tdata_sha256=file_sha256(tdata_zip),
    )


async def authenticate(
    client: TelegramClient,
    phone: str,
    secret_fn: InputFn = getpass.getpass,
    credential_client: CredentialApiClient | None = None,
    baseline: CredentialSnapshot | None = None,
) -> str | None:
    """Authenticate and return the current 2FA password if it was requested."""
    if await client.is_user_authorized():
        return None

    await client.send_code_request(phone)
    credential_snapshot: CredentialSnapshot | None = None
    if credential_client:
        print("验证码已触发，正在等待凭据接口更新……")
        credential_snapshot = await credential_client.wait_for_fresh_code(baseline)
        code = credential_snapshot.code or ""
    else:
        code = secret_fn("Telegram 登录验证码: ").strip().replace(" ", "")
    if not code:
        raise ValueError("登录验证码不能为空。")

    try:
        await client.sign_in(phone=phone, code=code)
        return None
    except errors.SessionPasswordNeededError:
        current_password = (
            credential_snapshot.current_password if credential_snapshot else None
        )
        if not current_password and credential_client:
            current_password = await credential_client.wait_for_current_password()
        if not current_password:
            current_password = secret_fn("当前 2FA 密码: ")
        if not current_password:
            raise ValueError("当前账号已启用 2FA，密码不能为空。")
        try:
            await client.sign_in(password=current_password)
        except errors.PasswordHashInvalidError:
            if not credential_client:
                raise
            current_password = secret_fn("接口中的 2FA 已失效，请输入当前 2FA 密码: ")
            if not current_password:
                raise ValueError("当前 2FA 密码不能为空。")
            await client.sign_in(password=current_password)
        return current_password


async def update_two_factor_password(
    client: TelegramClient,
    current_password: str | None,
    new_password: str,
    hint: str,
    email: str | None,
    secret_fn: InputFn = getpass.getpass,
) -> bool:
    password_state = await client(functions.account.GetPasswordRequest())
    if password_state.has_password and current_password is None:
        current_password = secret_fn("当前 2FA 密码: ")
        if not current_password:
            raise ValueError("当前账号已启用 2FA，密码不能为空。")

    async def email_code_callback(code_length: int) -> str:
        code = secret_fn(f"恢复邮箱确认码（{code_length} 位）: ")
        return code.strip().replace(" ", "")

    callback = email_code_callback if email else None
    return await client.edit_2fa(
        current_password=current_password,
        new_password=new_password,
        hint=hint,
        email=email,
        email_code_callback=callback,
    )


def describe_rpc_error(exc: RPCError) -> str:
    if isinstance(exc, errors.ApiIdInvalidError):
        return "API ID 或 API hash 无效。"
    if isinstance(exc, errors.PhoneNumberInvalidError):
        return "手机号格式无效。"
    if isinstance(exc, errors.PhoneCodeInvalidError):
        return "登录验证码无效。"
    if isinstance(exc, errors.PhoneCodeExpiredError):
        return "登录验证码已过期，请重新运行。"
    if isinstance(exc, errors.PasswordHashInvalidError):
        return "当前 2FA 密码错误。"
    if isinstance(exc, errors.EmailInvalidError):
        return "恢复邮箱格式无效。"
    if isinstance(exc, errors.CodeInvalidError):
        return "恢复邮箱确认码无效。"
    if isinstance(exc, errors.PasswordTooFreshError):
        return f"当前 2FA 密码设置时间过短，请等待 {exc.seconds} 秒后重试。"
    if isinstance(exc, errors.SessionTooFreshError):
        return f"当前登录会话过新，请等待 {exc.seconds} 秒后重试。"
    if isinstance(exc, errors.FloodWaitError):
        return f"请求过于频繁，Telegram 要求等待 {exc.seconds} 秒。"
    return f"Telegram API 请求失败：{exc}"


def normalize_phone_digits(phone: str | None) -> str:
    return "".join(character for character in (phone or "") if character.isdigit())


def unavailable_secret(prompt: str) -> str:
    raise CredentialApiError(f"自动任务无法交互读取：{prompt.rstrip(': ')}。")


def describe_task_error(exc: Exception) -> str:
    if isinstance(exc, RPCError):
        return describe_rpc_error(exc)
    if isinstance(exc, CredentialApiError):
        return f"凭据接口错误：{exc}"
    if isinstance(exc, ClientSetupError):
        return f"客户端环境错误：{exc}"
    if isinstance(exc, OSError):
        return f"网络或系统错误：{exc}"
    return str(exc) or exc.__class__.__name__


async def execute_batch_task(
    task: BatchTask,
    *,
    new_password: str,
    hint: str,
    poll_interval: float,
    poll_timeout: float,
    staging_root: Path,
    export_root: Path,
) -> ExportResult:
    """Run one isolated account flow and leave only the final ZIP files."""
    staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging_root.chmod(0o700)
    export_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    export_root.chmod(0o700)

    credential_client = CredentialApiClient(
        task.credential_url,
        poll_interval=poll_interval,
        timeout=poll_timeout,
    )
    baseline = await credential_client.fetch()

    with tempfile.TemporaryDirectory(
        prefix=f".{phone_slug(task.phone)}-",
        dir=staging_root,
    ) as temporary_directory:
        staging_dir = Path(temporary_directory)
        session_path = staging_dir / f"{phone_slug(task.phone)}.session"
        client = create_telegram_client(session_path)
        try:
            await client.connect()
            current_password = await authenticate(
                client,
                task.phone,
                secret_fn=unavailable_secret,
                credential_client=credential_client,
                baseline=baseline,
            )
            me = await client.get_me()
            expected_phone = normalize_phone_digits(task.phone)
            actual_phone = normalize_phone_digits(getattr(me, "phone", None))
            if not actual_phone or actual_phone != expected_phone:
                raise ValueError(
                    "登录账号手机号与任务不一致，已停止修改和导出。"
                )

            if current_password != new_password:
                changed = await update_two_factor_password(
                    client,
                    current_password=current_password,
                    new_password=new_password,
                    hint=hint,
                    email=None,
                    secret_fn=unavailable_secret,
                )
                if not changed:
                    raise RuntimeError("Telegram 未修改 2FA 设置。")

            password_state = await client(functions.account.GetPasswordRequest())
            if not password_state.has_password:
                raise RuntimeError("2FA 状态复核失败，账号仍未启用密码。")

            return await export_account_artifacts(
                client,
                me,
                phone=task.phone,
                current_password=new_password,
                session_path=session_path,
                staging_dir=staging_dir,
                export_root=export_root,
            )
        finally:
            await client.disconnect()


def generate_random_2fa(length: int) -> str:
    if not 12 <= length <= 64:
        raise ValueError("随机 2FA 密码长度必须在 12 到 64 之间。")
    return "".join(secrets.choice(RANDOM_2FA_ALPHABET) for _ in range(length))


def load_worker_config(config_argument: str | None) -> tuple[dict[str, object], Path]:
    config_path = Path(config_argument or "config.toml").expanduser()
    if not config_path.is_absolute():
        config_path = (Path.cwd() / config_path).resolve()
    if not config_path.exists():
        if config_argument:
            raise ValueError(f"Worker 配置文件不存在：{config_path}")
        return {}, Path.cwd()

    try:
        with config_path.open("rb") as source:
            payload = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"无法读取 Worker 配置文件：{config_path}") from exc

    worker = payload.get("worker", {})
    if not isinstance(worker, dict):
        raise ValueError("Worker 配置中的 [worker] 必须是 TOML 表。")
    return worker, config_path.parent


def resolve_config_path(value: object, base_dir: Path) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def resolve_worker_settings(
    args: argparse.Namespace,
    environ: Mapping[str, str],
) -> WorkerSettings:
    config, config_dir = load_worker_config(args.config)

    bot_value = args.bot_token or environ.get("TG_BOT_TOKEN") or config.get("bot_token")
    if bot_value is not None and not isinstance(bot_value, str):
        raise ValueError("配置项 worker.bot_token 必须是字符串。")
    bot_token = (bot_value or "").strip()
    if not bot_token:
        raise ValueError("Worker 缺少 Bot Token，请填写 config.toml。")

    admin_value: object = (
        args.admin_id or environ.get("TG_ADMIN_ID") or config.get("admin_id")
    )
    try:
        admin_id = int(str(admin_value))
    except (TypeError, ValueError) as exc:
        raise ValueError("Worker 缺少有效管理员用户 ID，请填写 config.toml。") from exc
    if admin_id <= 0:
        raise ValueError("管理员用户 ID 必须是正整数。")

    source_value: object = (
        args.source_chat_id
        if args.source_chat_id is not None
        else environ.get("TG_SOURCE_CHAT_ID") or config.get("source_chat_id")
    )
    if source_value is None:
        source_chat_id = None
    else:
        try:
            source_chat_id = int(str(source_value))
        except (TypeError, ValueError) as exc:
            raise ValueError("监听群 ID 必须是整数。") from exc
        if source_chat_id == 0:
            raise ValueError("监听群 ID 不能为 0。")

    length_value = (
        args.new_2fa_length
        if args.new_2fa_length is not None
        else environ.get("TG_NEW_2FA_LENGTH") or config.get("new_2fa_length", 16)
    )
    try:
        new_password_length = int(str(length_value))
    except (TypeError, ValueError) as exc:
        raise ValueError("随机 2FA 密码长度必须是整数。") from exc
    if not 12 <= new_password_length <= 64:
        raise ValueError("随机 2FA 密码长度必须在 12 到 64 之间。")

    hint_value = args.hint if args.hint is not None else config.get("hint", "")
    if not isinstance(hint_value, str):
        raise ValueError("配置项 worker.hint 必须是字符串。")
    hint = hint_value.strip()
    if args.email:
        raise ValueError("Worker 模式暂不支持需要交互确认的恢复邮箱。")
    if args.export_only:
        raise ValueError("Worker 模式固定执行 2FA 更新，不能使用 --export-only。")

    try:
        poll_interval = float(
            args.poll_interval
            if args.poll_interval is not None
            else config.get("poll_interval", 2.0)
        )
        poll_timeout = float(
            args.poll_timeout
            if args.poll_timeout is not None
            else config.get("poll_timeout", 180.0)
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Worker 轮询间隔和超时时间必须是数字。") from exc
    if poll_interval <= 0 or poll_timeout <= 0:
        raise ValueError("轮询间隔和超时时间必须大于 0。")

    state_value = (
        args.worker_state_dir
        or environ.get("TG_WORKER_STATE_DIR")
        or config.get("state_dir")
        or "worker-state"
    )
    state_dir = resolve_config_path(state_value, config_dir)
    export_value = (
        args.export_dir or environ.get("TG_EXPORT_DIR") or config.get("export_dir")
    )
    export_root = (
        resolve_config_path(export_value, config_dir)
        if export_value
        else state_dir / "artifacts"
    )

    keep_value = config.get("keep_artifacts", True)
    if not isinstance(keep_value, bool):
        raise ValueError("配置项 worker.keep_artifacts 必须是 true 或 false。")
    return WorkerSettings(
        bot_token=bot_token,
        admin_id=admin_id,
        source_chat_id=source_chat_id,
        new_password_length=new_password_length,
        hint=hint,
        poll_interval=poll_interval,
        poll_timeout=poll_timeout,
        state_dir=state_dir,
        export_root=export_root,
        keep_artifacts=(
            args.keep_artifacts if args.keep_artifacts is not None else keep_value
        ),
    )


def should_accept_worker_message(
    settings: WorkerSettings,
    *,
    sender_id: int | None,
    chat_id: int | None,
) -> bool:
    if settings.source_chat_id is not None:
        return chat_id == settings.source_chat_id
    return sender_id == settings.admin_id


async def process_worker_queue(
    bot: TelegramClient,
    queue: asyncio.Queue[BatchTask | None],
    ledger: TaskLedger,
    *,
    admin_id: int,
    new_password_length: int,
    hint: str,
    poll_interval: float,
    poll_timeout: float,
    staging_root: Path,
    export_root: Path,
    keep_artifacts: bool,
) -> None:
    while True:
        task = await queue.get()
        try:
            if task is None:
                return

            ledger.mark(task, "running")
            try:
                await bot.send_message(admin_id, f"开始处理 {task.phone}")
            except Exception as exc:
                print(
                    f"无法发送任务开始通知：{describe_task_error(exc)}",
                    file=sys.stderr,
                )
            try:
                new_password = generate_random_2fa(new_password_length)
                result = await execute_batch_task(
                    task,
                    new_password=new_password,
                    hint=hint,
                    poll_interval=poll_interval,
                    poll_timeout=poll_timeout,
                    staging_root=staging_root,
                    export_root=export_root,
                )
                await bot.send_file(
                    admin_id,
                    str(result.session_zip),
                    caption=(
                        f"{task.phone} Session\n"
                        f"2FA: {new_password}\n"
                        f"SHA256: {result.session_sha256}"
                    ),
                    force_document=True,
                )
                await bot.send_file(
                    admin_id,
                    str(result.tdata_zip),
                    caption=(
                        f"{task.phone} TData\n"
                        f"2FA: {new_password}\n"
                        f"SHA256: {result.tdata_sha256}"
                    ),
                    force_document=True,
                )
            except Exception as exc:
                detail = describe_task_error(exc)
                ledger.mark(task, "failed", detail)
                try:
                    await bot.send_message(admin_id, f"{task.phone} 处理失败：{detail}")
                except Exception as notification_exc:
                    print(
                        "无法发送任务失败通知："
                        f"{describe_task_error(notification_exc)}",
                        file=sys.stderr,
                    )
            else:
                ledger.mark(task, "succeeded")
                if not keep_artifacts:
                    shutil.rmtree(result.output_dir, ignore_errors=True)
        finally:
            queue.task_done()


async def run_worker(args: argparse.Namespace) -> int:
    settings = resolve_worker_settings(args, os.environ)
    admin_id = settings.admin_id
    state_dir = settings.state_dir
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_dir.chmod(0o700)
    staging_root = state_dir / "staging"
    ledger = TaskLedger(state_dir / "tasks.json")
    queue: asyncio.Queue[BatchTask | None] = asyncio.Queue()
    bot = create_telegram_client(
        state_dir / "worker-bot.session",
        receive_updates=True,
    )

    @bot.on(events.NewMessage(incoming=True))
    async def handle_admin_message(event: events.NewMessage.Event) -> None:
        if not should_accept_worker_message(
            settings,
            sender_id=event.sender_id,
            chat_id=event.chat_id,
        ):
            return

        message = event.raw_text or ""
        command = message.strip().split(maxsplit=1)[0].lower() if message.strip() else ""
        if command in {"/start", "/help"}:
            if event.sender_id != admin_id:
                return
            await bot.send_message(
                admin_id,
                "发送任务格式：\n"
                "+手机号 --- 登录链接\n"
                "+手机号 --- https://.../getcode?id=...\n"
                "指定群内任何成员均可投递，结果只私聊管理员。"
            )
            return
        if command == "/status":
            if event.sender_id != admin_id:
                return
            counts: dict[str, int] = {}
            for record in ledger.records.values():
                status = record.get("status", "unknown")
                counts[status] = counts.get(status, 0) + 1
            summary = ", ".join(
                f"{status}={count}" for status, count in sorted(counts.items())
            ) or "暂无任务"
            await bot.send_message(admin_id, f"队列={queue.qsize()}；{summary}")
            return

        tasks, invalid = parse_batch_tasks(message)
        queued = 0
        succeeded = 0
        pending = 0
        for task in tasks:
            reservation = ledger.reserve(task)
            if reservation == "queued":
                await queue.put(task)
                queued += 1
            elif reservation == "succeeded":
                succeeded += 1
            else:
                pending += 1

        if not tasks and invalid == 0:
            return
        sender_description = event.sender_id if event.sender_id is not None else "unknown"
        await bot.send_message(
            admin_id,
            f"已入队 {queued} 个；已完成跳过 {succeeded} 个；"
            f"处理中跳过 {pending} 个；无效/不完整 {invalid} 组；"
            f"来源用户={sender_description}。"
        )

    await bot.start(bot_token=settings.bot_token)
    me = await bot.get_me()
    processor = asyncio.create_task(
        process_worker_queue(
            bot,
            queue,
            ledger,
            admin_id=admin_id,
            new_password_length=settings.new_password_length,
            hint=settings.hint,
            poll_interval=settings.poll_interval,
            poll_timeout=settings.poll_timeout,
            staging_root=staging_root,
            export_root=settings.export_root,
            keep_artifacts=settings.keep_artifacts,
        )
    )
    source_description = settings.source_chat_id or "管理员私聊及所在会话"
    print(
        f"Worker 已启动：@{getattr(me, 'username', None) or me.id}，"
        f"监听={source_description}"
    )
    try:
        try:
            await bot.send_message(admin_id, "TG 2FA worker 已上线，发送 /help 查看格式。")
        except Exception as exc:
            print(
                f"无法发送上线通知，将继续等待管理员消息：{describe_task_error(exc)}",
                file=sys.stderr,
            )
        await bot.run_until_disconnected()
    finally:
        processor.cancel()
        try:
            await processor
        except asyncio.CancelledError:
            pass
        await bot.disconnect()
    return 0


async def run(args: argparse.Namespace) -> int:
    if args.poll_interval is None:
        args.poll_interval = 2.0
    if args.poll_timeout is None:
        args.poll_timeout = 180.0
    phone = resolve_phone(args, os.environ)
    if args.export_only and not args.export_dir:
        raise ValueError("使用 --export-only 时必须同时提供 --export-dir。")

    credential_url = resolve_credential_url(args, os.environ)
    credential_client = (
        CredentialApiClient(
            credential_url,
            poll_interval=args.poll_interval,
            timeout=args.poll_timeout,
        )
        if credential_url
        else None
    )
    export_temp: tempfile.TemporaryDirectory[str] | None = None
    staging_dir: Path | None = None
    session_path: Path | None = None
    export_root: Path | None = None
    if args.export_dir:
        export_root = Path(args.export_dir).expanduser().resolve()
        export_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        export_root.chmod(0o700)
        export_temp = tempfile.TemporaryDirectory(
            prefix=f".{phone_slug(phone)}-",
            dir=export_root,
        )
        staging_dir = Path(export_temp.name)
        session_path = staging_dir / f"{phone_slug(phone)}.session"

    client = create_telegram_client(session_path)

    try:
        baseline = None
        if credential_client:
            baseline = await credential_client.fetch()
            print("凭据接口连接正常，已记录旧数据基线。")
        await client.connect()
        current_password = await authenticate(
            client,
            phone,
            credential_client=credential_client,
            baseline=baseline,
        )
        me = await client.get_me()
        username = f"@{me.username}" if me.username else "未设置"
        print(
            f"已登录账号：id={me.id}，username={username}，"
            f"phone={mask_phone(me.phone)}"
        )

        if not args.yes:
            action = "导出该账号协议包" if args.export_only else "修改该账号的 2FA 密码"
            confirmed = input(f"确认{action}？[y/N]: ").strip().lower()
            if confirmed not in {"y", "yes"}:
                print("已取消，未执行账号操作。")
                return 1

        if args.export_only:
            assert export_root is not None
            assert staging_dir is not None
            assert session_path is not None
            result = await export_account_artifacts(
                client,
                me,
                phone=phone,
                current_password=current_password,
                session_path=session_path,
                staging_dir=staging_dir,
                export_root=export_root,
            )
            print(f"Session 协议包：{result.session_zip}")
            print(f"TData 包：{result.tdata_zip}")
            print(f"Session SHA256：{result.session_sha256}")
            print(f"TData SHA256：{result.tdata_sha256}")
            return 0

        new_password = prompt_new_password()
        if current_password is not None and new_password == current_password:
            raise ValueError("新密码不能与当前 2FA 密码相同。")

        hint = args.hint
        if hint is None:
            hint = input("密码提示（可留空）: ").strip()
        else:
            hint = hint.strip()
        if hint == new_password:
            raise ValueError("密码提示不能与新密码相同。")

        email = args.email
        if email is None:
            email = input("恢复邮箱（可留空）: ").strip() or None
        else:
            email = email.strip() or None

        print("正在提交新的 2FA 设置，此步骤可能需要一些时间……")
        changed = await update_two_factor_password(
            client,
            current_password=current_password,
            new_password=new_password,
            hint=hint,
            email=email,
        )
        if not changed:
            print("Telegram 未修改 2FA 设置。", file=sys.stderr)
            return 1

        print("2FA 密码已成功启用或修改。")
        if export_root and staging_dir and session_path:
            result = await export_account_artifacts(
                client,
                me,
                phone=phone,
                current_password=new_password,
                session_path=session_path,
                staging_dir=staging_dir,
                export_root=export_root,
            )
            print(f"Session 协议包：{result.session_zip}")
            print(f"TData 包：{result.tdata_zip}")
            print(f"Session SHA256：{result.session_sha256}")
            print(f"TData SHA256：{result.tdata_sha256}")
        return 0
    finally:
        await client.disconnect()
        if export_temp:
            export_temp.cleanup()


def main() -> int:
    args = build_parser().parse_args()
    try:
        coroutine = run_worker(args) if args.worker else run(args)
        return asyncio.run(coroutine)
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
        return 130
    except ValueError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    except RPCError as exc:
        print(f"错误：{describe_rpc_error(exc)}", file=sys.stderr)
        return 3
    except CredentialApiError as exc:
        print(f"凭据接口错误：{exc}", file=sys.stderr)
        return 4
    except ClientSetupError as exc:
        print(f"客户端环境错误：{exc}", file=sys.stderr)
        return 5
    except OSError as exc:
        print(f"网络或系统错误：{exc}", file=sys.stderr)
        return 6


if __name__ == "__main__":
    raise SystemExit(main())
