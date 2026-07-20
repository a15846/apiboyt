"""
Playwright fallback to render JS pages and extract verification code
from dynamically rendered credential pages.

Importing this module monkey‑patches ``CredentialApiClient._fetch_sync``
to retry via Playwright when the initial static request does not
return a usable ``code``.
"""

from __future__ import annotations

import os
import re
from typing import Optional, TYPE_CHECKING

try:
    from playwright.sync_api import sync_playwright  # type: ignore
except ImportError:  # Playwright not installed – fallback disabled
    sync_playwright = None  # type: ignore[assignment]

if TYPE_CHECKING:  # pragma: no cover
    from tg_2fa import CredentialApiClient  # noqa: F401


_CODE_PATTERN = re.compile(r"\b\d{4,8}\b")


def _extract_code(text: str) -> Optional[str]:
    """Return the first 4‑8‑digit number in *text*, if any."""

    match = _CODE_PATTERN.search(text)
    return match.group(0) if match else None


def _patch(client_cls):  # type: ignore[override]
    """Monkey‑patch *client_cls* (``CredentialApiClient``) in‑place."""

    original_fetch_sync = client_cls._fetch_sync  # type: ignore[attr-defined]

    def patched(self, *args, **kwargs):  # type: ignore[override]
        snapshot = original_fetch_sync(self, *args, **kwargs)
        if snapshot.code or os.getenv("FORCE_NO_BROWSER") == "1":
            return snapshot

        if sync_playwright is None:
            return snapshot  # Playwright unavailable – keep original result

        # Use Playwright to render the page and grab the HTML
        with sync_playwright() as pw:
            browser_kind = os.getenv("PLAYWRIGHT_BROWSER", "chromium")
            browser = getattr(pw, browser_kind).launch(headless=True)
            page = browser.new_page()
            page.goto(self.url, timeout=self.timeout * 1000)
            try:
                page.wait_for_function(
                    "document.body && /\\d{4,8}/.test(document.body.innerText)",
                    timeout=self.timeout * 1000,
                )
            except Exception:
                browser.close()
                return snapshot  # Still no code
            html = page.content()
            browser.close()

        # Re‑use the existing parser from ``tg_2fa``
        from tg_2fa import parse_credential_payload  # type: ignore

        new_snapshot = parse_credential_payload(html.encode(), "text/html")
        return new_snapshot if new_snapshot.code else snapshot

    client_cls._fetch_sync = patched  # type: ignore[attr-defined]


# Apply patch automatically on import
try:
    from tg_2fa import CredentialApiClient  # type: ignore

    _patch(CredentialApiClient)
except Exception:
    # If ``tg_2fa`` isn't importable yet, user can import patch later.
    pass
