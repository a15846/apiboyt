# Automatically enable Playwright fallback when Python starts
try:
    import tg_2fa_playwright_fallback  # noqa: F401
except Exception:
    pass
