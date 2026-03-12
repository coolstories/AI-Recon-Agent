"""
Stealth browser module using Playwright headless Chromium.
Falls back to requests if Playwright is unavailable.
Used by exploit.py and crawler when sites block direct HTTP requests.
"""

import asyncio
import hashlib
import time
import re
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


@dataclass
class StealthResponse:
    """Mimics requests.Response interface for drop-in compatibility."""
    status_code: int = 0
    text: str = ""
    url: str = ""
    headers: dict = field(default_factory=dict)
    _cookies: dict = field(default_factory=dict)

    @property
    def cookies(self):
        return _CookieJar(self._cookies)

    def json(self):
        import json
        return json.loads(self.text)


class _CookieJar:
    def __init__(self, d):
        self._d = d
    def get_dict(self):
        return self._d
    def get(self, key, default=None):
        return self._d.get(key, default)


# Singleton browser context to avoid spawning a new browser per request
_browser_ctx = {
    "browser": None,
    "context": None,
    "lock": asyncio.Lock() if PLAYWRIGHT_AVAILABLE else None,
    "pw": None,
}


async def _ensure_browser():
    """Launch browser once and reuse."""
    if not PLAYWRIGHT_AVAILABLE:
        return None, None
    if _browser_ctx["browser"] is not None:
        return _browser_ctx["browser"], _browser_ctx["context"]

    pw = await async_playwright().start()
    _browser_ctx["pw"] = pw
    browser = await pw.chromium.launch(
        headless=True,
        args=[
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
        ],
    )
    context = await browser.new_context(
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        viewport={"width": 1920, "height": 1080},
        locale="en-US",
        timezone_id="America/New_York",
        java_script_enabled=True,
        ignore_https_errors=True,
        extra_http_headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        },
    )
    # Anti-detection: override navigator.webdriver
    await context.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
        Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
        window.chrome = {runtime: {}};
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) =>
            parameters.name === 'notifications'
                ? Promise.resolve({state: Notification.permission})
                : originalQuery(parameters);
    """)
    _browser_ctx["browser"] = browser
    _browser_ctx["context"] = context
    return browser, context


async def _stealth_get_async(url, timeout=30):
    """Fetch a URL using stealth headless Chromium."""
    _, context = await _ensure_browser()
    if context is None:
        return None

    page = await context.new_page()
    try:
        response = await page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
        # Wait a bit for JS to execute (Cloudflare challenge, etc.)
        await page.wait_for_timeout(2000)

        # If Cloudflare challenge detected, wait longer
        content = await page.content()
        if "challenge-platform" in content or "Just a moment" in content or "Checking your browser" in content:
            await page.wait_for_timeout(5000)
            content = await page.content()

        status = response.status if response else 0
        final_url = page.url
        headers = {}
        if response:
            for h in await response.all_headers():
                headers[h] = await response.header_value(h) if hasattr(response, 'header_value') else ""
            # Simpler approach
            headers = dict(await response.all_headers()) if response else {}

        # Get cookies
        cookies_list = await context.cookies(url)
        cookies_dict = {c["name"]: c["value"] for c in cookies_list}

        return StealthResponse(
            status_code=status,
            text=content,
            url=final_url,
            headers=headers,
            _cookies=cookies_dict,
        )
    except Exception as e:
        return StealthResponse(status_code=0, text=f"Browser error: {str(e)}", url=url)
    finally:
        await page.close()


async def _stealth_post_async(url, data=None, timeout=30):
    """POST using stealth browser via page.evaluate(fetch(...))."""
    _, context = await _ensure_browser()
    if context is None:
        return None

    page = await context.new_page()
    try:
        # Navigate to the page first to set up cookies/session
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        await page.goto(base, timeout=timeout * 1000, wait_until="domcontentloaded")
        await page.wait_for_timeout(1000)

        # POST via fetch inside the page context
        if isinstance(data, dict):
            import json
            body_str = "&".join(f"{k}={v}" for k, v in data.items())
            content_type = "application/x-www-form-urlencoded"
        elif isinstance(data, str):
            body_str = data
            content_type = "application/x-www-form-urlencoded"
        else:
            body_str = ""
            content_type = "application/x-www-form-urlencoded"

        result = await page.evaluate(f"""
            async () => {{
                const resp = await fetch("{url}", {{
                    method: "POST",
                    headers: {{"Content-Type": "{content_type}"}},
                    body: `{body_str}`,
                    redirect: "follow",
                }});
                const text = await resp.text();
                const headers = {{}};
                resp.headers.forEach((v, k) => headers[k] = v);
                return {{status: resp.status, text: text, url: resp.url, headers: headers}};
            }}
        """)

        cookies_list = await context.cookies(url)
        cookies_dict = {c["name"]: c["value"] for c in cookies_list}

        return StealthResponse(
            status_code=result.get("status", 0),
            text=result.get("text", ""),
            url=result.get("url", url),
            headers=result.get("headers", {}),
            _cookies=cookies_dict,
        )
    except Exception as e:
        return StealthResponse(status_code=0, text=f"Browser POST error: {str(e)}", url=url)
    finally:
        await page.close()


def _run_async(coro):
    """Run async code from sync context, handling existing event loops."""
    try:
        loop = asyncio.get_running_loop()
        # We're inside an existing event loop — use nest_asyncio or thread
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(lambda: asyncio.run(coro)).result(timeout=60)
    except RuntimeError:
        # No running event loop
        return asyncio.run(coro)


def stealth_get(url, timeout=30):
    """Synchronous stealth GET. Returns StealthResponse or None if unavailable."""
    if not PLAYWRIGHT_AVAILABLE:
        return None
    return _run_async(_stealth_get_async(url, timeout))


def stealth_post(url, data=None, timeout=30):
    """Synchronous stealth POST. Returns StealthResponse or None."""
    if not PLAYWRIGHT_AVAILABLE:
        return None
    return _run_async(_stealth_post_async(url, data, timeout))


async def close_browser():
    """Cleanup — call when done."""
    if _browser_ctx["browser"]:
        await _browser_ctx["browser"].close()
        _browser_ctx["browser"] = None
        _browser_ctx["context"] = None
    if _browser_ctx["pw"]:
        await _browser_ctx["pw"].stop()
        _browser_ctx["pw"] = None
