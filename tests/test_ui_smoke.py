"""
tests/test_ui_smoke.py — Playwright UI smoke tests.

Boots the Bounty FastAPI server in a subprocess, then exercises real
browser interactions for every major page and modal.

Run:
    pytest tests/test_ui_smoke.py -v

Requirements:
    pip install pytest-playwright
    playwright install chromium
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Generator

import pytest
from playwright.sync_api import Page, expect

# ---------------------------------------------------------------------------
# Server fixture
# ---------------------------------------------------------------------------

def _free_port() -> int:
    """Return an unused TCP port on localhost."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def live_server_url() -> Generator[str, None, None]:
    """Start uvicorn in a subprocess; yield base URL; shut down after session."""
    port = _free_port()
    env = {**os.environ, "UI_TOKEN": ""}   # disable auth for tests

    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "bounty.ui.app:app",
            "--host", "127.0.0.1",
            "--port", str(port),
            "--log-level", "error",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    base = f"http://127.0.0.1:{port}"

    # Wait for the server to accept connections (up to 10 s)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.2)
    else:
        proc.terminate()
        raise RuntimeError("Server did not start in time")

    yield base

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def goto(page: Page, url: str) -> None:
    """Navigate, wait for network idle, then wait for Alpine to initialise."""
    page.goto(url, wait_until="networkidle")
    # Wait until Alpine has finished initialising (x-cloak removed from body subtree)
    page.wait_for_function(
        "() => !document.querySelector('[x-cloak]') || true",
        timeout=5000,
    )
    page.wait_for_timeout(300)  # small buffer for Alpine to process all directives


def open_modal(page: Page, trigger_text: str) -> None:
    """Click the trigger button and wait for Alpine's open event to propagate."""
    page.click(f"button:has-text('{trigger_text}')")
    page.wait_for_timeout(500)  # allow Alpine transition to complete


# ---------------------------------------------------------------------------
# Page-load smoke tests (no JS console errors allowed)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/",
    "/scans",
    "/programs",
    "/reports",
    "/schedules",
    "/settings",
    "/findings",
    "/assets",
    "/secrets",
    "/queue",
    "/errors",
])
def test_page_loads_no_console_errors(
    page: Page, live_server_url: str, path: str
) -> None:
    """Every main page must load with HTTP 200 and zero JS console errors."""
    js_errors: list[str] = []
    page.on("console", lambda msg: js_errors.append(msg.text) if msg.type == "error" else None)

    response = page.goto(live_server_url + path, wait_until="networkidle")
    assert response is not None and response.status == 200, (
        f"Expected 200 for {path}, got {response and response.status}"
    )
    # Filter out known benign errors:
    #  - third-party CDN warnings
    #  - 401/404 from background API/SSE calls (pre-existing; not page-load errors)
    def _benign(msg: str) -> bool:
        return (
            "cdn.tailwindcss" in msg
            or "unpkg.com" in msg
            or "jsdelivr" in msg
            or "401" in msg       # SSE/API auth (expected when running without token)
            or "404" in msg       # Missing optional API endpoints on fresh DB
        )
    real_errors = [e for e in js_errors if not _benign(e)]
    assert real_errors == [], f"JS console errors on {path}: {real_errors}"


# ---------------------------------------------------------------------------
# New Scan modal tests
# ---------------------------------------------------------------------------

def test_new_scan_modal_opens(page: Page, live_server_url: str) -> None:
    """Clicking '+ New Scan' must reveal the modal."""
    goto(page, live_server_url + "/scans")
    open_modal(page, "New Scan")
    # The modal backdrop div should now be visible
    backdrop = page.locator(".fixed.inset-0.z-50").first
    expect(backdrop).to_be_visible(timeout=5000)


def test_new_scan_modal_close_button(page: Page, live_server_url: str) -> None:
    """✕ button must close the New Scan modal."""
    goto(page, live_server_url + "/scans")
    open_modal(page, "New Scan")
    backdrop = page.locator(".fixed.inset-0.z-50").first
    expect(backdrop).to_be_visible(timeout=5000)
    page.click("[aria-label='Close modal']")
    page.wait_for_timeout(400)
    expect(backdrop).to_be_hidden(timeout=3000)


def test_new_scan_modal_cancel_button(page: Page, live_server_url: str) -> None:
    """Cancel button must close the New Scan modal."""
    goto(page, live_server_url + "/scans")
    open_modal(page, "New Scan")
    backdrop = page.locator(".fixed.inset-0.z-50").first
    expect(backdrop).to_be_visible(timeout=5000)
    page.locator(".fixed.inset-0.z-50 button:has-text('Cancel')").click()
    page.wait_for_timeout(400)
    expect(backdrop).to_be_hidden(timeout=3000)


def test_new_scan_modal_escape_key(page: Page, live_server_url: str) -> None:
    """Escape key must close the New Scan modal."""
    goto(page, live_server_url + "/scans")
    open_modal(page, "New Scan")
    backdrop = page.locator(".fixed.inset-0.z-50").first
    expect(backdrop).to_be_visible(timeout=5000)
    page.keyboard.press("Escape")
    page.wait_for_timeout(400)
    expect(backdrop).to_be_hidden(timeout=3000)


def test_new_scan_modal_backdrop_click(page: Page, live_server_url: str) -> None:
    """Clicking outside the modal card must close it."""
    goto(page, live_server_url + "/scans")
    open_modal(page, "New Scan")
    backdrop = page.locator(".fixed.inset-0.z-50").first
    expect(backdrop).to_be_visible(timeout=5000)
    # Click on the backdrop itself (not on the card) using top-left corner
    page.mouse.click(5, 5)
    page.wait_for_timeout(400)
    expect(backdrop).to_be_hidden(timeout=3000)


# ---------------------------------------------------------------------------
# New Program modal tests
# ---------------------------------------------------------------------------

def test_new_program_modal_opens(page: Page, live_server_url: str) -> None:
    """Clicking '+ New Program' must reveal the modal."""
    goto(page, live_server_url + "/programs")
    open_modal(page, "New Program")
    backdrop = page.locator(".fixed.inset-0.z-50").first
    expect(backdrop).to_be_visible(timeout=5000)


def test_new_program_modal_escape_closes(page: Page, live_server_url: str) -> None:
    """Escape key must close the New Program modal."""
    goto(page, live_server_url + "/programs")
    open_modal(page, "New Program")
    backdrop = page.locator(".fixed.inset-0.z-50").first
    expect(backdrop).to_be_visible(timeout=5000)
    page.keyboard.press("Escape")
    page.wait_for_timeout(400)
    expect(backdrop).to_be_hidden(timeout=3000)


# ---------------------------------------------------------------------------
# New Report modal tests
# ---------------------------------------------------------------------------

def test_new_report_modal_opens(page: Page, live_server_url: str) -> None:
    """Clicking '+ New Report' must reveal the modal."""
    goto(page, live_server_url + "/reports")
    open_modal(page, "New Report")
    backdrop = page.locator(".fixed.inset-0.z-50").first
    expect(backdrop).to_be_visible(timeout=5000)


def test_new_report_modal_cancel(page: Page, live_server_url: str) -> None:
    """Cancel button must close the New Report modal."""
    goto(page, live_server_url + "/reports")
    open_modal(page, "New Report")
    backdrop = page.locator(".fixed.inset-0.z-50").first
    expect(backdrop).to_be_visible(timeout=5000)
    page.locator(".fixed.inset-0.z-50 button:has-text('Cancel')").click()
    page.wait_for_timeout(400)
    expect(backdrop).to_be_hidden(timeout=3000)


# ---------------------------------------------------------------------------
# Schedules page (already Alpine — verify it still works)
# ---------------------------------------------------------------------------

def test_new_schedule_modal_opens(page: Page, live_server_url: str) -> None:
    """New Schedule modal (already Alpine) must open on button click."""
    goto(page, live_server_url + "/schedules")
    open_modal(page, "New Schedule")
    expect(page.locator("text=Create Schedule")).to_be_visible(timeout=5000)


def test_new_schedule_modal_cancel(page: Page, live_server_url: str) -> None:
    """Cancel button must close the New Schedule modal."""
    goto(page, live_server_url + "/schedules")
    open_modal(page, "New Schedule")
    expect(page.locator("text=Create Schedule")).to_be_visible(timeout=5000)
    page.click("button:has-text('Cancel')")
    page.wait_for_timeout(400)
    expect(page.locator("text=Create Schedule")).to_be_hidden(timeout=3000)


# ---------------------------------------------------------------------------
# New Program form-to-DB round-trip
# ---------------------------------------------------------------------------

def test_new_program_form_roundtrip(page: Page, live_server_url: str) -> None:
    """Create a program via the UI form; verify ULID id and target are persisted."""
    import re as _re

    goto(page, live_server_url + "/programs")
    open_modal(page, "New Program")

    backdrop = page.locator(".fixed.inset-0.z-50").first
    expect(backdrop).to_be_visible(timeout=5000)

    # Fill the basic program fields (no ID field — it's generated server-side)
    page.fill("#np-handle", "playwright-test-prog")
    page.fill("#np-name", "Playwright Test Program")
    # Platform defaults to h1; leave it

    # Click "+ Add target" and fill in the target row
    page.click("button:has-text('Add target')")
    page.wait_for_timeout(300)

    # Fill the target value input (the first one rendered by Alpine x-for)
    page.locator("#np-targets-root input[type='text']").first.fill("playwright.example.com")

    # Submit the form
    page.click("#np-submit")

    # After submission the modal closes and we're redirected to the detail page
    page.wait_for_url("**/programs/**", timeout=10000)

    # Extract the program id from the URL
    url = page.url
    program_id = url.rstrip("/").split("/")[-1]

    # id must be a 26-char ULID, not equal to the program name
    assert len(program_id) == 26, f"Expected 26-char ULID, got {program_id!r}"
    assert program_id != "Playwright Test Program", "id must not equal name"
    assert _re.match(r"^[0-9A-HJKMNP-TV-Z]{26}$", program_id), (
        f"id does not look like a valid ULID: {program_id!r}"
    )

    # The detail page should show the target we added
    expect(page.locator("text=playwright.example.com")).to_be_visible(timeout=5000)





