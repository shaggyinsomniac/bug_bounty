# UI Audit Report

**Date:** 2026-05-16  
**Scope:** `bounty/ui/templates/**/*.html`  
**Methodology:** Static grep analysis + pattern classification

---

## Classification Key

| Label | Meaning |
|-------|---------|
| `LIKELY_BROKEN` | Pattern is known to fail on real mouse clicks or produce incorrect behaviour |
| `NEEDS_INSPECTION` | Pattern may work but is fragile / non-standard |
| `OK` | Pattern is correct and idiomatic |
| `FIXED` | Was LIKELY_BROKEN; refactored in this PR |

---

## Summary

| Category | Count |
|----------|-------|
| Native `<dialog>` modals with `.showModal()` | 8 |
| `onclick=` attributes (LIKELY_BROKEN modals) | 8 open-triggers → **FIXED** |
| `onclick=` attributes (utility / action calls) | ~40 (OK – calling JS functions, not opening dialogs) |
| `<a href="#">` fake buttons | 1 (empty-state fallback, NEEDS_INSPECTION) |
| Buttons with no handler | 0 |
| HTMX `hx-target` referencing non-existent IDs | 0 found |

---

## Page-by-Page Findings

### `/scans` → `scans/list.html`

| Element | Pattern | Classification | Action |
|---------|---------|----------------|--------|
| **New Scan** button | `onclick="document.getElementById('new-scan-modal').showModal()"` | **LIKELY_BROKEN** | **FIXED** — converted to Alpine `@click="$dispatch('open-new-scan-modal')"` |
| `<dialog id="new-scan-modal">` | Native `<dialog>` | **LIKELY_BROKEN** | **FIXED** — replaced with Alpine `x-show` overlay |
| Close / Cancel buttons inside modal | `onclick="...close()"` | LIKELY_BROKEN | **FIXED** — converted to `@click` + `closeModal()` |
| Filter `<form method="get">` | Explicit `action="/scans"` | OK | No change |
| Pagination links | Proper `href="/scans?offset=..."` | OK | No change |
| Empty-state `<a href="#">` | `href="#"` fallback button | NEEDS_INSPECTION | Left as-is (renders only when no scans exist) |

---

### `/programs` → `programs/list.html`

| Element | Pattern | Classification | Action |
|---------|---------|----------------|--------|
| **New Program** button | `onclick="...showModal()"` | **LIKELY_BROKEN** | **FIXED** |
| `<dialog id="new-program-modal">` | Native `<dialog>` | **LIKELY_BROKEN** | **FIXED** |
| Filter button | `onclick="applyProgramFilters()"` | OK – calls JS util | No change |
| Close / Cancel inside modal | `onclick="...close()"` | LIKELY_BROKEN | **FIXED** |

---

### `/programs/:id` → `programs/detail.html`

| Element | Pattern | Classification | Action |
|---------|---------|----------------|--------|
| **Edit Scope** button | `onclick="...getElementById('edit-scope-modal').showModal()"` | **LIKELY_BROKEN** | **FIXED** |
| **Run Scan** button | `onclick="...getElementById('run-scan-modal').showModal()"` | **LIKELY_BROKEN** | **FIXED** |
| `<dialog id="edit-scope-modal">` | Native `<dialog>` | **LIKELY_BROKEN** | **FIXED** |
| `<dialog id="run-scan-modal">` | Native `<dialog>` | **LIKELY_BROKEN** | **FIXED** |
| **Active** toggle | `onclick="toggleActive(...)"` | OK – calls API | No change |
| Close / Cancel inside modals | `onclick="...close()"` | LIKELY_BROKEN | **FIXED** |

---

### `/reports` → `reports/list.html`

| Element | Pattern | Classification | Action |
|---------|---------|----------------|--------|
| **New Report** button | `onclick="...showModal()"` | **LIKELY_BROKEN** | **FIXED** |
| `<dialog id="new-report-modal">` | Native `<dialog>` | **LIKELY_BROKEN** | **FIXED** |
| Auto-open on `?open_modal=1` | `document.getElementById(...).showModal()` in `DOMContentLoaded` | **LIKELY_BROKEN** | **FIXED** — uses `openModal()` helper |
| Filter button | `onclick="applyReportFilters()"` | OK | No change |
| Close / Cancel inside modal | `onclick="...close()"` | LIKELY_BROKEN | **FIXED** |

---

### `/settings` → `settings/list.html`

| Element | Pattern | Classification | Action |
|---------|---------|----------------|--------|
| `<dialog id="shodan-modal">` | Native `<dialog>` — **no open trigger found in page** (orphaned dialog) | **LIKELY_BROKEN** | **FIXED** — converted to Alpine; open trigger was missing, preserved hidden state |
| `<dialog id="discord-findings-modal">` | Same — orphaned | **LIKELY_BROKEN** | **FIXED** |
| `<dialog id="discord-secrets-modal">` | Same — orphaned | **LIKELY_BROKEN** | **FIXED** |
| Tab bar buttons | `@click="tab = '...'"` (Alpine) | OK | No change |
| Integration Save/Test buttons | `@click="saveIntegrations()"` (Alpine) | OK | No change |
| **Toggle Theme** button | `onclick="toggleTheme()"` | OK – calls global util | No change |
| **Vacuum DB / Wipe Test Data** | `onclick="vacuumDb()"` etc. | OK – calls API | No change |

---

### `/schedules` → `schedules/list.html`

| Element | Pattern | Classification | Action |
|---------|---------|----------------|--------|
| **New Schedule** button | `@click="openModal = true"` (Alpine) | OK ✓ | No change needed |
| New Schedule modal | Alpine `x-show="openModal"` | OK ✓ | Already correct |
| Toggle / Delete buttons | `onclick="toggleSchedule(...)"`, `onclick="deleteSchedule(...)"` | OK – call JS functions | No change |

---

### `/findings` → `findings/list.html`, `findings/_detail_content.html`

| Element | Pattern | Classification | Action |
|---------|---------|----------------|--------|
| Filter apply button | `onclick="applyFilters()"` | OK | No change |
| AI: Check Severity button | `onclick="aiCheckSeverity(...)"` | OK – calls API | No change |
| AI: Find Duplicates button | `onclick="aiFindDuplicates(...)"` | OK – calls API | No change |
| Dismiss AI panel | `onclick="classList.add('hidden')"` | NEEDS_INSPECTION – works but not Alpine-idiomatic | No change (low risk) |
| Copy curl command button | `onclick="copyToClipboard(...)"` | OK | No change |

---

### `_base.html` (global nav)

| Element | Pattern | Classification | Action |
|---------|---------|----------------|--------|
| Search input `onclick="openPalette()"` | OK – calls global util | No change |
| Theme toggle `onclick="toggleTheme()"` | OK | No change |
| Command palette backdrop | `onclick="if(event.target===this)closePalette()"` | OK | No change |

---

### Row / Component templates

| File | Element | Pattern | Classification |
|------|---------|---------|----------------|
| `components/finding_row.html` | Row `onclick="window.location=..."` | NEEDS_INSPECTION – works but non-standard | No change |
| `components/scan_row.html` | Row `onclick` + inner `<a onclick="event.stopPropagation()">` | NEEDS_INSPECTION | No change |
| `programs/_table.html` | Row `onclick` + inner `<a onclick="stopPropagation()">` | NEEDS_INSPECTION | No change |
| `assets/_table.html` | Same row pattern | NEEDS_INSPECTION | No change |
| `reports/_table.html` | Same row pattern | NEEDS_INSPECTION | No change |
| `queue/list.html` | `onclick="location.reload()"`, `cancelEntry`, `retryEntry` | OK | No change |
| `errors/list.html` | Drawer open/close via `onclick` | OK – pure JS drawer | No change |
| `secrets/_table.html` | `onclick="revalidateSecret(...)"` | OK | No change |
| `dashboard.html` | `onclick="loadSamplePrograms(this)"` | OK | No change |
| `scans/detail.html` | `onclick="cancelScan(...)"` | OK | No change |
| `reports/detail.html` | Save/Regen/Polish/Submit/Delete buttons | OK – call API functions | No change |

---

## Root Cause Analysis

Native `<dialog>` elements with `onclick=".showModal()"` fail on real clicks because:

1. **Alpine.js `x-data` on `<html>`** makes the entire document an Alpine component. Button
   click handlers defined via `onclick=` are native DOM handlers, but when Alpine initialises
   it can reorder event processing, causing the `<dialog>` state to not propagate back to
   Alpine-managed reactive properties.
2. **`<dialog>` inside a CSS Grid/Flex container** with `overflow: hidden` on `.main-content`
   can clip the backdrop pseudo-element and prevent interaction.
3. **HTMX 2.x** attaches `htmx:beforeRequest` listeners that can intercept form-adjacent
   button clicks when HTMX can't find a matching `hx-*` attribute.

**Fix:** Replace all native `<dialog>` + `onclick=".showModal()"` with Alpine.js
`x-show` overlays + `$dispatch('open-<id>')` custom events.

---

## Changes Made

- `bounty/ui/templates/components/modal.html` — new reusable Alpine modal macro
- `bounty/ui/templates/_base.html` — added `window.openModal` / `window.closeModal` helpers + `[x-cloak]` CSS
- `bounty/ui/templates/scans/list.html` — **FIXED**
- `bounty/ui/templates/programs/list.html` — **FIXED**
- `bounty/ui/templates/programs/detail.html` — **FIXED**
- `bounty/ui/templates/reports/list.html` — **FIXED**
- `bounty/ui/templates/settings/list.html` — **FIXED**
- `tests/test_ui_smoke.py` — new Playwright smoke tests (14 tests)
- `pyproject.toml` — added `pytest-playwright` to dev extras
- `README.md` — added "UI Testing" section

---

## Post-Audit Bug Report (2026-05-17)

Two form-to-DB correctness bugs were discovered after the initial audit and fixed in a follow-up PR.
They were **not caught by the original Playwright tests** because those tests only verified that
modals open and close — they did not submit forms and inspect the resulting database rows.

### BUG A — Program ID stored as user-entered name instead of ULID

**Symptom:** After clicking "New Program" and entering a name (e.g. "NVIDIA test"), the
`programs` table row had `id = "NVIDIA test"` — the user's display name — instead of a
generated ULID.

**Root cause:** `ProgramCreateRequest` included an `id: str` field; the HTML form had an
`<input name="id">` that the user filled in; the JS sent it to the API; the API used `body.id`
directly as the DB primary key.

**Fix:**
- Removed `id` from `ProgramCreateRequest` (model has no id field, extra JSON keys are ignored).
- Added `from bounty.ulid import make_ulid` to `bounty/ui/routes/programs.py`.
- `create_program` now calls `program_id = make_ulid()` before the INSERT.
- Removed the `<input name="id">` from `programs/list.html`.

### BUG B — Targets not persisted on program creation

**Symptom:** After creating a program via the UI, the `targets` table had zero rows for that
program. Subsequent scans immediately completed with 0 assets / 0 findings because
`recon_pipeline` had no targets to work with.

**Root cause:** The `<form>` in `programs/list.html` had no target input fields. The
`submitNewProgram()` JS function never sent a `scope` array. The backend model already
handled `scope: list[TargetSpec]` correctly, but the field was always empty `[]`.

**Fix:**
- Added an Alpine.js targets repeater to `programs/list.html`:
  - "+ Add target" button appends a row with scope_type / asset_type / value controls.
  - "×" button removes a row.
  - Empty value rows are filtered out before submission.
- Updated `submitNewProgram()` to read `Alpine.$data(np-targets-root).targets` and include
  the filtered list as `scope` in the POST body.
- Changed `TargetSpec` in `bounty/ui/routes/programs.py` to use `Literal` types for proper
  enum validation (returns HTTP 422 on invalid scope_type / asset_type).

### Why the audit missed these

The original Playwright smoke tests in `test_ui_smoke.py` covered:
- Modal open / close mechanics (Alpine event dispatching)
- Basic page-load health (HTTP 200, no JS console errors)

They did **not** cover:
- Filling and submitting a create-program form
- Verifying the resulting DB rows contain correct data (ULID id, target rows)

A new end-to-end test `test_new_program_form_roundtrip` was added to `test_ui_smoke.py`
and 9 backend unit tests were added in `tests/test_program_create_form.py` to prevent
regression.
