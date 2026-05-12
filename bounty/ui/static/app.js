/**
 * bounty/ui/static/app.js
 * Global helpers — no build step, no modules.
 * Loaded by _base.html after Alpine and HTMX are available.
 */

/* ------------------------------------------------------------------ theme */
(function () {
  const stored = localStorage.getItem('bounty_theme');
  if (stored === 'light') {
    document.documentElement.classList.remove('dark');
  } else {
    document.documentElement.classList.add('dark');
  }
})();

function toggleTheme() {
  const html = document.documentElement;
  if (html.classList.contains('dark')) {
    html.classList.remove('dark');
    localStorage.setItem('bounty_theme', 'light');
  } else {
    html.classList.add('dark');
    localStorage.setItem('bounty_theme', 'dark');
  }
}

/* ------------------------------------------------------------------ SSE */
/**
 * sseConnect(url, handlers)
 * Opens an EventSource with exponential-backoff reconnect.
 * handlers: { eventName: fn(data) }
 * Returns a { close() } handle.
 */
function sseConnect(url, handlers) {
  let es = null;
  let backoff = 1000;
  let closed = false;
  const MAX_BACKOFF = 30000;

  function connect() {
    if (closed) return;
    es = new EventSource(url);

    es.addEventListener('open', () => {
      backoff = 1000;
      _updateSseStatus(true);
    });

    es.addEventListener('error', () => {
      _updateSseStatus(false);
      es.close();
      if (!closed) {
        setTimeout(connect, backoff);
        backoff = Math.min(backoff * 2, MAX_BACKOFF);
      }
    });

    // Generic message dispatcher
    Object.keys(handlers).forEach(evName => {
      es.addEventListener(evName, (e) => {
        try {
          const data = JSON.parse(e.data);
          handlers[evName](data);
          // Also update Alpine store if available
          if (window._bountyStore) {
            window._bountyStore.pushEvent({ type: evName, data, ts: Date.now() });
          }
        } catch (_) {}
      });
    });
  }

  connect();
  return { close() { closed = true; es && es.close(); } };
}

function _updateSseStatus(connected) {
  const dot = document.getElementById('sse-status-dot');
  if (!dot) return;
  if (connected) {
    dot.classList.remove('bg-red-500', 'bg-yellow-500');
    dot.classList.add('bg-green-400');
    dot.title = 'Live';
  } else {
    dot.classList.remove('bg-green-400', 'bg-yellow-500');
    dot.classList.add('bg-red-500');
    dot.title = 'Disconnected – reconnecting…';
  }
}

/* ------------------------------------------------------------------ toast */
/**
 * toast(message, kind)
 * kind: 'success' | 'error' | 'warning' | 'info'
 */
function toast(message, kind) {
  kind = kind || 'info';
  const colours = {
    success: 'bg-green-700 border-green-500',
    error:   'bg-red-800 border-red-500',
    warning: 'bg-yellow-700 border-yellow-500',
    info:    'bg-slate-700 border-slate-500',
  };
  const c = colours[kind] || colours.info;

  const container = document.getElementById('toast-container');
  if (!container) return;

  const el = document.createElement('div');
  el.className = `toast-enter flex items-center gap-2 px-4 py-2 rounded border text-sm text-white shadow-lg ${c}`;
  el.role = 'alert';
  el.textContent = message;

  // Dismiss button
  const btn = document.createElement('button');
  btn.textContent = '✕';
  btn.className = 'ml-auto opacity-70 hover:opacity-100 text-xs';
  btn.onclick = () => dismiss(el);
  el.appendChild(btn);

  container.appendChild(el);

  // Auto-dismiss after 4s
  const timer = setTimeout(() => dismiss(el), 4000);
  el._dismissTimer = timer;

  function dismiss(node) {
    clearTimeout(node._dismissTimer);
    node.classList.remove('toast-enter');
    node.classList.add('toast-exit');
    node.addEventListener('animationend', () => node.remove(), { once: true });
  }
}

// Dismiss all toasts on Escape (when palette is not open)
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    const overlay = document.getElementById('palette-overlay');
    if (!overlay || overlay.classList.contains('hidden')) {
      document.querySelectorAll('#toast-container > div').forEach(el => el.remove());
    }
  }
});

/* ------------------------------------------------------------------ htmxAuth */
/**
 * htmxAuth()
 * Sets Authorization header on every htmx request when a session token
 * is embedded in the page (meta tag bounty-token).
 */
function htmxAuth() {
  const meta = document.querySelector('meta[name="bounty-token"]');
  if (!meta) return;
  const token = meta.getAttribute('content');
  if (!token) return;
  document.addEventListener('htmx:configRequest', (e) => {
    e.detail.headers['Authorization'] = 'Bearer ' + token;
  });
}

/* ------------------------------------------------------------------ keyboard shortcuts */
(function () {
  let buf = '';
  let timer = null;

  const routes = {
    'gd': '/',
    'gs': '/scans',
    'ga': '/assets',
    'gf': '/findings',
    'gp': '/programs',
    'gk': '/secrets',
    'gr': '/reports',
    'gi': '/settings',
  };

  document.addEventListener('keydown', (e) => {
    // Ignore when typing in inputs (except palette input handled separately)
    const tag = document.activeElement && document.activeElement.tagName;
    const isPaletteInput = document.activeElement && document.activeElement.id === 'palette-input';
    if (!isPaletteInput && (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT')) return;

    // Cmd/Ctrl+K → command palette
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      openPalette();
      return;
    }

    if (isPaletteInput) return; // let palette key handler deal with it

    if (e.key === '/') {
      e.preventDefault();
      openPalette();
      return;
    }

    if (e.metaKey || e.ctrlKey || e.altKey) return;

    buf += e.key;
    clearTimeout(timer);
    timer = setTimeout(() => { buf = ''; }, 1000);

    if (routes[buf]) {
      window.location.href = routes[buf];
      buf = '';
    }
  });
})();

/* ------------------------------------------------------------------ command palette */
let _paletteDebounceTimer = null;
let _paletteSelectedIdx = -1;

function openPalette() {
  const overlay = document.getElementById('palette-overlay');
  const input = document.getElementById('palette-input');
  if (!overlay) return;
  overlay.classList.remove('hidden');
  overlay.classList.add('flex');
  if (input) {
    input.value = '';
    input.focus();
    _paletteSelectedIdx = -1;
    _fetchPaletteResults('');
  }
}

function closePalette() {
  const overlay = document.getElementById('palette-overlay');
  if (!overlay) return;
  overlay.classList.add('hidden');
  overlay.classList.remove('flex');
  _paletteSelectedIdx = -1;
  // Return focus to search trigger
  const si = document.getElementById('search-input');
  if (si) si.blur();
}

function debouncePaletteSearch(q) {
  clearTimeout(_paletteDebounceTimer);
  _paletteDebounceTimer = setTimeout(() => _fetchPaletteResults(q), 200);
}

async function _fetchPaletteResults(q) {
  try {
    const r = await fetch('/api/palette/search?q=' + encodeURIComponent(q));
    if (!r.ok) return;
    const data = await r.json();
    _renderPaletteResults(data, q);
  } catch (_) {}
}

function _renderPaletteResults(data, q) {
  const list = document.getElementById('palette-list');
  if (!list) return;
  list.innerHTML = '';
  _paletteSelectedIdx = -1;

  const badgeColours = {
    asset:   'bg-blue-900 text-blue-300',
    finding: 'bg-red-900 text-red-300',
    program: 'bg-green-900 text-green-300',
    scan:    'bg-purple-900 text-purple-300',
    report:  'bg-yellow-900 text-yellow-300',
    action:  'bg-slate-700 text-slate-300',
  };

  function makeItem(item, isAction) {
    const li = document.createElement('li');
    const typeKey = isAction ? 'action' : (item.type || 'action');
    const badge = item.badge || item.type || '';
    li.className = 'palette-item flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-slate-700 transition-colors text-sm';
    li.dataset.url = item.url || '#';
    li.innerHTML = `
      <span class="text-base">${item.icon || '→'}</span>
      <span class="flex-1 text-slate-100 truncate">${item.label}</span>
      ${badge ? `<span class="text-xs px-1.5 py-0.5 rounded ${badgeColours[typeKey] || badgeColours.action}">${badge}</span>` : ''}
    `;
    li.addEventListener('click', () => {
      closePalette();
      window.location.href = li.dataset.url;
    });
    li.addEventListener('mouseenter', () => {
      _paletteSetSelected(Array.from(list.children).indexOf(li));
    });
    return li;
  }

  // Quick actions (always shown at top when no query, or when short query)
  if (!q.trim() && data.quick_actions) {
    const hdr = document.createElement('li');
    hdr.className = 'px-4 py-1 text-xs uppercase tracking-wider text-slate-500';
    hdr.textContent = 'Quick Actions';
    list.appendChild(hdr);
    for (const qa of data.quick_actions) {
      list.appendChild(makeItem(qa, true));
    }
  }

  // Search results
  if (data.results && data.results.length > 0) {
    if (!q.trim() || true) {
      const hdr = document.createElement('li');
      hdr.className = 'px-4 py-1 text-xs uppercase tracking-wider text-slate-500';
      hdr.textContent = q.trim() ? 'Results' : 'Recent';
      list.appendChild(hdr);
    }
    for (const item of data.results) {
      list.appendChild(makeItem(item, false));
    }
  } else if (q.trim() && (!data.results || data.results.length === 0)) {
    // Show quick actions as fallback
    if (data.quick_actions && data.quick_actions.length > 0) {
      const hdr = document.createElement('li');
      hdr.className = 'px-4 py-1 text-xs text-slate-500';
      hdr.textContent = 'No results — quick actions:';
      list.appendChild(hdr);
      for (const qa of data.quick_actions) {
        list.appendChild(makeItem(qa, true));
      }
    } else {
      const li = document.createElement('li');
      li.className = 'px-4 py-3 text-sm text-slate-500 text-center';
      li.textContent = 'No results found';
      list.appendChild(li);
    }
  }
}

function _paletteSetSelected(idx) {
  const list = document.getElementById('palette-list');
  if (!list) return;
  const items = list.querySelectorAll('.palette-item');
  items.forEach((el, i) => {
    if (i === idx) {
      el.classList.add('bg-slate-700');
    } else {
      el.classList.remove('bg-slate-700');
    }
  });
  _paletteSelectedIdx = idx;
}

function handlePaletteKey(e) {
  const list = document.getElementById('palette-list');
  if (!list) return;
  const items = Array.from(list.querySelectorAll('.palette-item'));

  if (e.key === 'Escape') {
    e.preventDefault();
    closePalette();
  } else if (e.key === 'ArrowDown') {
    e.preventDefault();
    const next = Math.min(_paletteSelectedIdx + 1, items.length - 1);
    _paletteSetSelected(next);
    if (items[next]) items[next].scrollIntoView({ block: 'nearest' });
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    const prev = Math.max(_paletteSelectedIdx - 1, 0);
    _paletteSetSelected(prev);
    if (items[prev]) items[prev].scrollIntoView({ block: 'nearest' });
  } else if (e.key === 'Enter') {
    e.preventDefault();
    if (_paletteSelectedIdx >= 0 && items[_paletteSelectedIdx]) {
      const url = items[_paletteSelectedIdx].dataset.url;
      if (url && url !== '#') {
        closePalette();
        window.location.href = url;
      }
    } else if (items.length > 0) {
      const url = items[0].dataset.url;
      if (url && url !== '#') {
        closePalette();
        window.location.href = url;
      }
    }
  }
}

// Close palette on Escape (global handler complement)
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    const overlay = document.getElementById('palette-overlay');
    if (overlay && !overlay.classList.contains('hidden')) {
      closePalette();
    }
  }
});

/* ------------------------------------------------------------------ clipboard */
/**
 * copyToClipboard(text, btnElement)
 * Copies text to clipboard and shows a transient ✓ on the button.
 */
async function copyToClipboard(text, btnEl) {
  try {
    await navigator.clipboard.writeText(text);
    const orig = btnEl.textContent;
    btnEl.textContent = '✓ Copied';
    btnEl.disabled = true;
    setTimeout(() => { btnEl.textContent = orig; btnEl.disabled = false; }, 2000);
  } catch (e) {
    toast('Copy failed: ' + e.message, 'error');
  }
}

/* ------------------------------------------------------------------ markdown */
/**
 * renderMarkdown(el)
 * Replaces el.innerHTML with marked.parse(el.textContent).
 * Requires marked.js CDN — included via {% block head %} on findings pages.
 */
function renderMarkdown(el) {
  if (!el || !el.textContent.trim()) return;
  try {
    if (typeof marked !== 'undefined') {
      el.innerHTML = marked.parse(el.textContent);
    }
  } catch (_) {}
}

/* ------------------------------------------------------------------ kanban DnD */
/**
 * kanbanDnD()
 * Initialises HTML5 drag-and-drop on .kanban-card / .kanban-column elements.
 * On drop, PATCHes /api/findings/{id}/status with the new status.
 * Reverts card position on failure.
 */
function kanbanDnD() {
  let draggedCard = null;
  let sourceCol = null;

  function bindCard(card) {
    card.addEventListener('dragstart', (e) => {
      draggedCard = card;
      sourceCol = card.closest('.kanban-column');
      card.classList.add('opacity-50');
      if (e.dataTransfer) e.dataTransfer.effectAllowed = 'move';
    });
    card.addEventListener('dragend', () => {
      card.classList.remove('opacity-50');
    });
  }

  document.querySelectorAll('.kanban-card').forEach(bindCard);

  document.querySelectorAll('.kanban-column').forEach(col => {
    col.addEventListener('dragover', (e) => {
      e.preventDefault();
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
      col.classList.add('ring-2', 'ring-blue-500');
    });
    col.addEventListener('dragleave', () => {
      col.classList.remove('ring-2', 'ring-blue-500');
    });
    col.addEventListener('drop', async (e) => {
      e.preventDefault();
      col.classList.remove('ring-2', 'ring-blue-500');
      if (!draggedCard) return;

      const findingId = draggedCard.dataset.findingId;
      const newStatus = col.dataset.status;
      const prevCol = sourceCol;

      // Optimistic UI: move card
      const cards = col.querySelector('.kanban-cards');
      if (cards) cards.prepend(draggedCard);

      // Update count badges
      if (prevCol && prevCol !== col) {
        const ob = prevCol.querySelector('.kanban-count');
        const nb = col.querySelector('.kanban-count');
        if (ob) ob.textContent = String(Math.max(0, parseInt(ob.textContent || '0') - 1));
        if (nb) nb.textContent = String(parseInt(nb.textContent || '0') + 1);
      }

      try {
        const r = await fetch('/api/findings/' + findingId + '/status', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus }),
        });
        if (!r.ok) {
          // Revert
          if (prevCol) {
            const pc = prevCol.querySelector('.kanban-cards');
            if (pc) pc.prepend(draggedCard);
            const ob = prevCol.querySelector('.kanban-count');
            const nb = col.querySelector('.kanban-count');
            if (ob) ob.textContent = String(parseInt(ob.textContent || '0') + 1);
            if (nb) nb.textContent = String(Math.max(0, parseInt(nb.textContent || '0') - 1));
          }
          toast('Failed to update status', 'error');
        } else {
          toast('Moved to ' + newStatus, 'success');
        }
      } catch (err) {
        toast('Network error', 'error');
      }
      draggedCard = null;
      sourceCol = null;
    });
  });
}

/* ------------------------------------------------------------------ init */
document.addEventListener('DOMContentLoaded', () => {
  htmxAuth();

  // Start global SSE — pages subscribe to window._bountyStore
  if (typeof EventSource !== 'undefined') {
    sseConnect('/sse/events', {
      'scan.started':       d => toast('Scan started: ' + (d.scan_id || ''), 'info'),
      'scan.completed':     d => toast('Scan completed', 'success'),
      'scan.failed':        d => toast('Scan failed', 'error'),
      'finding.created':    () => {},
      'secret.live':        d => toast('Live secret found!', 'warning'),
    });
  }
});

