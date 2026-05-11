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

// Dismiss all on Escape
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    document.querySelectorAll('#toast-container > div').forEach(el => el.remove());
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
    // Ignore when typing in inputs
    const tag = document.activeElement && document.activeElement.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;

    // Cmd/Ctrl+K → command palette
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      const input = document.getElementById('search-input');
      if (input) input.focus();
      return;
    }

    if (e.key === '/') {
      e.preventDefault();
      const input = document.getElementById('search-input');
      if (input) input.focus();
      return;
    }

    buf += e.key;
    clearTimeout(timer);
    timer = setTimeout(() => { buf = ''; }, 1000);

    if (routes[buf]) {
      window.location.href = routes[buf];
      buf = '';
    }
  });
})();

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

