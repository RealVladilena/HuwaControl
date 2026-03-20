'use strict';

// ── Chart.js defaults ─────────────────────────────────────────────────────────
Chart.defaults.color           = '#7a7a7a';
Chart.defaults.borderColor     = '#2d2d2d';
Chart.defaults.font.family     = "'Segoe UI', system-ui, sans-serif";
Chart.defaults.font.size       = 11;
Chart.defaults.plugins.legend.display = false;

// ── Router selector ───────────────────────────────────────────────────────────
function getActiveRouter() {
  const sel = document.getElementById('routerSelect');
  if (sel) return parseInt(sel.value) || null;
  return null;
}

function apiUrl(path, params = {}) {
  const rid = getActiveRouter();
  if (rid) params.router_id = rid;
  const qs = new URLSearchParams(params).toString();
  return path + (qs ? '?' + qs : '');
}

const routerSelect = document.getElementById('routerSelect');
if (routerSelect) {
  routerSelect.addEventListener('change', () => {
    // Met à jour la session côté serveur en naviguant sur '/?router_id=X'
    const rid = routerSelect.value;
    fetch('/?router_id=' + rid, { redirect: 'manual' }).catch(() => {});
    // Notifie les pages
    document.dispatchEvent(new CustomEvent('routerChanged', { detail: { router_id: rid } }));
  });
}

// ── Chart helpers ─────────────────────────────────────────────────────────────

/** Formate les valeurs bps pour l'axe Y (ex: 1.5M, 800K, 300) */
function fmtBpsAxis(v) {
  if (v >= 1e9) return (v / 1e9).toFixed(1) + 'G';
  if (v >= 1e6) return (v / 1e6).toFixed(1) + 'M';
  if (v >= 1e3) return (v / 1e3).toFixed(0) + 'K';
  return v;
}

/**
 * Construit un graphique Chart.js.
 * @param {string} canvasId
 * @param {string[]} labels   noms des datasets
 * @param {string[]} colors
 * @param {string[]} fills
 * @param {object}  [opts]    options supplémentaires : { yFmt: fn }
 */
function buildLineChart(canvasId, labels, colors, fills, opts = {}) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  return new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: labels.map((label, i) => ({
        label,
        data: [],
        borderColor:     colors[i] || '#cc0000',
        backgroundColor: fills[i]  || 'rgba(204,0,0,0.1)',
        borderWidth: 1.8,
        pointRadius: 0,
        pointHoverRadius: 4,
        fill: true,
        tension: 0.35,
      })),
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: false,   // désactivé pour éviter le bug de rendu initial
      interaction: { mode: 'index', intersect: false },
      scales: {
        x: { grid: { color: '#1e1e1e' }, ticks: { maxTicksLimit: 8, maxRotation: 0 } },
        y: {
          grid: { color: '#1e1e1e' }, beginAtZero: true,
          ticks: {
            maxTicksLimit: 5,
            callback: opts.yFmt || undefined,
          },
        },
      },
      plugins: {
        tooltip: {
          backgroundColor: '#1f1f1f', borderColor: '#2d2d2d', borderWidth: 1,
          titleColor: '#e8e8e8', bodyColor: '#aaa', padding: 10,
          callbacks: opts.tooltipFmt ? { label: opts.tooltipFmt } : {},
        },
        legend: {
          display: labels.length > 1,
          labels: { boxWidth: 10, padding: 14, color: '#7a7a7a' },
        },
      },
    },
  });
}

function updateChart(chart, xLabels, datasets) {
  if (!chart) return;
  chart.data.labels = xLabels;
  datasets.forEach((data, i) => {
    if (chart.data.datasets[i]) chart.data.datasets[i].data = data;
  });
  chart.update('none');
}

// ── Sidebar toggle (responsive) ───────────────────────────────────────────────
const _sidebar  = document.getElementById('sidebar');
const _layout   = document.getElementById('layout');

// Backdrop mobile
const _backdrop = document.createElement('div');
_backdrop.className = 'sidebar-backdrop';
document.body.appendChild(_backdrop);

function _isMobile() { return window.innerWidth <= 768; }

function _closeSidebar() {
  _sidebar?.classList.remove('mobile-open');
  _backdrop.classList.remove('active');
}

_backdrop.addEventListener('click', _closeSidebar);

document.getElementById('sidebarToggle')?.addEventListener('click', () => {
  if (_isMobile()) {
    const opened = _sidebar?.classList.toggle('mobile-open');
    _backdrop.classList.toggle('active', opened);
  } else {
    _sidebar?.classList.toggle('collapsed');
    _layout?.classList.toggle('sidebar-collapsed');
  }
});

// Fermer la sidebar mobile au resize vers desktop
window.addEventListener('resize', () => {
  if (!_isMobile()) _closeSidebar();
});

// Sur mobile, fermer la sidebar quand on clique un lien nav
if (_isMobile()) {
  document.querySelectorAll('.nav__item a').forEach(a =>
    a.addEventListener('click', _closeSidebar)
  );
}

// ── Poll button ───────────────────────────────────────────────────────────────
document.getElementById('pollBtn')?.addEventListener('click', () => {
  const rid = getActiveRouter();
  if (!rid) return;
  const icon = document.querySelector('#pollBtn i');
  icon.classList.add('fa-spin');
  fetch('/api/routers/' + rid + '/poll', { method: 'POST' })
    .then(r => r.json())
    .then(d => d.ts && updateLastPoll(d.ts))
    .catch(console.error)
    .finally(() => icon.classList.remove('fa-spin'));
});

// ── Topbar refresh ────────────────────────────────────────────────────────────
function updateLastPoll(ts) {
  const el = document.getElementById('last-poll-time');
  if (el && ts) el.textContent = 'Dernier poll : ' + new Date(ts * 1000).toLocaleTimeString();
}

function refreshTopbar() {
  fetch(apiUrl('/api/status'))
    .then(r => r.json())
    .then(d => {
      const cpuEl = document.getElementById('hdr-cpu-val');
      if (cpuEl) cpuEl.textContent = d.cpu_usage != null ? d.cpu_usage.toFixed(1) + '%' : '—';
      const memEl = document.getElementById('hdr-mem-val');
      if (memEl) memEl.textContent = d.mem_usage != null ? d.mem_usage.toFixed(1) + '%' : '—';

      const dot   = document.querySelector('#conn-indicator .dot');
      const label = document.getElementById('conn-label');
      if (dot && label) {
        const ok = d.timestamp && (Date.now() / 1000 - d.timestamp) < 300;
        dot.className     = 'dot ' + (ok ? 'dot--up' : 'dot--down');
        label.textContent = ok ? (d.router_ip || d.router_name) : 'Hors ligne';
      }

      if (d.timestamp) updateLastPoll(d.timestamp);
    })
    .catch(() => {
      const dot = document.querySelector('#conn-indicator .dot');
      if (dot) dot.className = 'dot dot--down';
    });
}

refreshTopbar();
document.addEventListener('routerChanged', refreshTopbar);

// ── WebSocket temps réel ───────────────────────────────────────────────────────
(function () {
  if (typeof io === 'undefined') {
    setInterval(refreshTopbar, 30000);
    return;
  }
  const _sock = io({ transports: ['websocket', 'polling'] });

  _sock.on('connect', () => {
    const dot = document.querySelector('#conn-indicator .dot');
    if (dot) dot.classList.add('dot--ws');
  });

  _sock.on('router_update', (d) => {
    const rid = getActiveRouter();
    if (rid && d.router_id !== rid) return;

    const cpuEl = document.getElementById('hdr-cpu-val');
    if (cpuEl && d.cpu != null) cpuEl.textContent = d.cpu.toFixed(1) + '%';
    const memEl = document.getElementById('hdr-mem-val');
    if (memEl && d.mem != null) memEl.textContent = d.mem.toFixed(1) + '%';

    const dot   = document.querySelector('#conn-indicator .dot');
    const label = document.getElementById('conn-label');
    if (dot)   dot.className   = 'dot dot--up dot--ws';
    if (label) label.textContent = d.router_ip || d.router_name || 'En ligne';

    if (d.ts) updateLastPoll(d.ts);

    document.dispatchEvent(new CustomEvent('snmpPolled', { detail: d }));
  });

  _sock.on('disconnect', () => {
    setInterval(refreshTopbar, 30000);
  });
})();

// ── Toast notifications ────────────────────────────────────────────────────────
(function () {
  const _container = document.createElement('div');
  _container.className = 'toast-container';
  document.body.appendChild(_container);

  const ICONS = {
    success: 'fa-circle-check',
    error:   'fa-circle-xmark',
    warning: 'fa-triangle-exclamation',
    info:    'fa-circle-info',
  };

  window.showToast = function (msg, type = 'success', duration = 3000) {
    const el = document.createElement('div');
    el.className = 'toast toast--' + type;
    el.innerHTML = `<i class="fa-solid ${ICONS[type] || ICONS.info}"></i><span>${msg}</span>`;
    _container.appendChild(el);
    requestAnimationFrame(() => {
      requestAnimationFrame(() => el.classList.add('toast--visible'));
    });
    setTimeout(() => {
      el.classList.remove('toast--visible');
      setTimeout(() => el.remove(), 300);
    }, duration);
  };
})();


// ── Sparkline (mini chart sans axes pour les tableaux) ──────────────────────
window.buildSparkline = function (canvasId, inData, outData) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  // Destroy previous instance if any
  if (ctx._sparkChart) { ctx._sparkChart.destroy(); }
  const chart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: inData.map((_, i) => i),
      datasets: [
        { data: inData,  borderColor: '#00cc44', borderWidth: 1.5,
          pointRadius: 0, tension: 0.3, fill: false },
        { data: outData, borderColor: '#cc0000', borderWidth: 1.5,
          pointRadius: 0, tension: 0.3, fill: false },
      ],
    },
    options: {
      animation: false,
      responsive: false,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      scales: { x: { display: false }, y: { display: false } },
    },
  });
  ctx._sparkChart = chart;
  return chart;
};
