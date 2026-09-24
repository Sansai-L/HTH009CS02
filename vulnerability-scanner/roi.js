/* ══════════════════════════════════════════════════════
   VulnRankPro — roi.js
   Interactive ROI Simulator with Drag-and-Drop + Chart.js
   ══════════════════════════════════════════════════════ */

'use strict';

// ─────────────────────────────────────────────────────────
// ROI STATE
// ─────────────────────────────────────────────────────────
const roi = {
  allItems:    [],   // all vulnerabilities (backlog + sprint)
  backlog:     [],   // items currently in backlog column
  sprint:      [],   // items currently in sprint column
  capacity:    5,
  chartInst:   null,
  dragId:      null,
  dragFrom:    null, // 'backlog' | 'sprint'
};

// Color helpers
const sevColor = { Critical:'#f87171', High:'#fb923c', Medium:'#fbbf24', Low:'#34d399' };
const sevColorHex = sev => sevColor[sev] || '#94a3b8';

// ─────────────────────────────────────────────────────────
// INIT: called when ROI tab is first activated
// ─────────────────────────────────────────────────────────
function roiInit(findings) {
  if (!findings || findings.length === 0) {
    document.getElementById('roiNoData').classList.remove('hidden');
    document.getElementById('roiBoard').classList.add('hidden');
    document.getElementById('roi-chart-area')?.classList.add('hidden');
    return;
  }

  document.getElementById('roiNoData').classList.add('hidden');
  document.getElementById('roiBoard').classList.remove('hidden');

  // Clone and sort: KEV first, then by businessRisk desc
  roi.allItems = findings
    .map((f, i) => ({ ...f, roiRank: i + 1 }))
    .sort((a, b) => {
      if (a.isKEV && !b.isKEV) return -1;
      if (!a.isKEV && b.isKEV) return 1;
      return b.businessRisk - a.businessRisk;
    });

  roi.backlog = [...roi.allItems];
  roi.sprint  = [];

  roiRenderBoard();
  roiInitChart();
  roiUpdateAll();
}

// ─────────────────────────────────────────────────────────
// CHART.JS SETUP
// ─────────────────────────────────────────────────────────
function roiInitChart() {
  const ctx = document.getElementById('roiChart').getContext('2d');
  if (roi.chartInst) { roi.chartInst.destroy(); roi.chartInst = null; }

  // Generate projection baseline (no remediation = flat line)
  const labels   = roiProjectionLabels(10);
  const baseline = roiBaselineData(10);
  const proj     = roiProjectionData(10);

  roi.chartInst = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'No Action (Baseline)',
          data: baseline,
          borderColor: '#475569',
          backgroundColor: 'rgba(71,85,105,0.08)',
          borderDash: [6, 4],
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: '#475569',
          tension: 0.4,
          fill: false,
        },
        {
          label: 'With Current Sprint',
          data: proj,
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59,130,246,0.12)',
          borderWidth: 3,
          pointRadius: 5,
          pointBackgroundColor: '#3b82f6',
          pointHoverRadius: 7,
          tension: 0.4,
          fill: true,
        },
        {
          label: 'Risk-Free Target',
          data: Array(11).fill(0),
          borderColor: 'rgba(16,185,129,0.3)',
          borderDash: [3, 6],
          borderWidth: 1.5,
          pointRadius: 0,
          fill: false,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      animation: { duration: 500, easing: 'easeInOutQuart' },
      plugins: {
        legend: {
          labels: { color: '#94a3b8', font: { family:'Inter', size:12 }, boxWidth:24 },
        },
        tooltip: {
          backgroundColor: '#1a2236',
          borderColor: '#1e2d45',
          borderWidth: 1,
          titleColor: '#e2e8f0',
          bodyColor: '#94a3b8',
          padding: 12,
          callbacks: {
            label: ctx => ` ${ctx.dataset.label}: ${ctx.raw.toFixed(1)} risk pts`,
          },
        },
      },
      scales: {
        x: {
          grid:   { color: 'rgba(30,45,69,0.7)' },
          ticks:  { color: '#64748b', font:{ family:'Inter', size:11 } },
          title:  { display:true, text:'Sprints (Weeks)', color:'#64748b', font:{ family:'Inter', size:11 } },
        },
        y: {
          grid:   { color: 'rgba(30,45,69,0.7)' },
          ticks:  { color: '#64748b', font:{ family:'Inter', size:11 } },
          title:  { display:true, text:'Total Environment Risk Score', color:'#64748b', font:{ family:'Inter', size:11 } },
          beginAtZero: true,
        },
      },
    },
  });
}

// ─────────────────────────────────────────────────────────
// PROJECTION MATH
// ─────────────────────────────────────────────────────────
function totalRisk(items) {
  return items.reduce((s, f) => s + f.businessRisk, 0);
}

function roiProjectionLabels(sprints) {
  return Array.from({ length: sprints + 1 }, (_, i) => i === 0 ? 'Now' : `S${i}`);
}

function roiBaselineData(sprints) {
  const t = totalRisk(roi.allItems);
  return Array.from({ length: sprints + 1 }, () => t);
}

/**
 * Project risk reduction over N sprints:
 * - Sprint 1: remove sprint items' risk (user's current selection)
 * - Sprint 2+: auto-pick next best capacity items from remaining backlog
 */
function roiProjectionData(sprints) {
  const remaining = [...roi.allItems]
    .filter(f => !roi.sprint.find(s => s.id === f.id))
    .sort((a, b) => {
      if (a.isKEV && !b.isKEV) return -1;
      if (!a.isKEV && b.isKEV) return 1;
      return b.businessRisk - a.businessRisk;
    });

  const points = [];
  let current  = totalRisk(roi.allItems);
  points.push(current);

  // Sprint 1 = user's current sprint selection
  const sprintDrop = totalRisk(roi.sprint);
  current = Math.max(0, current - sprintDrop);
  points.push(current);

  // Future sprints = greedy best-pick from remaining
  let pool = [...remaining];
  for (let s = 2; s <= sprints; s++) {
    const chunk  = pool.slice(0, roi.capacity);
    const drop   = totalRisk(chunk);
    current = Math.max(0, current - drop);
    pool    = pool.slice(roi.capacity);
    points.push(current);
    if (current <= 0 || pool.length === 0) {
      while (points.length <= sprints) points.push(0);
      break;
    }
  }
  return points;
}

function roiWeeksToZero() {
  const proj = roiProjectionData(50);
  const idx  = proj.findIndex(v => v <= 0);
  return idx === -1 ? '50+' : idx;
}

// ─────────────────────────────────────────────────────────
// UPDATE CHART + KPIs
// ─────────────────────────────────────────────────────────
function roiUpdateAll() {
  // KPIs
  const total      = totalRisk(roi.allItems);
  const sprintDrop = totalRisk(roi.sprint);
  const pct        = total > 0 ? ((sprintDrop / total) * 100).toFixed(1) : '0.0';
  const weeks      = roiWeeksToZero();

  document.getElementById('roiKpiTotal').textContent = total.toFixed(1);
  document.getElementById('roiKpiDrop').textContent  = sprintDrop > 0 ? `−${sprintDrop.toFixed(1)}` : '—';
  document.getElementById('roiKpiWeeks').textContent = weeks;
  document.getElementById('roiKpiPct').textContent   = `${pct}%`;
  document.getElementById('roiDropScore').textContent= sprintDrop.toFixed(1);

  // Capacity meter
  const used = roi.sprint.length;
  const cap  = roi.capacity;
  const pctM = Math.min(100, (used / cap) * 100);
  const fill = document.getElementById('roiMeterFill');
  fill.style.width = pctM + '%';
  fill.classList.toggle('full', used >= cap);
  document.getElementById('roiMeterLabel').textContent = `${used} / ${cap} slots used`;
  document.getElementById('roiSprintCount').textContent= `${used} / ${cap} capacity`;

  // Update chart datasets
  if (roi.chartInst) {
    const labels  = roiProjectionLabels(10);
    const base    = roiBaselineData(10);
    const proj    = roiProjectionData(10);

    roi.chartInst.data.labels          = labels;
    roi.chartInst.data.datasets[0].data = base;
    roi.chartInst.data.datasets[1].data = proj;

    // Color gradient: green if improving quickly, accent otherwise
    const dropRatio = sprintDrop / (total || 1);
    const lineColor = dropRatio > 0.3 ? '#10b981' : dropRatio > 0.15 ? '#3b82f6' : '#6366f1';
    const bgColorMap = {
      '#10b981': 'rgba(16,185,129,0.1)',
      '#3b82f6': 'rgba(59,130,246,0.1)',
      '#6366f1': 'rgba(99,102,241,0.1)',
    };
    roi.chartInst.data.datasets[1].borderColor     = lineColor;
    roi.chartInst.data.datasets[1].backgroundColor = bgColorMap[lineColor] || 'rgba(59,130,246,0.1)';

    roi.chartInst.update('active');
  }
}

// ─────────────────────────────────────────────────────────
// RENDER BOARD
// ─────────────────────────────────────────────────────────
function roiRenderBoard() {
  roiRenderBacklog();
  roiRenderSprint();
}

function roiRenderBacklog(filter = '') {
  const q    = filter.toLowerCase();
  const show = roi.backlog.filter(f =>
    !q || f.name.toLowerCase().includes(q) || String(f.port).includes(q) || f.severity.toLowerCase().includes(q)
  );
  document.getElementById('roiBacklogCount').textContent = `${roi.backlog.length} vulnerabilities`;
  document.getElementById('dropBacklog').innerHTML = show.map((f, i) => roiCardHTML(f, i + 1, 'backlog')).join('');
  attachDragListeners('backlog');
}

function roiRenderSprint() {
  const zone  = document.getElementById('dropSprint');
  const empty = document.getElementById('roiSprintEmpty');

  if (roi.sprint.length === 0) {
    zone.innerHTML = '';
    zone.appendChild(empty);
    empty.style.display = 'flex';
  } else {
    empty.style.display = 'none';
    zone.innerHTML = roi.sprint.map((f, i) => roiCardHTML(f, i + 1, 'sprint')).join('');
    attachDragListeners('sprint');
  }
  document.getElementById('roiSprintCount').textContent = `${roi.sprint.length} / ${roi.capacity} capacity`;
}

function roiCardHTML(f, rank, col) {
  const scoreColor = f.isKEV ? '#ff4747' : sevColorHex(f.severity);
  const kevTag     = f.isKEV ? `<div class="roi-card-kev-tag">🇺🇸 KEV</div>` : '';
  const removeBtn  = col === 'sprint'
    ? `<button class="roi-card-remove" onclick="roiRemoveFromSprint('${f.id}')" title="Remove from sprint">✕</button>`
    : '';
  return `
    <div class="roi-card${f.isKEV ? ' kev-card' : ''}"
         data-id="${f.id}" data-sev="${f.severity}" draggable="true">
      ${kevTag}
      <span class="roi-card-drag-handle">⠿</span>
      <span class="roi-card-rank">#${rank}</span>
      <div class="roi-card-info">
        <div class="roi-card-name" title="${f.name}">${f.name}</div>
        <div class="roi-card-meta">
          ${f.port}/tcp &bull; ${f.service} &bull; ${f.cve}
          ${f.mitreTacticId ? ` &bull; <span class="tactic-badge ${f.mitreTacticId}" style="font-size:0.62rem;padding:1px 5px">${f.mitreTacticId}</span>` : ''}
        </div>
      </div>
      <span class="roi-card-score" style="color:${scoreColor}">${f.businessRisk}</span>
      ${removeBtn}
    </div>`;
}

function attachDragListeners(col) {
  const zone = col === 'backlog' ? document.getElementById('dropBacklog') : document.getElementById('dropSprint');
  zone.querySelectorAll('.roi-card').forEach(card => {
    card.addEventListener('dragstart', e => {
      roi.dragId   = card.dataset.id;
      roi.dragFrom = col;
      card.classList.add('dragging');
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/plain', card.dataset.id);
    });
    card.addEventListener('dragend', () => {
      card.classList.remove('dragging');
      document.querySelectorAll('.roi-drop-zone').forEach(z => {
        z.classList.remove('drag-over','drag-over-full');
      });
    });
  });
}

// ─────────────────────────────────────────────────────────
// DRAG EVENTS (global — called from HTML ondragover/ondrop)
// ─────────────────────────────────────────────────────────
window.roiOnDragOver = function(e, target) {
  e.preventDefault();
  const zone = target === 'sprint'
    ? document.getElementById('dropSprint')
    : document.getElementById('dropBacklog');

  if (target === 'sprint' && roi.sprint.length >= roi.capacity && roi.dragFrom !== 'sprint') {
    zone.classList.add('drag-over-full');
    zone.classList.remove('drag-over');
    e.dataTransfer.dropEffect = 'none';
  } else {
    zone.classList.add('drag-over');
    zone.classList.remove('drag-over-full');
    e.dataTransfer.dropEffect = 'move';
  }
};

window.roiOnDragLeave = function(e) {
  e.currentTarget.classList.remove('drag-over','drag-over-full');
};

window.roiOnDrop = function(e, target) {
  e.preventDefault();
  document.querySelectorAll('.roi-drop-zone').forEach(z => z.classList.remove('drag-over','drag-over-full'));

  const id   = roi.dragId || e.dataTransfer.getData('text/plain');
  const from = roi.dragFrom;
  if (!id || !from || from === target) return;

  if (target === 'sprint') {
    // Enforce capacity
    if (roi.sprint.length >= roi.capacity) {
      const sprintCol = document.getElementById('roiColSprint');
      sprintCol.classList.add('capacity-full-shake');
      setTimeout(() => sprintCol.classList.remove('capacity-full-shake'), 420);
      roiShowCapacityToast();
      return;
    }
    // Move from backlog → sprint
    const idx = roi.backlog.findIndex(f => f.id === id);
    if (idx === -1) return;
    const [item] = roi.backlog.splice(idx, 1);
    roi.sprint.push(item);
  } else {
    // Move from sprint → backlog
    const idx = roi.sprint.findIndex(f => f.id === id);
    if (idx === -1) return;
    const [item] = roi.sprint.splice(idx, 1);
    roi.backlog.push(item);
    // Re-sort backlog by risk
    roi.backlog.sort((a, b) => {
      if (a.isKEV && !b.isKEV) return -1;
      if (!a.isKEV && b.isKEV) return 1;
      return b.businessRisk - a.businessRisk;
    });
  }

  roi.dragId   = null;
  roi.dragFrom = null;
  roiRenderBoard();
  roiUpdateAll();
};

// ─────────────────────────────────────────────────────────
// REMOVE FROM SPRINT (✕ button)
// ─────────────────────────────────────────────────────────
window.roiRemoveFromSprint = function(id) {
  const idx = roi.sprint.findIndex(f => f.id === id);
  if (idx === -1) return;
  const [item] = roi.sprint.splice(idx, 1);
  roi.backlog.push(item);
  roi.backlog.sort((a, b) => {
    if (a.isKEV && !b.isKEV) return -1;
    if (!a.isKEV && b.isKEV) return 1;
    return b.businessRisk - a.businessRisk;
  });
  roiRenderBoard();
  roiUpdateAll();
};

// ─────────────────────────────────────────────────────────
// CAPACITY TOAST
// ─────────────────────────────────────────────────────────
function roiShowCapacityToast() {
  let t = document.getElementById('roiCapToast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'roiCapToast';
    t.style.cssText = `
      position:fixed;bottom:28px;right:28px;z-index:999;
      background:#ff4747;color:#fff;padding:12px 20px;border-radius:10px;
      font-weight:700;font-size:0.9rem;box-shadow:0 8px 32px rgba(0,0,0,0.4);
      animation:slideUpToast .3s ease;pointer-events:none;
    `;
    document.head.insertAdjacentHTML('beforeend',
      `<style>@keyframes slideUpToast{from{transform:translateY(20px);opacity:0}to{transform:none;opacity:1}}</style>`);
    document.body.appendChild(t);
  }
  t.textContent = `🚫 Sprint full! Max ${roi.capacity} fixes/sprint. Remove an item first.`;
  t.style.display = 'block';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.style.display = 'none', 2800);
}

// ─────────────────────────────────────────────────────────
// AUTO-FILL: pick top N by business risk (KEV first)
// ─────────────────────────────────────────────────────────
document.getElementById('roiAutoFill').addEventListener('click', () => {
  const slots     = roi.capacity - roi.sprint.length;
  const toAdd     = roi.backlog.slice(0, slots);
  roi.sprint.push(...toAdd);
  roi.backlog     = roi.backlog.slice(slots);
  roiRenderBoard();
  roiUpdateAll();
});

// ─────────────────────────────────────────────────────────
// CLEAR SPRINT
// ─────────────────────────────────────────────────────────
document.getElementById('roiClearSprint').addEventListener('click', () => {
  roi.backlog.push(...roi.sprint);
  roi.sprint = [];
  roi.backlog.sort((a, b) => {
    if (a.isKEV && !b.isKEV) return -1;
    if (!a.isKEV && b.isKEV) return 1;
    return b.businessRisk - a.businessRisk;
  });
  roiRenderBoard();
  roiUpdateAll();
});

// ─────────────────────────────────────────────────────────
// CAPACITY STEPPER
// ─────────────────────────────────────────────────────────
document.getElementById('roiCapDec').addEventListener('click', () => {
  if (roi.capacity <= 1) return;
  roi.capacity--;
  // Eject items beyond new capacity back to backlog
  while (roi.sprint.length > roi.capacity) {
    const item = roi.sprint.pop();
    roi.backlog.unshift(item);
  }
  syncCapacityUI();
  roiRenderBoard();
  roiUpdateAll();
});

document.getElementById('roiCapInc').addEventListener('click', () => {
  if (roi.capacity >= 20) return;
  roi.capacity++;
  syncCapacityUI();
  roiUpdateAll();
});

function syncCapacityUI() {
  document.getElementById('roiCapVal').textContent     = roi.capacity;
  document.getElementById('roiCapInLabel').textContent = roi.capacity;
}

// ─────────────────────────────────────────────────────────
// SEARCH
// ─────────────────────────────────────────────────────────
document.getElementById('roiSearch').addEventListener('input', e => {
  roiRenderBacklog(e.target.value);
});

// ─────────────────────────────────────────────────────────
// LOAD FROM SCAN / DEMO
// ─────────────────────────────────────────────────────────
function roiLoadData() {
  // Use findings from the main app state if available
  const src = (typeof state !== 'undefined' && state.findings && state.findings.length > 0)
    ? state.findings
    : null;

  if (src) {
    roiInit(src);
  } else {
    // Load demo data (use the VULN_DB directly)
    const demo = typeof VULN_DB !== 'undefined'
      ? VULN_DB.map(v => {
          let item = {
            ...v,
            assetCriticality: 3, exposure: 2,
            businessRisk: +((v.exploitability / 10) * (3 / 4) * (2 / 3) * 100).toFixed(1),
            severity: getSeverity?.((v.exploitability / 10) * (3 / 4) * (2 / 3) * 100) || 'High',
            isKEV: false,
          };
          if (typeof enrichWithMitreAttack === 'function') {
            item = enrichWithMitreAttack(item);
          }
          return item;
        })
      : [];
    roiInit(demo);
  }
}

document.getElementById('roiLoadScan').addEventListener('click', roiLoadData);
document.getElementById('roiDemoLoad').addEventListener('click', roiLoadData);

// ─────────────────────────────────────────────────────────
// TAB ACTIVATION HOOK — trigger init when ROI tab opens
// ─────────────────────────────────────────────────────────
document.querySelector('.nav-btn[data-tab="roi"]').addEventListener('click', () => {
  // Small delay to let the tab paint first
  setTimeout(() => {
    if (roi.allItems.length === 0) roiLoadData();
    else if (roi.chartInst) roi.chartInst.resize();
  }, 80);
});

// ─────────────────────────────────────────────────────────
// SYNC: called from app.js after scan completes
// ─────────────────────────────────────────────────────────
window.roiSyncFromScan = function(findings) {
  roi.allItems = [];
  roi.backlog  = [];
  roi.sprint   = [];
  roiInit(findings);
};
