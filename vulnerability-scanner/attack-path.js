/* ══════════════════════════════════════════════════════
   VulnRankPro — attack-path.js
   Interactive Attack Path Visualization & Topology Graph
   Visualizing Business-Risk Math:
     • Exposure (Concentric Perimeter Placement)
     • Asset Criticality (Node Sizing)
     • Pivot Path & Remediation Roadmap Severing
   ══════════════════════════════════════════════════════ */

'use strict';

// ─────────────────────────────────────────────────────────
// 1. TOPOLOGY MODEL & LAB ENVIRONMENT
// ─────────────────────────────────────────────────────────
const AP_TOPOLOGY = {
  // Concentric Zones (Centered at x=450, y=280)
  center: { x: 440, y: 280 },
  zones: [
    { id: 'core',      name: 'Restricted Enclave', exposure: 1, radius: 150, color: 'rgba(239, 68, 68, 0.05)', stroke: 'rgba(239, 68, 68, 0.25)' },
    { id: 'dmz',       name: 'DMZ Tier',           exposure: 2, radius: 270, color: 'rgba(251, 191, 36, 0.03)', stroke: 'rgba(251, 191, 36, 0.2)'  },
    { id: 'perimeter', name: 'Perimeter Ring',     exposure: 3, radius: 390, color: 'rgba(56, 189, 248, 0.02)', stroke: 'rgba(56, 189, 248, 0.15)' },
  ],

  // Nodes with exact Lab IPs, Domains, Exposure, Criticality
  nodes: [
    {
      id:          'ext_attacker',
      label:       'External Adversary',
      hostname:    'threat-actor.external.net',
      ip:          '203.0.113.42',
      tier:        'Untrusted Internet',
      exposure:    3,
      criticality: 0,
      x:           95,
      y:           280,
      icon:        '💀',
      color:       '#ef4444',
      services:    ['Tor Exit Node', 'Cobalt Strike C2 Listener'],
      vulns:       [],
      desc:        'Untrusted threat actor operating from public internet.'
    },
    {
      id:          'dmz_web',
      label:       'DMZ Web Gateway',
      hostname:    'web.lab.local',
      ip:          '192.168.1.100',
      tier:        'Perimeter Ring',
      exposure:    3, // Outer Perimeter
      criticality: 2, // Edge proxy
      x:           265,
      y:           160,
      icon:        '🌐',
      color:       '#38bdf8',
      services:    ['Apache 2.2.8:80', 'Tomcat:8080', 'HTTPS:443'],
      vulns:       ['V008', 'V017', 'V006', 'V016', 'V009'],
      desc:        'Public-facing web server hosting Drupal and PHP application stacks.'
    },
    {
      id:          'dmz_files',
      label:       'DMZ File & Exchange',
      hostname:    'files.lab.local',
      ip:          '192.168.1.105',
      tier:        'DMZ Tier',
      exposure:    2, // Semi-Public
      criticality: 2,
      x:           285,
      y:           400,
      icon:        '📂',
      color:       '#fbbf24',
      services:    ['vsftpd:21', 'SMTP:25', 'Telnet:23', 'Samba SMB:445'],
      vulns:       ['V001', 'V003', 'V004', 'V005'],
      desc:        'File sharing and relay server sitting in the demilitarized zone.'
    },
    {
      id:          'int_app',
      label:       'Internal App Tier',
      hostname:    'app.corp.internal',
      ip:          '192.168.1.120',
      tier:        'Internal Network',
      exposure:    1, // Restricted
      criticality: 3, // Production App Server (Large)
      x:           510,
      y:           280,
      icon:        '⚙️',
      color:       '#818cf8',
      services:    ['Java RMI:1099', 'distccd:3632', 'OpenSSH:22', 'X11:6000'],
      vulns:       ['V011', 'V015', 'V002', 'V014', 'V018'],
      desc:        'Internal application runtime host and compilation cluster.'
    },
    {
      id:          'int_core',
      label:       'Crown-Jewel Core DB',
      hostname:    'db-master.secure.internal',
      ip:          '192.168.1.150',
      tier:        'Protected Enclave',
      exposure:    1, // Internal Only
      criticality: 4, // Critical Crown Jewel (MASSIVE node)
      x:           735,
      y:           280,
      icon:        '👑',
      color:       '#f43f5e',
      services:    ['MySQL:3306', 'PostgreSQL:5432', 'NFS:2049', 'Bindshell:1524', 'IRC:6667'],
      vulns:       ['V007', 'V012', 'V010', 'V019', 'V013', 'V020'],
      desc:        'High-value primary database holding financial, customer, and credential records.'
    }
  ],

  // Network directional access paths (Edges)
  edges: [
    { id: 'e_ext_web',   from: 'ext_attacker', to: 'dmz_web',   label: 'HTTP/HTTPS Ingress: 80/443' },
    { id: 'e_ext_files', from: 'ext_attacker', to: 'dmz_files', label: 'FTP/SMTP Ingress: 21/25' },
    { id: 'e_web_files', from: 'dmz_web',      to: 'dmz_files', label: 'SMB Protocol: 445' },
    { id: 'e_web_app',   from: 'dmz_web',      to: 'int_app',   label: 'Internal API: 8080/3632' },
    { id: 'e_files_app', from: 'dmz_files',    to: 'int_app',   label: 'NFS/Build Sync: 2049' },
    { id: 'e_app_core',  from: 'int_app',      to: 'int_core',  label: 'Backend DB Channel: 3306/5432' },
    { id: 'e_files_core',from: 'dmz_files',    to: 'int_core',  label: 'Admin Direct Shell: 1524' }
  ],

  // Attack Vectors (Multi-Hop Pivot Paths)
  vectors: {
    'vector-1': {
      id:    'vector-1',
      name:  'Vector A: Web RCE → Samba SMB → Core Crown Jewel',
      color: '#ef4444',
      risk:  100,
      hops: [
        {
          id:       'h1',
          edgeId:   'e_ext_web',
          from:     'ext_attacker',
          to:       'dmz_web',
          vulnId:   'V017',
          vulnName: 'Drupal SQLi (CVE-2014-3704) / PHP RCE (CVE-2012-1823)',
          port:     '80/tcp',
          phase:    'Phase 1: Initial Access',
          desc:     'Attacker exploits public web tier vulnerabilities to obtain web shell execution on the perimeter host.'
        },
        {
          id:       'h2',
          edgeId:   'e_web_files',
          from:     'dmz_web',
          to:       'dmz_files',
          vulnId:   'V003',
          vulnName: 'Samba Command Injection RCE (CVE-2007-2447)',
          port:     '445/tcp',
          phase:    'Phase 4: Lateral Movement',
          desc:     'From compromised perimeter web server, attacker pivots laterally to DMZ File Exchange using Samba usermap_script.'
        },
        {
          id:       'h3',
          edgeId:   'e_files_app',
          from:     'dmz_files',
          to:       'int_app',
          vulnId:   'V015',
          vulnName: 'distccd Unauthenticated RCE (CVE-2004-2687)',
          port:     '3632/tcp',
          phase:    'Phase 2: Neutralize Execution',
          desc:     'Attacker pivots further into internal application cluster executing commands via unprotected distcc compiler daemon.'
        },
        {
          id:       'h4',
          edgeId:   'e_app_core',
          from:     'int_app',
          to:       'int_core',
          vulnId:   'V007',
          vulnName: 'MySQL Root Without Password / Root Bindshell 1524 (V019)',
          port:     '3306/1524',
          phase:    'Phase 3: Credential Access',
          desc:     'From internal app host, adversary connects directly to MySQL without a password and drops an interactive root shell.'
        }
      ]
    },
    'vector-2': {
      id:    'vector-2',
      name:  'Vector B: vsftpd Backdoor → Root Bindshell Takeover',
      color: '#f97316',
      risk:  100,
      hops: [
        {
          id:       'h1',
          edgeId:   'e_ext_files',
          from:     'ext_attacker',
          to:       'dmz_files',
          vulnId:   'V001',
          vulnName: 'vsftpd 2.3.4 Backdoor (CVE-2011-2523)',
          port:     '21/tcp',
          phase:    'Phase 1: Initial Access',
          desc:     'Attacker triggers compiled-in FTP backdoor on public port 21 to spawn a command shell.'
        },
        {
          id:       'h2',
          edgeId:   'e_files_core',
          from:     'dmz_files',
          to:       'int_core',
          vulnId:   'V019',
          vulnName: 'Root Bindshell on Port 1524',
          port:     '1524/tcp',
          phase:    'Phase 5: Sever Command & Control',
          desc:     'Attacker pivots across unsegmented network directly into root bindshell listening on the core database server.'
        }
      ]
    },
    'vector-3': {
      id:    'vector-3',
      name:  'Vector C: Tomcat Manager → Java RMI → Core Database',
      color: '#eab308',
      risk:  85,
      hops: [
        {
          id:       'h1',
          edgeId:   'e_ext_web',
          from:     'ext_attacker',
          to:       'dmz_web',
          vulnId:   'V006',
          vulnName: 'Apache Tomcat Manager Default Creds (CVE-2009-3548)',
          port:     '8080/tcp',
          phase:    'Phase 2: Neutralize Execution',
          desc:     'Default credentials on Tomcat manager permit WAR file deployment and remote execution.'
        },
        {
          id:       'h2',
          edgeId:   'e_web_app',
          from:     'dmz_web',
          to:       'int_app',
          vulnId:   'V011',
          vulnName: 'Java RMI Registry Insecure Deserialization (CVE-2015-4852)',
          port:     '1099/tcp',
          phase:    'Phase 2: Neutralize Execution',
          desc:     'Adversary invokes deserialization gadget chains across the internal network.'
        },
        {
          id:       'h3',
          edgeId:   'e_app_core',
          from:     'int_app',
          to:       'int_core',
          vulnId:   'V012',
          vulnName: 'PostgreSQL Trust Authentication (No Password)',
          port:     '5432/tcp',
          phase:    'Phase 3: Credential Access',
          desc:     'Unrestricted trust authentication grants immediate superuser access to PostgreSQL crown jewel records.'
        }
      ]
    }
  }
};

// ─────────────────────────────────────────────────────────
// 2. ATTACK PATH STATE
// ─────────────────────────────────────────────────────────
const apState = {
  currentVectorId: 'vector-1',
  severedHops:     new Set(), // Set of hop IDs or edge IDs severed
  selectedNodeId:  'int_core',
  dragNode:        null,
  dragOffset:      { x: 0, y: 0 },
  initialized:     false
};

// ─────────────────────────────────────────────────────────
// 3. MATH VISUALIZATION ENCODING HELPERS
// ─────────────────────────────────────────────────────────
/**
 * Asset Criticality Math -> Node Size
 * Criticality 0 (Adversary): 24px
 * Criticality 1 (Dev/Test): 32px
 * Criticality 2 (DMZ/Internal): 42px
 * Criticality 3 (Production): 54px
 * Criticality 4 (Crown Jewel DB): 72px (Massive pulsating node)
 */
function getNodeRadius(crit) {
  if (crit === 0) return 24;
  if (crit === 1) return 32;
  if (crit === 2) return 42;
  if (crit === 3) return 54;
  return 72; // Criticality 4 Crown Jewel
}

// ─────────────────────────────────────────────────────────
// 4. GRAPH RENDERING ENGINE (INTERACTIVE SVG)
// ─────────────────────────────────────────────────────────
function renderAttackPathGraph() {
  const svg = document.getElementById('apGraphSvg');
  if (!svg) return;

  const vector = AP_TOPOLOGY.vectors[apState.currentVectorId] || AP_TOPOLOGY.vectors['vector-1'];
  const activeHops = vector.hops || [];
  const activeEdgeIds = new Set(activeHops.map(h => h.edgeId));

  // Determine if the path is severed
  let isSevered = false;
  let severedHopIndex = -1;
  activeHops.forEach((h, idx) => {
    if (apState.severedHops.has(h.id) || apState.severedHops.has(h.edgeId) || apState.severedHops.has(h.vulnId)) {
      if (!isSevered) {
        isSevered = true;
        severedHopIndex = idx;
      }
    }
  });

  // Calculate downstream compromised state
  const compromisedNodes = new Set();
  compromisedNodes.add('ext_attacker');
  if (!isSevered) {
    activeHops.forEach(h => compromisedNodes.add(h.to));
  } else {
    for (let i = 0; i < severedHopIndex; i++) {
      compromisedNodes.add(activeHops[i].to);
    }
  }

  const isCrownJewelCompromised = compromisedNodes.has('int_core');

  let html = `
    <!-- Defs: Markers & Gradients -->
    <defs>
      <filter id="glow-red" x="-20%" y="-20%" width="140%" height="140%">
        <feGaussianBlur stdDeviation="6" result="blur" />
        <feComposite in="SourceGraphic" in2="blur" operator="over" />
      </filter>
      <filter id="glow-gold" x="-30%" y="-30%" width="160%" height="160%">
        <feGaussianBlur stdDeviation="8" result="blur" />
        <feComposite in="SourceGraphic" in2="blur" operator="over" />
      </filter>
      <marker id="arrow-default" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto">
        <path d="M 0 1 L 10 5 L 0 9 z" fill="#334155" />
      </marker>
      <marker id="arrow-active" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="7" markerHeight="7" orient="auto">
        <path d="M 0 1 L 10 5 L 0 9 z" fill="#ef4444" />
      </marker>
      <marker id="arrow-severed" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto">
        <path d="M 0 1 L 10 5 L 0 9 z" fill="#475569" />
      </marker>
    </defs>
  `;

  // 1. Concentric Exposure Perimeter Rings (Math Visualization of Exposure)
  const cx = 580, cy = 280; // Pivot layout anchor
  html += `
    <g class="ap-zones-group">
      <!-- Exposure 3: Outer Perimeter -->
      <circle cx="${cx}" cy="${cy}" r="390" fill="rgba(56, 189, 248, 0.02)" stroke="rgba(56, 189, 248, 0.2)" stroke-dasharray="6,6" stroke-width="1.5" />
      <text x="${cx - 380}" y="${cy - 230}" fill="#38bdf8" font-size="11" font-family="'JetBrains Mono',monospace" font-weight="700" letter-spacing="1">
        ⭕ PERIMETER ZONE (EXPOSURE: 3 / INTERNET-FACING)
      </text>

      <!-- Exposure 2: DMZ Mid-Tier -->
      <circle cx="${cx}" cy="${cy}" r="275" fill="rgba(251, 191, 36, 0.03)" stroke="rgba(251, 191, 36, 0.25)" stroke-dasharray="5,5" stroke-width="1.5" />
      <text x="${cx - 265}" y="${cy - 170}" fill="#fbbf24" font-size="11" font-family="'JetBrains Mono',monospace" font-weight="700" letter-spacing="1">
        🛡️ DMZ MIDDLE TIER (EXPOSURE: 2 / SEMI-PUBLIC)
      </text>

      <!-- Exposure 1: Core Restricted Enclave -->
      <circle cx="${cx}" cy="${cy}" r="155" fill="rgba(239, 68, 68, 0.05)" stroke="rgba(239, 68, 68, 0.3)" stroke-dasharray="4,4" stroke-width="1.5" />
      <text x="${cx - 145}" y="${cy - 110}" fill="#f87171" font-size="11" font-family="'JetBrains Mono',monospace" font-weight="700" letter-spacing="1">
        👑 CORE RESTRICTED ENCLAVE (EXPOSURE: 1 / INTERNAL)
      </text>
    </g>
  `;

  // 2. Edges (Network access paths)
  html += `<g class="ap-edges-group">`;
  AP_TOPOLOGY.edges.forEach(edge => {
    const fromNode = AP_TOPOLOGY.nodes.find(n => n.id === edge.from);
    const toNode   = AP_TOPOLOGY.nodes.find(n => n.id === edge.to);
    if (!fromNode || !toNode) return;

    const hopIndex = activeHops.findIndex(h => h.edgeId === edge.id);
    const isInActiveVector = hopIndex !== -1;

    let edgeClass = 'ap-edge-default';
    let marker    = 'url(#arrow-default)';
    let isEdgeSevered = false;

    if (isInActiveVector) {
      if (isSevered && hopIndex >= severedHopIndex) {
        edgeClass = 'ap-edge-severed';
        marker    = 'url(#arrow-severed)';
        isEdgeSevered = true;
      } else {
        edgeClass = 'ap-edge-active';
        marker    = 'url(#arrow-active)';
      }
    }

    // Draw straight or slight curve
    const x1 = fromNode.x, y1 = fromNode.y;
    const x2 = toNode.x,   y2 = toNode.y;

    // Edge line
    html += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="${edgeClass}" marker-end="${marker}" />`;

    // Severed scissor badge if severed at this exact hop
    if (isInActiveVector && hopIndex === severedHopIndex) {
      const midX = (x1 + x2) / 2;
      const midY = (y1 + y2) / 2;
      html += `
        <g class="ap-severed-badge" transform="translate(${midX}, ${midY})">
          <rect x="-38" y="-14" width="76" height="28" rx="14" fill="#111827" stroke="#ef4444" stroke-width="2" />
          <text x="0" y="4" fill="#f87171" font-size="11" font-weight="900" text-anchor="middle" font-family="'JetBrains Mono',monospace">
            ✂️ SEVERED
          </text>
        </g>
      `;
    }
  });
  html += `</g>`;

  // 3. Nodes (Sized by Asset Criticality)
  html += `<g class="ap-nodes-group">`;
  AP_TOPOLOGY.nodes.forEach(node => {
    const r = getNodeRadius(node.criticality);
    const isCrown = node.id === 'int_core';
    const isCompromised = compromisedNodes.has(node.id);

    let fill = '#1e293b';
    let stroke = node.color;
    let nodeClasses = 'ap-node-circle';

    if (isCrown) {
      if (isCrownJewelCompromised) {
        fill = '#450a0a';
        stroke = '#ef4444';
        nodeClasses += ' ap-node-crown';
      } else {
        fill = '#064e3b';
        stroke = '#10b981';
        nodeClasses += ' ap-node-shielded';
      }
    } else if (isCompromised) {
      fill = '#1f1315';
      stroke = '#ef4444';
    }

    html += `
      <g class="ap-node" id="node-${node.id}" transform="translate(${node.x}, ${node.y})"
         onmousedown="apStartDrag(event, '${node.id}')"
         onclick="apSelectNode('${node.id}')"
         onmouseenter="apShowTooltip(event, '${node.id}')"
         onmouseleave="apHideTooltip()">

        <!-- Node Outer Ring -->
        <circle cx="0" cy="0" r="${r}" fill="${fill}" stroke="${stroke}" stroke-width="2.5" class="${nodeClasses}" />

        <!-- Node Icon -->
        <text x="0" y="${r >= 50 ? -12 : -4}" font-size="${r >= 50 ? 26 : 18}" text-anchor="middle" dominant-baseline="central">
          ${node.icon}
        </text>

        <!-- Node IP / Hostname -->
        <text x="0" y="${r >= 50 ? 14 : 10}" fill="#ffffff" font-size="${r >= 50 ? 12 : 9.5}" font-weight="800" text-anchor="middle" font-family="'JetBrains Mono',monospace">
          ${node.ip}
        </text>

        <!-- Criticality / Status Badge -->
        <text x="0" y="${r >= 50 ? 28 : 22}" fill="${isCrown ? (isCrownJewelCompromised ? '#fca5a5' : '#6ee7b7') : '#94a3b8'}" font-size="8.5" font-weight="700" text-anchor="middle" font-family="'JetBrains Mono',monospace">
          ${isCrown ? (isCrownJewelCompromised ? '⚠️ COMPROMISED' : '🛡️ SHIELDED') : `Crit: ${node.criticality}/4`}
        </text>

        <!-- Label below node -->
        <text x="0" y="${r + 16}" fill="#cbd5e1" font-size="11" font-weight="700" text-anchor="middle">
          ${node.label}
        </text>
        <text x="0" y="${r + 28}" fill="#64748b" font-size="9" text-anchor="middle" font-family="'JetBrains Mono',monospace">
          ${node.hostname}
        </text>
      </g>
    `;
  });
  html += `</g>`;

  svg.innerHTML = html;

  // Update Inspector side panel
  renderAttackPathInspector(vector, isSevered, severedHopIndex, isCrownJewelCompromised);
}

// ─────────────────────────────────────────────────────────
// 5. INSPECTOR & ROADMAP INTEGRATION PANEL
// ─────────────────────────────────────────────────────────
function renderAttackPathInspector(vector, isSevered, severedHopIndex, isCrownJewelCompromised) {
  // 1. Status Banner
  const banner = document.getElementById('apStatusBanner');
  const title  = document.getElementById('apStatusTitle');
  const desc   = document.getElementById('apStatusDesc');
  const globalBadge = document.getElementById('apGlobalStatusBadge');

  if (isSevered) {
    banner.className = 'ap-status-banner severed';
    banner.querySelector('.asb-icon').textContent = '🛡️';
    title.textContent = 'ATTACK PATH SUCCESSFULLY SEVERED!';
    desc.textContent  = `Adversary pivot terminated at Hop ${severedHopIndex + 1}. The Crown-Jewel Database (192.168.1.150) is protected from lateral compromise.`;
    globalBadge.className = 'ap-badge';
    globalBadge.style.background = 'rgba(16, 185, 129, 0.15)';
    globalBadge.style.color = '#34d399';
    globalBadge.style.borderColor = 'rgba(16, 185, 129, 0.4)';
    globalBadge.textContent = '🛡️ Attack Vector: SEVERED BY SPRINT';
  } else {
    banner.className = 'ap-status-banner danger';
    banner.querySelector('.asb-icon').textContent = '⚠️';
    title.textContent = 'Active Multi-Hop Pivot to Crown Jewel';
    desc.textContent  = 'An adversary breaching the perimeter node can pivot across subnets and achieve full root execution on the core database.';
    globalBadge.className = 'ap-badge active-path-badge';
    globalBadge.style.background = '';
    globalBadge.style.color = '';
    globalBadge.style.borderColor = '';
    globalBadge.textContent = '🔴 Primary Pivot Vector: UNMITIGATED';
  }

  // 2. Hop Count Badge
  document.getElementById('apHopCountBadge').textContent = `${vector.hops.length} Hops to Crown Jewel`;

  // 3. Step-by-Step Hop Cards
  const hopsList = document.getElementById('apHopsList');
  hopsList.innerHTML = vector.hops.map((hop, idx) => {
    const isThisHopSevered = apState.severedHops.has(hop.id) || apState.severedHops.has(hop.vulnId);
    const isBlockedDownstream = isSevered && idx > severedHopIndex;

    const fromNode = AP_TOPOLOGY.nodes.find(n => n.id === hop.from);
    const toNode   = AP_TOPOLOGY.nodes.find(n => n.id === hop.to);

    return `
      <div class="ap-hop-card ${isThisHopSevered ? 'severed' : ''}">
        <div class="ap-hop-card-header">
          <span class="ahc-hop-num">
            ${isThisHopSevered ? '✂️ HOP ' + (idx + 1) + ' SEVERED' : 'HOP ' + (idx + 1) + (isBlockedDownstream ? ' (BLOCKED)' : ' (ACTIVE)')}
          </span>
          <button class="btn-sever-hop ${isThisHopSevered ? 'active-severed' : ''}" onclick="apToggleSeverHop('${hop.id}')">
            ${isThisHopSevered ? '↺ Restore Path' : '✂️ Sever Hop'}
          </button>
        </div>
        <div class="ahc-route">
          ${fromNode ? fromNode.ip : hop.from} &rarr; ${toNode ? toNode.ip : hop.to} <small style="color:var(--text3)">(${hop.port})</small>
        </div>
        <div class="ahc-vuln">
          <strong>Exploit:</strong> ${hop.vulnName}
        </div>
        <div style="font-size:0.72rem;color:var(--text3);margin-top:3px">
          ${hop.desc}
        </div>
      </div>
    `;
  }).join('');

  // 4. Roadmap Integration: Weekly Sprint Tasks that Sever Paths
  renderRoadmapSprintSeveringTasks();
}

/**
 * Connects the Attack Path Graph to the Remediation Roadmap!
 * Renders weekly sprint tasks with instant path-severing simulation toggles
 */
function renderRoadmapSprintSeveringTasks() {
  const container = document.getElementById('apRoadmapTasksList');
  if (!container) return;

  const vector = AP_TOPOLOGY.vectors[apState.currentVectorId] || AP_TOPOLOGY.vectors['vector-1'];
  const activeVulnIds = new Set(vector.hops.map(h => h.vulnId));

  // Get current scan findings or demo VULN_DB
  const findings = (typeof state !== 'undefined' && state.findings && state.findings.length > 0)
    ? state.findings
    : VULN_DB;

  // Find roadmap tasks relevant to our active attack path
  const relevantTasks = findings.filter(f => activeVulnIds.has(f.id));

  if (relevantTasks.length === 0) {
    container.innerHTML = `<p style="font-size:0.75rem;color:var(--text3)">No direct sprint tasks match this vector. Switch vector above.</p>`;
    return;
  }

  container.innerHTML = relevantTasks.map(task => {
    const isChecked = apState.severedHops.has(task.id);
    return `
      <div class="arb-task-item ${isChecked ? 'checked' : ''}" onclick="apToggleSprintFix('${task.id}')">
        <div class="arb-task-left">
          <input type="checkbox" ${isChecked ? 'checked' : ''} onclick="event.stopPropagation(); apToggleSprintFix('${task.id}')" />
          <div>
            <span class="arb-task-name">${task.isKEV ? '🇺🇸 ' : ''}${task.name}</span>
            <div style="font-size:0.7rem;color:var(--text3)">${task.cve || task.id} &bull; ${task.port}/tcp</div>
          </div>
        </div>
        <span class="arb-task-score">${task.businessRisk || 100}</span>
      </div>
    `;
  }).join('');
}

// ─────────────────────────────────────────────────────────
// 6. INTERACTIVE SEVERING & SIMULATION CONTROLS
// ─────────────────────────────────────────────────────────
window.apToggleSeverHop = function(hopId) {
  if (apState.severedHops.has(hopId)) {
    apState.severedHops.delete(hopId);
  } else {
    apState.severedHops.add(hopId);
  }
  renderAttackPathGraph();
};

window.apToggleSprintFix = function(vulnId) {
  // Find which hop contains this vuln
  const vector = AP_TOPOLOGY.vectors[apState.currentVectorId];
  const matchingHop = vector?.hops.find(h => h.vulnId === vulnId);

  if (apState.severedHops.has(vulnId) || (matchingHop && apState.severedHops.has(matchingHop.id))) {
    apState.severedHops.delete(vulnId);
    if (matchingHop) apState.severedHops.delete(matchingHop.id);
  } else {
    apState.severedHops.add(vulnId);
    if (matchingHop) apState.severedHops.add(matchingHop.id);
  }
  renderAttackPathGraph();
};

// Button: Sever Current Vector at Lateral Pivot
document.getElementById('apSeverCurrentBtn')?.addEventListener('click', () => {
  const vector = AP_TOPOLOGY.vectors[apState.currentVectorId];
  if (vector && vector.hops.length >= 2) {
    const hop2 = vector.hops[1];
    apToggleSeverHop(hop2.id);
  }
});

// Button: Reset All Severed Paths
document.getElementById('apResetPathsBtn')?.addEventListener('click', () => {
  apState.severedHops.clear();
  renderAttackPathGraph();
});

// Button: Center Crown Jewel
document.getElementById('apFitGraphBtn')?.addEventListener('click', () => {
  apSelectNode('int_core');
});

// Vector Select dropdown
document.getElementById('apVectorSelect')?.addEventListener('change', e => {
  apState.currentVectorId = e.target.value;
  renderAttackPathGraph();
});

// ─────────────────────────────────────────────────────────
// 7. NODE SELECTION & TOOLTIP
// ─────────────────────────────────────────────────────────
window.apSelectNode = function(nodeId) {
  apState.selectedNodeId = nodeId;
  const node = AP_TOPOLOGY.nodes.find(n => n.id === nodeId);
  if (!node) return;

  const stats = document.getElementById('apPathStats');
  if (stats) {
    stats.innerHTML = `
      Selected Host: <strong>${node.label}</strong> (${node.ip}) &bull;
      Exposure: <strong>${node.exposure}/3</strong> &bull;
      Criticality: <strong>${node.criticality}/4</strong>
    `;
  }
};

window.apShowTooltip = function(e, nodeId) {
  const node = AP_TOPOLOGY.nodes.find(n => n.id === nodeId);
  const tt   = document.getElementById('apTooltip');
  if (!node || !tt) return;

  const rect = document.getElementById('apCanvasContainer').getBoundingClientRect();
  const x = e.clientX - rect.left + 15;
  const y = e.clientY - rect.top + 15;

  tt.innerHTML = `
    <strong>${node.icon} ${node.label}</strong>
    <div class="tt-row">IP: <span class="tt-val">${node.ip}</span></div>
    <div class="tt-row">Hostname: <span class="tt-val">${node.hostname}</span></div>
    <div class="tt-row">Tier: <span style="color:#cbd5e1">${node.tier}</span></div>
    <div class="tt-row">Exposure: <span class="tt-val">${node.exposure}/3</span></div>
    <div class="tt-row">Asset Criticality: <span class="tt-val">${node.criticality}/4</span></div>
    <div style="margin-top:6px;font-size:0.72rem;color:#94a3b8">
      Services: ${node.services.join(', ')}
    </div>
  `;
  tt.style.left = `${Math.min(x, rect.width - 270)}px`;
  tt.style.top  = `${Math.min(y, rect.height - 180)}px`;
  tt.classList.remove('hidden');
};

window.apHideTooltip = function() {
  const tt = document.getElementById('apTooltip');
  if (tt) tt.classList.add('hidden');
};

// ─────────────────────────────────────────────────────────
// 8. ROADMAP INTERACTION: "VIEW IN ATTACK PATH"
// ─────────────────────────────────────────────────────────
/**
 * Called when user clicks "🕸️ View Path" on any task in the Remediation Roadmap tab.
 * Switches to Tab 6, focuses the relevant vector, and simulates severing that attack path!
 */
window.openAttackPathWithFix = function(vulnId) {
  // 1. Switch tab to attack-path
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelector('.nav-btn[data-tab="attack-path"]')?.classList.add('active');
  document.getElementById('tab-attack-path')?.classList.add('active');

  // 2. Identify vector containing this vulnerability
  let targetVector = 'vector-1';
  for (const [vKey, vObj] of Object.entries(AP_TOPOLOGY.vectors)) {
    if (vObj.hops.some(h => h.vulnId === vulnId)) {
      targetVector = vKey;
      break;
    }
  }

  // 3. Set vector and simulate severing
  apState.currentVectorId = targetVector;
  const select = document.getElementById('apVectorSelect');
  if (select) select.value = targetVector;

  // Toggle this specific fix in the severing set
  apState.severedHops.clear();
  apState.severedHops.add(vulnId);

  // Render updated graph
  renderAttackPathGraph();
};

// ─────────────────────────────────────────────────────────
// 9. TAB HOOK & INITIALIZATION
// ─────────────────────────────────────────────────────────
document.querySelector('.nav-btn[data-tab="attack-path"]')?.addEventListener('click', () => {
  setTimeout(() => {
    renderAttackPathGraph();
  }, 60);
});

// Initial startup render
setTimeout(() => {
  renderAttackPathGraph();
}, 200);
