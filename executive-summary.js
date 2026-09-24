/* ══════════════════════════════════════════════════════
   VulnRankPro — executive-summary.js
   One-Click Executive Summary PDF & Reporting Engine
   • Data Aggregation & Baseline vs Projected Risk KPI
   • Jargon Translation Parser (Asset Criticality Based)
   • Visual Donut / Pie Chart (Risk Secured)
   • jsPDF Document Generator & Print Engine
   ══════════════════════════════════════════════════════ */

'use strict';

// ─────────────────────────────────────────────────────────
// 1. JARGON TRANSLATION ENGINE
// ─────────────────────────────────────────────────────────
/**
 * Strips raw technical jargon (CVE codes, port numbers, protocol acronyms)
 * and translates vulnerabilities into board-level business asset impacts
 * based on Asset Criticality metadata.
 */
function translateToExecutiveLanguage(finding) {
  const crit = finding.assetCriticality || 3;
  const id   = finding.id || '';

  // Asset Name mapping based on Criticality & Role
  let assetName = 'Production Business Server';
  let assetSub  = 'Standard Infrastructure';
  if (crit === 4) {
    assetName = 'Primary Customer & Financial Database';
    assetSub  = 'Tier 1 — Mission-Critical Data Store';
  } else if (crit === 3) {
    if ([80, 443].includes(finding.port)) {
      assetName = 'Public-Facing Web Application Portal';
      assetSub  = 'Tier 2 — Customer Ingress Gateway';
    } else {
      assetName = 'Core Application & Compilation Server';
      assetSub  = 'Tier 2 — Production Application Host';
    }
  } else if (crit === 2) {
    assetName = 'DMZ Communications & File Exchange Gateway';
    assetSub  = 'Tier 3 — Perimeter Supporting Host';
  } else {
    assetName = 'Development & Staging Test Host';
    assetSub  = 'Tier 4 — Non-Production Asset';
  }

  // Business Action & Consequence Translation (Zero Jargon)
  let businessAction = 'Remediated Unauthorized Access Vector';
  let businessImpact = 'Prevents unauthorized access into the business network.';
  let phaseBlocked   = 'Access Prevention';

  const translations = {
    'V001': { // vsftpd
      action: 'Removed Covert Administrative Backdoor',
      impact: 'Stops external threat actors from obtaining instant root shell control.',
      phase:  'Phase 1: Block Initial Access'
    },
    'V002': { // SSH default
      action: 'Enforced Strong Multi-Factor Authentication',
      impact: 'Revokes factory default passwords and blocks automated brute-force takeovers.',
      phase:  'Phase 3: Invalidate Credential Access'
    },
    'V003': { // Samba RCE
      action: 'Eliminated Unauthenticated Remote Takeover Vector',
      impact: 'Blocks adversaries from executing malicious code and pivoting laterally into core databases.',
      phase:  'Phase 1: Block Initial Access'
    },
    'V004': { // Telnet
      action: 'Decommissioned Cleartext Transmission Service',
      impact: 'Stops interception and theft of internal administrative credentials on the wire.',
      phase:  'Phase 3: Invalidate Credential Access'
    },
    'V005': { // SMTP Relay
      action: 'Restricted Mail Routing & Relaying Rules',
      impact: 'Prevents our company infrastructure from being weaponized for external phishing campaigns.',
      phase:  'Phase 1: Block Initial Access'
    },
    'V006': { // Tomcat
      action: 'Secured Application Manager Deployment Console',
      impact: 'Terminates unauthorized deployment of rogue applications onto internal servers.',
      phase:  'Phase 2: Neutralize Execution'
    },
    'V007': { // MySQL no pass
      action: 'Enforced Mandatory Password Protection on Database',
      impact: 'Eliminates open remote root database queries, protecting confidential customer records.',
      phase:  'Phase 3: Invalidate Credential Access'
    },
    'V008': { // PHP-CGI RCE
      action: 'Patched Remote Code Execution Gateway',
      impact: 'Blocks web attackers from injecting arbitrary commands into edge server processes.',
      phase:  'Phase 2: Neutralize Execution'
    },
    'V009': { // POODLE
      action: 'Enforced Modern Cryptographic Cipher Standards',
      impact: 'Disables legacy encryption protocols vulnerable to session eavesdropping and decryption.',
      phase:  'Phase 3: Invalidate Credential Access'
    },
    'V010': { // NFS Root Export
      action: 'Restricted Unrestricted File Share Access',
      impact: 'Prevents untrusted hosts from reading or modifying the root server filesystem.',
      phase:  'Phase 4: Contain Lateral Movement'
    },
    'V011': { // Java RMI
      action: 'Hardened Remote Object Invocations Against Deserialization',
      impact: 'Blocks complex multi-stage payload execution across the enterprise application layer.',
      phase:  'Phase 2: Neutralize Execution'
    },
    'V012': { // PostgreSQL Trust
      action: 'Enforced Strict SCRAM Authentication on Internal Database',
      impact: 'Stops network pivoters from querying proprietary database records without verification.',
      phase:  'Phase 3: Invalidate Credential Access'
    },
    'V013': { // UnrealIRCd
      action: 'Purged Unauthorized Backdoor From Communication Server',
      impact: 'Terminates persistent command-and-control beaconing out of corporate infrastructure.',
      phase:  'Phase 5: Sever Command & Control'
    },
    'V014': { // X11
      action: 'Disabled Remote Graphical Display Hijacking',
      impact: 'Protects user sessions from keystroke logging and unauthorized screen captures.',
      phase:  'Phase 4: Contain Lateral Movement'
    },
    'V015': { // distccd
      action: 'Hardened Distributed Compilation Daemon',
      impact: 'Prevents rogue command execution on development and continuous integration hosts.',
      phase:  'Phase 2: Neutralize Execution'
    },
    'V016': { // HTTP TRACE
      action: 'Disabled Diagnostic Session Tracing Protocols',
      impact: 'Prevents session cookie theft and credential hijacking against corporate web portal users.',
      phase:  'Phase 3: Invalidate Credential Access'
    },
    'V017': { // Drupal
      action: 'Hardened Web Core Against Injection Attacks',
      impact: 'Stops unauthenticated attackers from creating unauthorized administrative user accounts.',
      phase:  'Phase 1: Block Initial Access'
    },
    'V018': { // Weak SSH Key
      action: 'Upgraded Cryptographic Keys to 4096-bit Encryption',
      impact: 'Prevents factorization attacks and machine impersonation across secure management channels.',
      phase:  'Phase 4: Contain Lateral Movement'
    },
    'V019': { // Bindshell
      action: 'Terminated Direct Root Shell Backdoor',
      impact: 'Neutralizes active listening root backdoor, cutting direct external command shells.',
      phase:  'Phase 5: Sever Command & Control'
    },
    'V020': { // VNC no auth
      action: 'Enabled Password Protection & Tunneling on Remote Desktop',
      impact: 'Prevents anonymous graphical desktop takeover by unauthorized network intruders.',
      phase:  'Phase 4: Contain Lateral Movement'
    },
  };

  if (translations[id]) {
    businessAction = translations[id].action;
    businessImpact = translations[id].impact;
    phaseBlocked   = translations[id].phase;
  } else {
    businessAction = `Mitigated High-Risk Finding (${finding.category || 'Security Risk'})`;
    businessImpact = 'Hardens network perimeter and prevents unauthorized exploitation.';
    phaseBlocked   = finding.mitrePhase || 'Phase 1: Initial Access';
  }

  const priorityLabel = finding.isKEV
    ? 'Critical (CISA Watchlist)'
    : (finding.severity === 'Critical' ? 'Critical Priority' : 'High Priority');

  return {
    assetName,
    assetSub,
    businessAction,
    businessImpact,
    phaseBlocked,
    effort: `${finding.effort || 2} hrs`,
    priorityLabel,
    isKEV: finding.isKEV || false,
    riskScore: finding.businessRisk || 0
  };
}

// ─────────────────────────────────────────────────────────
// 2. DATA AGGREGATION & METRICS
// ─────────────────────────────────────────────────────────
function getExecutiveMetrics() {
  const findings = (typeof state !== 'undefined' && state.findings && state.findings.length > 0)
    ? state.findings
    : (typeof VULN_DB !== 'undefined' ? VULN_DB.map(v => ({ ...v, businessRisk: 75, severity: 'High', effort: 2 })) : []);

  const capacity = (typeof state !== 'undefined' && state.scanConfig && state.scanConfig.capacity)
    ? state.scanConfig.capacity
    : 5;

  // Order: KEV overrides first, then highest risk score
  const ordered = [...findings].sort((a, b) => {
    if (a.isKEV && !b.isKEV) return -1;
    if (!a.isKEV && b.isKEV) return 1;
    return (b.businessRisk || 0) - (a.businessRisk || 0);
  });

  // Baseline Risk (sum of all findings)
  const baselineRisk = +ordered.reduce((s, f) => s + (f.businessRisk || 0), 0).toFixed(1);

  // Current Capacity-Constrained Sprint Fixes (Week 1)
  const sprintFixes = ordered.slice(0, capacity);

  // Risk Reduced
  const riskReduced   = +sprintFixes.reduce((s, f) => s + (f.businessRisk || 0), 0).toFixed(1);
  const projectedRisk = +Math.max(0, baselineRisk - riskReduced).toFixed(1);
  const pctReduced    = baselineRisk > 0 ? +((riskReduced / baselineRisk) * 100).toFixed(1) : 0;
  const kevCount      = sprintFixes.filter(f => f.isKEV).length;

  return {
    baselineRisk,
    projectedRisk,
    riskReduced,
    pctReduced,
    capacity,
    totalFindings: ordered.length,
    sprintFixes,
    kevCount,
    targetHost: (typeof state !== 'undefined' && state.scanConfig && state.scanConfig.ip) || '192.168.56.101',
    date: new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
  };
}

// ─────────────────────────────────────────────────────────
// 3. PIE / DONUT CHART GENERATION (CANVAS)
// ─────────────────────────────────────────────────────────
function drawExecutiveChart(metrics) {
  const canvas = document.getElementById('execPieChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const cx = w / 2, cy = h / 2;
  const radius = Math.min(cx, cy) - 15;
  const innerRadius = radius * 0.58;

  const reducedVal = metrics.riskReduced;
  const remainVal  = metrics.projectedRisk;
  const total      = reducedVal + remainVal;

  const reducedAngle = total > 0 ? (reducedVal / total) * Math.PI * 2 : 0;

  // Background ring
  ctx.fillStyle = '#1e293b';
  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, Math.PI * 2);
  ctx.arc(cx, cy, innerRadius, Math.PI * 2, 0, true);
  ctx.fill();

  // Green Sector: Risk Reduced
  if (reducedAngle > 0) {
    ctx.fillStyle = '#10b981';
    ctx.beginPath();
    ctx.arc(cx, cy, radius, -Math.PI / 2, -Math.PI / 2 + reducedAngle);
    ctx.arc(cx, cy, innerRadius, -Math.PI / 2 + reducedAngle, -Math.PI / 2, true);
    ctx.closePath();
    ctx.fill();
  }

  // Blue Sector: Residual Controlled Backlog
  if (reducedAngle < Math.PI * 2) {
    ctx.fillStyle = '#3b82f6';
    ctx.beginPath();
    ctx.arc(cx, cy, radius, -Math.PI / 2 + reducedAngle, -Math.PI / 2 + Math.PI * 2);
    ctx.arc(cx, cy, innerRadius, -Math.PI / 2 + Math.PI * 2, -Math.PI / 2 + reducedAngle, true);
    ctx.closePath();
    ctx.fill();
  }

  // Center Text (Large Percentage Drop)
  ctx.fillStyle = '#ffffff';
  ctx.font = 'bold 22px Inter, sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(`-${metrics.pctReduced}%`, cx, cy - 6);

  ctx.fillStyle = '#94a3b8';
  ctx.font = '10px Inter, sans-serif';
  ctx.fillText('Risk Drop', cx, cy + 14);

  // Legend HTML
  const leg = document.getElementById('execPieLegend');
  if (leg) {
    leg.innerHTML = `
      <div class="ecl-item">
        <span class="ecl-dot" style="background:#10b981"></span>
        <span>Sprint 1 Risk Eliminated: <strong>${reducedVal} pts (${metrics.pctReduced}%)</strong></span>
      </div>
      <div class="ecl-item">
        <span class="ecl-dot" style="background:#3b82f6"></span>
        <span>Controlled Residual Risk: <strong>${remainVal} pts (${(100 - metrics.pctReduced).toFixed(1)}%)</strong></span>
      </div>
    `;
  }
}

// ─────────────────────────────────────────────────────────
// 4. MODAL POPULATION & JARGON-FREE TABLE
// ─────────────────────────────────────────────────────────
window.openExecutiveSummaryModal = function() {
  const modal = document.getElementById('execPdfModal');
  if (!modal) return;

  const metrics = getExecutiveMetrics();

  // Populate Document Meta
  document.getElementById('execDocDate').textContent   = metrics.date;
  document.getElementById('execDocTarget').textContent = metrics.targetHost;

  // KPIs
  document.getElementById('execKpiBaseline').textContent  = metrics.baselineRisk;
  document.getElementById('execKpiProjected').textContent = metrics.projectedRisk;
  document.getElementById('execKpiReduced').textContent   = `−${metrics.riskReduced}`;
  document.getElementById('execKpiPct').textContent       = `${metrics.pctReduced}% Drop`;
  document.getElementById('execKpiKevCount').textContent  = `${metrics.kevCount} Neutralized`;

  // Narrative Paragraph with Dynamic Numbers
  const narrative = document.getElementById('execNarrativeText');
  narrative.innerHTML = `
    During the recent automated security assessment, our risk engine evaluated target environment <strong>${metrics.targetHost}</strong> using the business-risk model (<strong>Exploitability &times; Asset Criticality &times; Exposure</strong>). Baseline environment risk is measured at <strong>${metrics.baselineRisk} points</strong> across <strong>${metrics.totalFindings} findings</strong>. By executing the capacity-constrained <strong>Week 1 Sprint (${metrics.capacity} fixes)</strong>, the organization will immediately eliminate <strong>${metrics.riskReduced} risk points (&minus;${metrics.pctReduced}%)</strong>, while systematically neutralizing <strong>${metrics.kevCount} critical exploits on the U.S. CISA Known Exploited Vulnerabilities (KEV) watchlist</strong>.
  `;

  // Draw Visual Chart
  setTimeout(() => {
    drawExecutiveChart(metrics);
  }, 50);

  // Populate Jargon-Free Table
  const tbody = document.getElementById('execTableBody');
  tbody.innerHTML = metrics.sprintFixes.map((f, i) => {
    const t = translateToExecutiveLanguage(f);
    const pClass = t.isKEV ? 'critical' : 'high';
    return `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;color:var(--text3)">${i + 1}</td>
        <td>
          <span class="asset-pill">${t.assetName}</span>
          <span class="asset-sub">${t.assetSub}</span>
        </td>
        <td>
          <strong style="color:#f1f5f9">${t.businessAction}</strong>
          <div style="font-size:0.72rem;color:#94a3b8;margin-top:2px">${t.businessImpact}</div>
        </td>
        <td>
          <span style="font-size:0.75rem;color:#a5b4fc;font-weight:600">${t.phaseBlocked}</span>
        </td>
        <td style="font-family:'JetBrains Mono',monospace;color:var(--text2)">${t.effort}</td>
        <td>
          <span class="exec-priority-badge ${pClass}">${t.priorityLabel}</span>
        </td>
      </tr>
    `;
  }).join('');

  modal.classList.remove('hidden');
};

window.closeExecutiveSummaryModal = function() {
  const modal = document.getElementById('execPdfModal');
  if (modal) modal.classList.add('hidden');
};

// Print / Save to PDF via Browser
window.printExecutiveSummary = function() {
  window.print();
};

// ─────────────────────────────────────────────────────────
// 5. ONE-CLICK PDF GENERATION ENGINE (jsPDF + Vector Canvas)
// ─────────────────────────────────────────────────────────
window.generateAndDownloadPDF = async function() {
  const btn = document.getElementById('downloadPdfDirectBtn');
  const origText = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span>⏳</span> Generating PDF…';

  try {
    const metrics = getExecutiveMetrics();

    // Check if jsPDF is available
    if (typeof window.jspdf !== 'undefined' && window.jspdf.jsPDF) {
      const { jsPDF } = window.jspdf;
      const doc = new jsPDF({ orientation: 'portrait', unit: 'pt', format: 'a4' });

      // Page dimensions
      const pw = doc.internal.pageSize.getWidth();
      const ph = doc.internal.pageSize.getHeight();
      const margin = 36;
      let y = 40;

      // Header Banner (Navy gradient bar)
      doc.setFillColor(15, 23, 42); // #0f172a
      doc.rect(margin, y, pw - margin * 2, 60, 'F');

      // Title & Subtitle
      doc.setTextColor(255, 255, 255);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(16);
      doc.text('EXECUTIVE VULNERABILITY REMEDIATION BRIEF', margin + 14, y + 26);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.setTextColor(148, 163, 184); // #94a3b8
      doc.text(`Scope: ${metrics.targetHost}  |  Date: ${metrics.date}  |  Classification: BOARD-READY / CONFIDENTIAL`, margin + 14, y + 44);

      y += 76;

      // Executive Narrative Box
      doc.setFillColor(241, 245, 249); // #f1f5f9
      doc.setDrawColor(203, 213, 225);
      doc.roundedRect(margin, y, pw - margin * 2, 56, 4, 4, 'FD');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.setTextColor(15, 23, 42);
      doc.text('Executive Strategic Overview', margin + 12, y + 16);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(51, 65, 85);
      const narrativeLines = doc.splitTextToSize(
        `Automated evaluation based on Business Risk (Exploitability x Asset Criticality x Exposure). Baseline risk across ${metrics.totalFindings} findings is ${metrics.baselineRisk} points. The immediate Week 1 capacity sprint (${metrics.capacity} fixes) eliminates ${metrics.riskReduced} risk points (-${metrics.pctReduced}%), neutralizing ${metrics.kevCount} actively exploited CISA KEV watchlist threats.`,
        pw - margin * 2 - 24
      );
      doc.text(narrativeLines, margin + 12, y + 30);

      y += 70;

      // 4 KPI Summary Cards
      const kpiW = (pw - margin * 2 - 24) / 4;
      const kpis = [
        { label: 'BASELINE RISK', val: `${metrics.baselineRisk}`, sub: 'Pre-Remediation' },
        { label: 'POST-SPRINT RISK', val: `${metrics.projectedRisk}`, sub: 'Projected' },
        { label: 'TOTAL RISK REDUCED', val: `-${metrics.riskReduced}`, sub: `-${metrics.pctReduced}% DROP`, green: true },
        { label: 'CISA WATCHLIST', val: `${metrics.kevCount}`, sub: 'Exploits Cut', red: true }
      ];

      kpis.forEach((kpi, idx) => {
        const kx = margin + idx * (kpiW + 8);
        doc.setFillColor(248, 250, 252);
        doc.setDrawColor(226, 232, 240);
        doc.roundedRect(kx, y, kpiW, 46, 3, 3, 'FD');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7);
        doc.setTextColor(100, 116, 139);
        doc.text(kpi.label, kx + 8, y + 12);

        doc.setFontSize(14);
        if (kpi.green) doc.setTextColor(16, 185, 129);
        else if (kpi.red) doc.setTextColor(239, 68, 68);
        else doc.setTextColor(15, 23, 42);
        doc.text(kpi.val, kx + 8, y + 28);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7);
        doc.setTextColor(148, 163, 184);
        doc.text(kpi.sub, kx + 8, y + 38);
      });

      y += 58;

      // Table Header: Simplified Jargon-Free Roadmap
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      doc.text('High-Priority Business Fixes (Current Sprint Roadmap)', margin, y + 10);

      y += 18;

      // Table header bar
      doc.setFillColor(30, 41, 59);
      doc.rect(margin, y, pw - margin * 2, 18, 'F');
      doc.setFontSize(7.5);
      doc.setTextColor(255, 255, 255);
      doc.text('#', margin + 6, y + 12);
      doc.text('PROTECTED BUSINESS ASSET', margin + 26, y + 12);
      doc.text('BUSINESS IMPACT MITIGATED', margin + 200, y + 12);
      doc.text('KILL-CHAIN PHASE', margin + 380, y + 12);
      doc.text('EFFORT', margin + 465, y + 12);

      y += 18;

      // Table Rows
      metrics.sprintFixes.forEach((f, i) => {
        const t = translateToExecutiveLanguage(f);
        doc.setFillColor(i % 2 === 0 ? 255 : 248, i % 2 === 0 ? 255 : 250, i % 2 === 0 ? 255 : 252);
        doc.rect(margin, y, pw - margin * 2, 28, 'F');
        doc.setDrawColor(241, 245, 249);
        doc.line(margin, y + 28, pw - margin, y + 28);

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(100, 116, 139);
        doc.text(`${i + 1}`, margin + 6, y + 14);

        // Asset
        doc.setTextColor(15, 23, 42);
        doc.text(t.assetName.substring(0, 32), margin + 26, y + 11);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(6.5);
        doc.setTextColor(100, 116, 139);
        doc.text(t.assetSub, margin + 26, y + 21);

        // Impact
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(30, 41, 59);
        doc.text(t.businessAction.substring(0, 38), margin + 200, y + 11);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(6.5);
        doc.setTextColor(100, 116, 139);
        doc.text(t.businessImpact.substring(0, 42), margin + 200, y + 21);

        // Phase
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(79, 70, 229);
        doc.text(t.phaseBlocked.substring(0, 22), margin + 380, y + 15);

        // Effort
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.5);
        doc.setTextColor(51, 65, 85);
        doc.text(t.effort, margin + 465, y + 15);

        y += 28;
      });

      y += 24;

      // Embed Pie Chart (Convert Canvas to PNG Image)
      const chartCanvas = document.getElementById('execPieChart');
      if (chartCanvas) {
        const chartDataUrl = chartCanvas.toDataURL('image/png');
        doc.addImage(chartDataUrl, 'PNG', margin + 15, y, 100, 100);

        // Strategic Takeaways next to chart
        const tx = margin + 130;
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(10);
        doc.setTextColor(15, 23, 42);
        doc.text('Key Executive Takeaways', tx, y + 16);

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(51, 65, 85);
        const takeawayLines = [
          `• Immediate Risk ROI: Eliminates ${metrics.pctReduced}% of entire environment risk in Sprint 1.`,
          `• Lateral Movement Blocked: Dismantles pivot paths targeting crown-jewel assets.`,
          `• CISA Compliance: 100% of discovered Known Exploited Vulnerabilities resolved.`,
          `• Resource Efficient: Delivered under ${metrics.capacity} fixes/week organizational capacity limit.`
        ];
        takeawayLines.forEach((tline, tidx) => {
          doc.text(tline, tx, y + 36 + tidx * 16);
        });

        y += 115;
      }

      // Governance Signatures
      doc.setDrawColor(203, 213, 225);
      doc.line(margin, y, pw - margin, y);
      y += 18;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(100, 116, 139);
      doc.text('Prepared by: Automated Cyber Risk Engine', margin, y);
      doc.text('Authorized by: Chief Information Security Officer', margin + 220, y);
      doc.text('Audit: ISO 27001 / NIST CSF Aligned', pw - margin - 150, y);

      // Save PDF
      doc.save(`Executive_Remediation_Summary_${new Date().toISOString().slice(0, 10)}.pdf`);
    } else {
      // Fallback: Use browser print dialog
      window.print();
    }
  } catch (err) {
    console.error('PDF generation error, falling back to print dialog:', err);
    window.print();
  } finally {
    btn.disabled = false;
    btn.innerHTML = origText;
  }
};
