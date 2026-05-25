#!/usr/bin/env node
// generate-pages.js
// Run: node generate-pages.js
// Generates one HTML file per risk in the risk/ directory
// and one HTML file per layer in the layer/ directory

const fs = require('fs');
const path = require('path');

// Load data
const dataFile = fs.readFileSync(path.join(__dirname, 'js/data.js'), 'utf8');
// Extract the object (skip "const AI_RISK_DATA = " and trailing ";")
const jsonStr = dataFile.replace('const AI_RISK_DATA = ', '').replace(/;\s*$/, '');
const data = eval('(' + jsonStr + ')');

const FW_COLORS = {
  nist:    { bg: 'rgba(37,99,235,0.15)',  color: '#93C5FD', border: 'rgba(37,99,235,0.3)'  },
  owasp:   { bg: 'rgba(225,29,72,0.15)',  color: '#FCA5A5', border: 'rgba(225,29,72,0.3)'  },
  mitre:   { bg: 'rgba(14,116,144,0.15)', color: '#67E8F9', border: 'rgba(14,116,144,0.3)' },
  enisa:   { bg: 'rgba(3,105,161,0.15)',  color: '#7DD3FC', border: 'rgba(3,105,161,0.3)'  },
  euai:    { bg: 'rgba(29,78,216,0.15)',  color: '#A5B4FC', border: 'rgba(29,78,216,0.3)'  },
  cisa:    { bg: 'rgba(185,28,28,0.15)',  color: '#FCA5A5', border: 'rgba(185,28,28,0.3)'  },
  saif:    { bg: 'rgba(21,128,61,0.15)',  color: '#86EFAC', border: 'rgba(21,128,61,0.3)'  },
  iso:     { bg: 'rgba(124,58,237,0.15)', color: '#C4B5FD', border: 'rgba(124,58,237,0.3)' },
  maestro: { bg: 'rgba(157,23,77,0.15)',  color: '#F9A8D4', border: 'rgba(157,23,77,0.3)'  }
};

const FW_LABELS = {
  nist: 'NIST', owasp: 'OWASP', mitre: 'MITRE ATLAS', enisa: 'ENISA',
  euai: 'EU AI Act', cisa: 'CISA', saif: 'Google SAIF', iso: 'ISO 42001', maestro: 'MAESTRO'
};

function fwBadge(fwId) {
  const c = FW_COLORS[fwId] || { bg: 'rgba(255,255,255,0.1)', color: '#ccc', border: 'rgba(255,255,255,0.2)' };
  return `<span class="fw-pill" style="background:${c.bg};color:${c.color};border:1px solid ${c.border}">${FW_LABELS[fwId] || fwId}</span>`;
}

function severityBadge(sev) {
  return `<span class="severity-badge sev-${sev}">${sev}</span>`;
}

function controlBadgeStyle(fwId) {
  const c = FW_COLORS[fwId] || { bg: 'rgba(255,255,255,0.1)', color: '#aaa', border: 'rgba(255,255,255,0.15)' };
  return `background:${c.bg};color:${c.color};border:1px solid ${c.border}`;
}

function truncate(str, n) {
  return str.length > n ? str.slice(0, n) + '…' : str;
}

const navHTML = `<nav>
  <div class="nav-brand"><span>//</span> AI Risk Explorer</div>
  <div class="nav-links">
    <a href="../index.html">Explorer</a>
    <a href="../search.html">Search</a>
    <a href="../frameworks.html">Frameworks</a>
    <a href="../crosswalk.html">Crosswalk</a>
  </div>
  <div class="nav-right">
    <span class="badge-nav">v1.0 · 2025</span>
  </div>
</nav>`;

const footerHTML = `<footer>
  <span>AI Risk Explorer · <a href="https://arnav.au" target="_blank">arnav.au</a></span>
  <span>References: NIST AI RMF 2023, OWASP LLM Top 10 2025, MITRE ATLAS v5.1, ENISA 2024, EU AI Act 2024</span>
</footer>`;

// Generate risk pages
let riskCount = 0;
for (const layer of data.layers) {
  const related_all = layer.risks;
  for (const risk of layer.risks) {
    const related = related_all.filter(r => r.id !== risk.id).slice(0, 5);
    const fwPills = risk.frameworks.map(fwBadge).join('');

    const controlsHTML = risk.controls.map(ctrl => {
      const fw = data.frameworks.find(f => f.id === ctrl.framework);
      return `<div class="control-card">
        <div class="control-header">
          <span class="control-badge" style="${controlBadgeStyle(ctrl.framework)}">${fw ? fw.short : ctrl.framework}</span>
          <div>
            <div class="control-title">${ctrl.title}</div>
            <div class="control-ref">${ctrl.ref}</div>
          </div>
        </div>
        <div class="control-detail">${ctrl.detail}</div>
      </div>`;
    }).join('\n');

    const fwSidebarHTML = risk.frameworks.map(f => {
      const fw = data.frameworks.find(x => x.id === f);
      const c = FW_COLORS[f];
      return `<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border)">
        <div>
          <div style="font-size:13px;color:var(--text)">${fw ? fw.name : f}</div>
          <div style="font-size:11px;color:var(--text3);font-family:var(--font-mono)">${fw ? fw.version : ''}</div>
        </div>
        <a href="${fw ? fw.url : '#'}" target="_blank" style="font-family:var(--font-mono);font-size:10px;color:${c ? c.color : '#aaa'}">↗</a>
      </div>`;
    }).join('');

    const relatedHTML = related.length > 0 ? `<div class="sidebar-card">
      <h3>Related risks in ${layer.name}</h3>
      ${related.map(r => `<a class="related-risk" href="${r.id}.html">
        <div class="related-dot" style="background:${layer.color}"></div>
        <div>
          <div class="related-title">${r.title}</div>
          <div style="margin-top:2px">${severityBadge(r.severity)}</div>
        </div>
      </a>`).join('')}
    </div>` : '';

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${risk.title} — AI Risk Explorer</title>
<meta name="description" content="${risk.description.substring(0, 160)}">
<link rel="stylesheet" href="../css/style.css">
</head>
<body>
${navHTML}
<div class="container">
  <div class="risk-detail">
    <div class="breadcrumb animate-in">
      <a href="../index.html">Explorer</a>
      <span class="breadcrumb-sep">›</span>
      <a href="../layer/${layer.id}.html">${layer.name}</a>
      <span class="breadcrumb-sep">›</span>
      <span>${risk.title}</span>
    </div>

    <div class="risk-title-block animate-in">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px">
        <span style="font-family:var(--font-mono);font-size:11px;padding:3px 10px;border-radius:4px;background:${layer.color}22;color:${layer.color};border:1px solid ${layer.color}44">${layer.name}</span>
        ${severityBadge(risk.severity)}
      </div>
      <h1>${risk.title}</h1>
      <div class="risk-meta" style="margin-top:12px">
        <div class="fw-pills">${fwPills}</div>
        <span style="font-family:var(--font-mono);font-size:11px;color:var(--text3)">${risk.controls.length} control${risk.controls.length!==1?'s':''} mapped</span>
      </div>
    </div>

    <div class="detail-grid animate-in">
      <div class="detail-main">
        <div class="detail-section">
          <h2>Description</h2>
          <p class="detail-body">${risk.description}</p>
        </div>

        <div class="detail-section">
          <h2>Attack scenario</h2>
          <div class="scenario-box">${risk.scenario}</div>
        </div>

        <div class="detail-section">
          <h2>Real-world examples</h2>
          <div class="example-box">${risk.example}</div>
        </div>

        <div class="detail-section">
          <h2>${risk.controls.length} mapped controls</h2>
          ${controlsHTML}
        </div>
      </div>

      <div class="detail-sidebar">
        <div class="sidebar-card">
          <h3>Risk details</h3>
          <div class="sidebar-stat">
            <span class="sidebar-stat-label">Severity</span>
            ${severityBadge(risk.severity)}
          </div>
          <div class="sidebar-stat">
            <span class="sidebar-stat-label">Layer</span>
            <span class="sidebar-stat-value" style="color:${layer.color}">${layer.name}</span>
          </div>
          <div class="sidebar-stat">
            <span class="sidebar-stat-label">Frameworks</span>
            <span class="sidebar-stat-value">${risk.frameworks.length}</span>
          </div>
          <div class="sidebar-stat">
            <span class="sidebar-stat-label">Controls mapped</span>
            <span class="sidebar-stat-value">${risk.controls.length}</span>
          </div>
        </div>

        <div class="sidebar-card">
          <h3>Frameworks</h3>
          ${fwSidebarHTML}
        </div>

        ${relatedHTML}

        <div style="margin-top:12px">
          <a href="../layer/${layer.id}.html" style="display:block;text-align:center;font-size:13px;padding:10px;border:1px solid var(--border);border-radius:var(--r);color:var(--text2);text-decoration:none;">← All ${layer.name} risks</a>
        </div>
      </div>
    </div>
  </div>
</div>
${footerHTML}
</body>
</html>`;

    fs.writeFileSync(path.join(__dirname, 'risk', `${risk.id}.html`), html);
    riskCount++;
    console.log(`  ✓ risk/${risk.id}.html`);
  }
}

// Generate layer pages
let layerCount = 0;
for (const layer of data.layers) {
  const critCount = layer.risks.filter(r => r.severity === 'critical').length;
  const highCount = layer.risks.filter(r => r.severity === 'high').length;
  const medCount = layer.risks.filter(r => r.severity === 'medium').length;

  const icons = {
    data: '◈', model: '◎', inference: '◉', application: '⬡', governance: '⊙'
  };

  const risksHTML = layer.risks.map(risk => {
    return `<a href="../risk/${risk.id}.html" class="full-risk-card">
      <div>
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
          ${severityBadge(risk.severity)}
        </div>
        <h3>${risk.title}</h3>
        <p>${truncate(risk.description, 160)}</p>
        <div class="fw-pills" style="margin-top:10px">${risk.frameworks.map(fwBadge).join('')}</div>
      </div>
      <div class="full-risk-card-right">
        <span style="font-family:var(--font-mono);font-size:11px;color:var(--text3)">${risk.controls.length} controls</span>
        <span style="color:var(--text3);font-size:18px">›</span>
      </div>
    </a>`;
  }).join('\n');

  // other layers nav
  const otherLayers = data.layers.filter(l => l.id !== layer.id);
  const otherLayersHTML = otherLayers.map(l => `
    <a href="${l.id}.html" style="display:flex;align-items:center;gap:8px;padding:10px;border-radius:var(--r);text-decoration:none;transition:background 0.15s;" onmouseover="this.style.background='var(--surface)'" onmouseout="this.style.background='none'">
      <div style="width:8px;height:8px;border-radius:50%;background:${l.color};flex-shrink:0"></div>
      <span style="font-size:13px;color:var(--text2)">${l.name}</span>
      <span style="font-family:var(--font-mono);font-size:10px;color:var(--text3);margin-left:auto">${l.risks.length}</span>
    </a>
  `).join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${layer.name} Risks — AI Risk Explorer</title>
<meta name="description" content="${layer.description.substring(0, 160)}">
<link rel="stylesheet" href="../css/style.css">
</head>
<body>
${navHTML}
<div class="container">
  <div class="breadcrumb animate-in" style="padding-top:2rem">
    <a href="../index.html">Explorer</a>
    <span class="breadcrumb-sep">›</span>
    <span>${layer.name}</span>
  </div>

  <div class="layer-page-header animate-in">
    <div class="layer-icon-large" style="background:${layer.color}22;color:${layer.color}">${icons[layer.id] || '◆'}</div>
    <div>
      <h1>${layer.name}</h1>
      <p>${layer.description}</p>
      <div style="display:flex;gap:12px;margin-top:1rem;flex-wrap:wrap">
        <span style="font-family:var(--font-mono);font-size:12px;color:var(--text3)">${layer.risks.length} risks mapped</span>
        ${critCount > 0 ? `<span class="severity-badge sev-critical">${critCount} critical</span>` : ''}
        ${highCount > 0 ? `<span class="severity-badge sev-high">${highCount} high</span>` : ''}
        ${medCount > 0 ? `<span class="severity-badge sev-medium">${medCount} medium</span>` : ''}
      </div>
    </div>
  </div>

  <div style="display:grid;grid-template-columns:1fr 260px;gap:2rem;align-items:start">
    <div>
      <div style="font-family:var(--font-mono);font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:1rem">All risks in this layer</div>
      <div class="full-risk-list animate-in">
        ${risksHTML}
      </div>
    </div>
    <div>
      <div class="sidebar-card" style="position:sticky;top:72px">
        <h3>Other layers</h3>
        ${otherLayersHTML}
        <div style="border-top:1px solid var(--border);margin-top:8px;padding-top:8px">
          <a href="../index.html" style="font-size:13px;color:var(--text3);text-decoration:none;display:flex;align-items:center;gap:6px;padding:6px 0">
            ← Back to full explorer
          </a>
        </div>
      </div>
    </div>
  </div>

  <div style="height:4rem"></div>
</div>
${footerHTML}
</body>
</html>`;

  fs.writeFileSync(path.join(__dirname, 'layer', `${layer.id}.html`), html);
  layerCount++;
  console.log(`  ✓ layer/${layer.id}.html`);
}

console.log(`\n✅ Generated ${riskCount} risk pages and ${layerCount} layer pages.`);
