// Shared utilities for AI Risk Explorer

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

function getLayer(id) {
  return AI_RISK_DATA.layers.find(l => l.id === id);
}

function getRisk(riskId) {
  for (const layer of AI_RISK_DATA.layers) {
    const risk = layer.risks.find(r => r.id === riskId);
    if (risk) return { risk, layer };
  }
  return null;
}

function getAllRisks() {
  const all = [];
  for (const layer of AI_RISK_DATA.layers) {
    for (const risk of layer.risks) {
      all.push({ ...risk, layerId: layer.id, layerName: layer.name, layerColor: layer.color });
    }
  }
  return all;
}

function controlBadgeStyle(fwId) {
  const c = FW_COLORS[fwId] || { bg: 'rgba(255,255,255,0.1)', color: '#aaa', border: 'rgba(255,255,255,0.15)' };
  return `background:${c.bg};color:${c.color};border:1px solid ${c.border}`;
}

function renderNav(activePage) {
  const pages = [
    { href: '../index.html', label: 'Explorer', key: 'index' },
    { href: '../search.html', label: 'Search', key: 'search' },
    { href: '../frameworks.html', label: 'Frameworks', key: 'frameworks' },
    { href: '../crosswalk.html', label: 'Crosswalk', key: 'crosswalk' }
  ];
  const rootPages = [
    { href: 'index.html', label: 'Explorer', key: 'index' },
    { href: 'search.html', label: 'Search', key: 'search' },
    { href: 'frameworks.html', label: 'Frameworks', key: 'frameworks' },
    { href: 'crosswalk.html', label: 'Crosswalk', key: 'crosswalk' }
  ];
  return '';  // nav is hardcoded in each HTML for path correctness
}

function truncate(str, n) {
  return str.length > n ? str.slice(0, n) + '…' : str;
}
