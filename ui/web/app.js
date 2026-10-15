// VeriDex AI - Frontend Reactive Controller

let currentFeatures = null;

// Tab Switching
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
  
  event.currentTarget.classList.add('active');
  document.getElementById(`tab-${tabId}`).classList.add('active');

  if (tabId === 'threat-vault') {
    loadVaultLogs();
  }
}

// Preset Loaders
function loadSample(url) {
  document.getElementById('urlInput').value = url;
  scanUrl();
}

function loadNlpPreset(type) {
  const nlpInput = document.getElementById('nlpInput');
  if (type === 'urgency') {
    nlpInput.value = "URGENT SECURITY NOTICE: Your PayPal account has been temporarily suspended due to unauthorized access. You must act immediately within 24 hours to confirm your password, SSN, and verify your identity before your account is permanently deleted!";
  } else if (type === 'greed') {
    nlpInput.value = "CONGRATULATIONS! You are selected as the lucky winner of our exclusive crypto lottery. Claim your 5,000 USDT airdrop immediately! Provide your private wallet seed phrase to receive instant cash payout.";
  } else if (type === 'techsupport') {
    nlpInput.value = "CRITICAL WINDOWS DEFENDER ALERT: Virus detected! Trojan horse payload found on your system. Call toll-free Microsoft Support immediately at 1-800-555-0199 and download AnyDesk to allow our technician remote access.";
  } else if (type === 'safe') {
    nlpInput.value = "Hi team, please find attached the meeting minutes and presentation slides from today's architecture review. Let me know if you have any questions before Monday's sync.";
  }
  scanNlp();
}

// URL Scanner
async function scanUrl() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) {
    alert("Please enter a valid target URL.");
    return;
  }

  const btn = document.getElementById('btnScanUrl');
  btn.innerText = "Scanning...";
  btn.disabled = true;

  try {
    const res = await fetch('/api/scan/url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, source: 'WEB_DASHBOARD' })
    });
    const data = await res.json();
    renderUrlResult(data);
    loadStats();
  } catch (err) {
    console.error("Scan error:", err);
    alert("Failed to communicate with on-device engine: " + err.message);
  } finally {
    btn.innerText = "Scan On-Device";
    btn.disabled = false;
  }
}

function renderUrlResult(data) {
  const container = document.getElementById('urlResultContainer');
  container.classList.remove('hidden');

  // Verdict Header
  const banner = document.getElementById('verdictBanner');
  const icon = document.getElementById('verdictIcon');
  const title = document.getElementById('verdictTitle');
  const sub = document.getElementById('verdictSub');
  const badgeLatency = document.getElementById('badgeLatency');
  const badgeEngine = document.getElementById('badgeEngine');

  badgeLatency.innerText = `${data.latency_ms} ms`;
  badgeEngine.innerText = data.engine || "ONNX Runtime";

  title.innerText = data.verdict;
  title.style.color = data.threat_color;

  if (data.is_threat) {
    icon.innerText = "🚨";
    sub.innerText = "Threat identified by on-device intelligence. Contextual mitigation triggered.";
  } else {
    icon.innerText = "🛡️";
    sub.innerText = "URL passed all structural, homoglyph, and on-device ML inspections.";
  }

  // Score Circle
  const circle = document.getElementById('scoreCircle');
  const scoreText = document.getElementById('scoreText');
  const confidenceVal = document.getElementById('confidenceVal');

  circle.style.borderColor = data.threat_color;
  scoreText.innerText = `${data.risk_score}%`;
  scoreText.style.color = data.threat_color;
  confidenceVal.innerText = `${data.confidence}%`;

  // Explainable AI (XAI)
  const xaiList = document.getElementById('xaiList');
  xaiList.innerHTML = '';
  
  if (data.risk_factors && data.risk_factors.length > 0) {
    data.risk_factors.forEach(factor => {
      const li = document.createElement('li');
      li.className = `xai-item ${data.is_threat ? 'danger' : 'safe'}`;
      li.innerHTML = `<span>${data.is_threat ? '⚠️' : '✅'}</span> <div>${factor}</div>`;
      xaiList.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.className = 'xai-item safe';
    li.innerHTML = '<span>✅</span> <div>No anomalies or threat cues detected.</div>';
    xaiList.appendChild(li);
  }

  // Feature Matrix
  currentFeatures = data.features;
  renderFeatureTable(data.features);
}

function toggleFeatures() {
  const table = document.getElementById('featuresTableContainer');
  const icon = document.getElementById('featuresToggleIcon');
  if (table.classList.contains('hidden')) {
    table.classList.remove('hidden');
    icon.innerText = "▲";
  } else {
    table.classList.add('hidden');
    icon.innerText = "▼";
  }
}

function renderFeatureTable(features) {
  const tbody = document.getElementById('featuresTableBody');
  tbody.innerHTML = '';

  if (!features) return;

  const featureDescriptions = {
    "url_length": "Overall URL character count",
    "domain_length": "Length of hostname",
    "path_length": "Depth of URL path directory",
    "query_length": "Query string parameter payload length",
    "subdomain_count": "Number of nested subdomains",
    "entropy_domain": "Shannon entropy (detects DGA / algorithmic randomness)",
    "entropy_path": "Path randomness indicator",
    "count_digits_domain": "Numeric characters in domain",
    "ratio_digits_domain": "Ratio of digits to domain length",
    "count_hyphens_domain": "Hyphens in domain (common in spoofing)",
    "count_dots_url": "Dot count in entire URL",
    "count_special_chars": "Special obfuscation characters (@, ?, =, %, etc.)",
    "has_at_symbol": "Credential delimiter obfuscation symbol (@)",
    "has_double_slash": "Internal redirect indicator (// in path)",
    "has_ip_address": "Raw IP host bypassing registered DNS",
    "is_https": "TLS/SSL transport encryption flag",
    "is_suspicious_tld": "High-risk spam top-level domain flag",
    "suspicious_keyword_count": "Count of phishing cues (login, verify, secure, etc.)",
    "typosquat_score": "Confidence score from brand homoglyph analyzer",
    "is_punycode": "IDN homograph attack indicator (xn--)"
  };

  for (const [key, val] of Object.entries(features)) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${key}</strong></td>
      <td>${val}</td>
      <td style="color: #94a3b8;">${featureDescriptions[key] || "Structural feature"}</td>
    `;
    tbody.appendChild(tr);
  }
}

// NLP Scanner
async function scanNlp() {
  const text = document.getElementById('nlpInput').value.trim();
  if (!text) {
    alert("Please paste text content to analyze.");
    return;
  }

  const btn = document.getElementById('btnScanNlp');
  btn.innerText = "Analyzing...";
  btn.disabled = true;

  try {
    const res = await fetch('/api/scan/text', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text })
    });
    const data = await res.json();
    renderNlpResult(data);
  } catch (err) {
    console.error("NLP error:", err);
    alert("NLP Analysis failed: " + err.message);
  } finally {
    btn.innerText = "Analyze Manipulation";
    btn.disabled = false;
  }
}

function renderNlpResult(data) {
  const container = document.getElementById('nlpResultContainer');
  container.classList.remove('hidden');

  const badge = document.getElementById('nlpThreatBadge');
  const summary = document.getElementById('nlpSummaryText');
  const latency = document.getElementById('nlpLatency');
  const cuesGrid = document.getElementById('cuesGrid');

  badge.innerText = `${data.threat_level} (${data.risk_score}%)`;
  if (data.threat_level === 'CRITICAL') {
    badge.style.background = 'rgba(239, 68, 68, 0.2)';
    badge.style.color = '#ef4444';
    badge.style.borderColor = '#ef4444';
  } else if (data.threat_level === 'SUSPICIOUS') {
    badge.style.background = 'rgba(245, 158, 11, 0.2)';
    badge.style.color = '#f59e0b';
    badge.style.borderColor = '#f59e0b';
  } else {
    badge.style.background = 'rgba(34, 197, 94, 0.2)';
    badge.style.color = '#22c55e';
    badge.style.borderColor = '#22c55e';
  }

  summary.innerText = data.summary;
  latency.innerText = `${data.latency_ms} ms`;

  cuesGrid.innerHTML = '';
  if (data.detected_cues && data.detected_cues.length > 0) {
    data.detected_cues.forEach(cue => {
      const card = document.createElement('div');
      card.className = 'cue-card';
      const tokenPills = cue.matched_tokens.map(t => `<span class="token-pill">${t}</span>`).join(' ');
      card.innerHTML = `
        <h5>${cue.category.replace(/_/g, ' ')} <span>+${cue.category_risk}%</span></h5>
        <p>${cue.description}</p>
        <div class="cue-tokens">${tokenPills}</div>
      `;
      cuesGrid.appendChild(card);
    });
  } else {
    cuesGrid.innerHTML = `
      <div class="cue-card" style="grid-column: 1 / -1;">
        <h5 style="color: #22c55e;">No Manipulation Cues Detected</h5>
        <p>Text appears neutral and does not use artificial urgency, fear intimidation, or credential harvesting phrases.</p>
      </div>
    `;
  }
}

// Vault Logs
async function loadVaultLogs() {
  const tbody = document.getElementById('vaultTableBody');
  try {
    const res = await fetch('/api/vault/logs?limit=50');
    const logs = await res.json();
    
    if (!logs || logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #94a3b8; padding: 25px;">Vault is clean. No threats recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = '';
    logs.forEach(log => {
      const tr = document.createElement('tr');
      const isThreat = log.is_threat;
      const tagColor = isThreat ? '#ef4444' : '#22c55e';
      tr.innerHTML = `
        <td style="font-family: var(--font-mono); color: #94a3b8;">${log.timestamp}</td>
        <td class="url-cell" title="${log.url}">${log.url}</td>
        <td style="color: ${tagColor}; font-weight: 700;">${log.verdict}</td>
        <td style="font-family: var(--font-mono); font-weight: 600;">${log.risk_score}%</td>
        <td style="font-family: var(--font-mono); color: #38bdf8;">${log.latency_ms} ms</td>
        <td><span class="sample-tag">${log.source}</span></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Vault fetch error:", err);
  }
}

async function clearVault() {
  if (confirm("Are you sure you want to clear the encrypted local threat vault?")) {
    await fetch('/api/vault/clear', { method: 'POST' });
    loadVaultLogs();
    loadStats();
  }
}

function exportVaultReport() {
  window.open('/api/vault/logs?limit=500', '_blank');
}

// Stats Poller
async function loadStats() {
  try {
    const res = await fetch('/api/vault/stats');
    const data = await res.json();
    document.getElementById('metricTotalScans').innerText = data.total_scans;
    document.getElementById('metricThreatsBlocked').innerText = data.threats_blocked;
    document.getElementById('metricTyposquats').innerText = data.typosquats_detected;
    document.getElementById('metricAvgLatency').innerText = `${data.avg_latency_ms} ms`;
  } catch (err) {
    console.error("Stats load error:", err);
  }
}

// Latency Benchmark
async function runBenchmark() {
  const btn = document.getElementById('btnBench');
  btn.innerText = "Running Stress Test...";
  btn.disabled = true;

  try {
    const res = await fetch('/api/benchmark');
    const data = await res.json();
    
    document.getElementById('benchResults').classList.remove('hidden');
    document.getElementById('benchAvg').innerText = `${data.avg_latency_ms} ms`;
    document.getElementById('benchMin').innerText = `${data.min_latency_ms} ms`;
    document.getElementById('benchP95').innerText = `${data.p95_latency_ms} ms`;
    document.getElementById('benchEngine').innerText = data.engine;
  } catch (err) {
    alert("Benchmark failed: " + err.message);
  } finally {
    btn.innerText = "Run Latency Stress Test";
    btn.disabled = false;
  }
}

// Clipboard Interceptor Switch
document.getElementById('clipboardToggle').addEventListener('change', async (e) => {
  const active = e.target.checked;
  try {
    await fetch(`/api/interceptor/toggle?enable=${active}`, { method: 'POST' });
  } catch (err) {
    console.error("Toggle error:", err);
  }
});

// Initialization
window.addEventListener('DOMContentLoaded', () => {
  loadStats();
});
