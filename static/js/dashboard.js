// Dashboard Client-Side Logic - High-Performance Real-Time Dynamic Stream
let trafficChart = null;
const MAX_CHART_POINTS = 20;
let pollingInterval = null;

document.addEventListener('DOMContentLoaded', () => {
  initChart();
  fetchStatus();
  // Fast, responsive 1.2s dynamic polling loop
  pollingInterval = setInterval(fetchStatus, 1200);
});

// Initialize Chart.js Multi-Stream Real-Time Traffic Line Chart
function initChart() {
  const ctx = document.getElementById('trafficChart');
  if (!ctx) return;

  const labels = [];
  const ppsData = [];
  const synData = [];
  const initialTime = new Date();

  for (let i = MAX_CHART_POINTS - 1; i >= 0; i--) {
    const t = new Date(initialTime.getTime() - i * 1200);
    labels.push(t.toLocaleTimeString());
    ppsData.push(0);
    synData.push(0);
  }

  trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Total Packets / Sec',
          data: ppsData,
          borderColor: '#00f2fe',
          backgroundColor: 'rgba(0, 242, 254, 0.12)',
          borderWidth: 2.2,
          fill: true,
          tension: 0.38,
          pointRadius: 2.5,
          pointHoverRadius: 6,
          pointBackgroundColor: '#00f2fe'
        },
        {
          label: 'SYN Flag Packets / Sec',
          data: synData,
          borderColor: '#f59e0b',
          backgroundColor: 'rgba(245, 158, 11, 0.08)',
          borderWidth: 2,
          borderDash: [4, 4],
          fill: false,
          tension: 0.35,
          pointRadius: 2,
          pointHoverRadius: 5,
          pointBackgroundColor: '#f59e0b'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 300, easing: 'easeOutQuad' },
      interaction: { mode: 'index', intersect: false },
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.04)' },
          ticks: { color: '#9ca3af', font: { family: "'JetBrains Mono', monospace", size: 10 }, maxRotation: 0 }
        },
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#9ca3af', font: { family: "'JetBrains Mono', monospace", size: 10 } }
        }
      },
      plugins: {
        legend: {
          position: 'top',
          labels: { color: '#e5e7eb', font: { family: "'Inter', sans-serif", size: 11 }, boxWidth: 12 }
        }
      }
    }
  });
}

// Fetch Status from Backend
async function fetchStatus() {
  try {
    const response = await fetch('/api/status');
    if (!response.ok) return;
    const data = await response.json();
    updateUI(data);
  } catch (err) {
    console.error('Error fetching system status:', err);
  }
}

// Update UI Elements with Latest Telemetry
function updateUI(data) {
  // Update Network Interface Info
  if (data.interfaces && data.interfaces.length > 0) {
    const select = document.getElementById('interface-select');
    if (select && select.options.length <= 1) {
      select.innerHTML = '';
      data.interfaces.forEach(iface => {
        const opt = document.createElement('option');
        opt.value = iface.name;
        opt.innerText = iface.name;
        if (iface.is_selected) opt.selected = true;
        select.appendChild(opt);
      });
    }
  }

  if (data.local_ip) {
    const ipEl = document.getElementById('interface-ip');
    if (ipEl) ipEl.innerText = `IP: ${data.local_ip}`;
  }

  // Update Global Header Status Pill
  const statusDot = document.getElementById('header-status-dot');
  const statusText = document.getElementById('header-status-text');
  const modeBadge = document.getElementById('current-mode-badge');
  const modeLabel = document.getElementById('current-mode-label');
  const modeDot = document.getElementById('mode-indicator-dot');

  if (data.mode === 'SIMULATION') {
    modeBadge.className = 'mode-badge';
    modeDot.className = 'mode-indicator sim';
    modeLabel.innerText = `SIMULATION (${data.simulation_scenario || 'ACTIVE'})`;
  } else if (data.is_monitoring) {
    modeBadge.className = 'mode-badge';
    modeDot.className = 'mode-indicator live';
    modeLabel.innerText = 'LIVE CAPTURE';
  } else {
    modeBadge.className = 'mode-badge';
    modeDot.className = 'mode-indicator';
    modeLabel.innerText = 'STANDBY';
  }

  const isDDoS = (data.prediction && data.prediction.includes('DDoS')) || data.prediction === 1;

  if (!data.is_monitoring && data.mode !== 'SIMULATION') {
    statusDot.className = 'status-dot stopped';
    statusText.innerText = 'MONITORING STANDBY';
  } else if (isDDoS) {
    statusDot.className = 'status-dot ddos';
    statusText.innerText = 'POSSIBLE DDoS DETECTED';
  } else {
    statusDot.className = 'status-dot normal';
    statusText.innerText = 'NETWORK NORMAL';
  }

  // Update Monitoring Buttons Visibility
  const btnStart = document.getElementById('btn-start-monitor');
  const btnStop = document.getElementById('btn-stop-monitor');
  if (btnStart && btnStop) {
    if (data.is_monitoring && data.mode === 'LIVE') {
      btnStart.classList.add('btn-hidden');
      btnStop.classList.remove('btn-hidden');
    } else {
      btnStart.classList.remove('btn-hidden');
      btnStop.classList.add('btn-hidden');
    }
  }

  // Update 8 Metric Cards with Dynamic Number Formatting
  const ppsEl = document.getElementById('val-pps');
  const bpsEl = document.getElementById('val-bps');
  const connEl = document.getElementById('val-connections');
  const ipsEl = document.getElementById('val-ips');
  const tcpEl = document.getElementById('val-tcp');
  const udpEl = document.getElementById('val-udp');
  const synEl = document.getElementById('val-syn');
  const threatsEl = document.getElementById('val-threats');

  if (ppsEl) ppsEl.innerText = Math.round(data.metrics.packets_per_second || 0).toLocaleString();
  if (bpsEl) bpsEl.innerText = formatBytes(data.metrics.bytes_per_second || 0);
  if (connEl) connEl.innerText = (data.metrics.connection_count || 0).toLocaleString();
  if (ipsEl) ipsEl.innerText = ((data.metrics.unique_source_ips || 0) + (data.metrics.unique_destination_ips || 0)).toLocaleString();
  if (tcpEl) tcpEl.innerText = (data.metrics.tcp_count || 0).toLocaleString();
  if (udpEl) udpEl.innerText = (data.metrics.udp_count || 0).toLocaleString();
  if (synEl) synEl.innerText = (data.metrics.syn_count || 0).toLocaleString();
  if (threatsEl) threatsEl.innerText = (data.threats_count || 0).toLocaleString();

  // Dynamic Threat Card Accent Glow
  const threatCard = document.querySelector('.stat-card-threat');
  if (threatCard) {
    if (isDDoS) {
      threatCard.style.boxShadow = 'var(--shadow-glow-red)';
    } else {
      threatCard.style.boxShadow = 'none';
    }
  }

  // Update AI Analysis Panel
  const predText = document.getElementById('ai-prediction-text');
  const riskBadge = document.getElementById('ai-risk-badge');
  const confText = document.getElementById('ai-confidence-text');
  const probNormBar = document.getElementById('prob-normal-bar');
  const probDdosBar = document.getElementById('prob-ddos-bar');
  const probNormText = document.getElementById('prob-normal-text');
  const probDdosText = document.getElementById('prob-ddos-text');

  if (predText) {
    predText.innerText = isDDoS ? 'POSSIBLE DDoS' : 'NORMAL';
    predText.style.color = isDDoS ? 'var(--accent-red)' : 'var(--accent-green)';
  }

  if (riskBadge) {
    riskBadge.className = `ai-risk-badge risk-${(data.risk_level || 'low').toLowerCase()}`;
    riskBadge.innerText = data.risk_level || 'LOW';
  }

  const confPercent = ((data.confidence || 0) * 100).toFixed(1);
  if (confText) confText.innerText = `${confPercent}%`;

  const normProb = ((data.prob_normal || 0) * 100).toFixed(1);
  const ddosProb = ((data.prob_ddos || 0) * 100).toFixed(1);
  if (probNormBar) probNormBar.style.width = `${normProb}%`;
  if (probNormText) probNormText.innerText = `${normProb}%`;
  if (probDdosBar) probDdosBar.style.width = `${ddosProb}%`;
  if (probDdosText) probDdosText.innerText = `${ddosProb}%`;

  // Update Diagnostic Observations
  const obsList = document.getElementById('ai-observations-list');
  if (obsList && data.observations) {
    obsList.innerHTML = '';
    data.observations.forEach(obs => {
      const li = document.createElement('li');
      li.innerHTML = `<span class="observation-dot"></span> ${obs}`;
      obsList.appendChild(li);
    });
  }

  // Update Real-Time Multi-Stream Chart
  if (trafficChart) {
    const now = new Date().toLocaleTimeString();
    trafficChart.data.labels.push(now);
    trafficChart.data.datasets[0].data.push(Math.round(data.metrics.packets_per_second || 0));
    trafficChart.data.datasets[1].data.push(Math.round(data.metrics.syn_count || 0));

    if (trafficChart.data.labels.length > MAX_CHART_POINTS) {
      trafficChart.data.labels.shift();
      trafficChart.data.datasets[0].data.shift();
      trafficChart.data.datasets[1].data.shift();
    }
    trafficChart.update();
  }

  // Update Recent Events Table
  if (data.recent_events && data.recent_events.length > 0) {
    const tbody = document.getElementById('recent-events-tbody');
    if (tbody) {
      tbody.innerHTML = '';
      data.recent_events.forEach(evt => {
        const tr = document.createElement('tr');
        const isEvtDDoS = (evt.prediction && evt.prediction.includes('DDoS')) || evt.prediction === 1;
        tr.innerHTML = `
          <td>${evt.timestamp}</td>
          <td><span class="mode-badge">${evt.mode}</span></td>
          <td style="color:${isEvtDDoS ? 'var(--accent-red)' : 'var(--accent-green)'}; font-weight:600;">${isEvtDDoS ? 'POSSIBLE DDoS' : 'NORMAL'}</td>
          <td><span class="ai-risk-badge risk-${(evt.risk_level || 'low').toLowerCase()}">${evt.risk_level}</span></td>
          <td style="font-family: var(--font-mono);">${(evt.confidence * 100).toFixed(1)}%</td>
          <td style="font-family: var(--font-mono);">${Number(evt.packets_per_second || 0).toLocaleString()}</td>
          <td style="font-family: var(--font-mono);">${Number(evt.syn_count || 0).toLocaleString()}</td>
          <td style="font-family: var(--font-mono);">${Number(evt.connection_count || 0).toLocaleString()}</td>
        `;
        tbody.appendChild(tr);
      });
    }
  }
}

// Safe formatting helper
function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B/s';
  const k = 1024;
  const sizes = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  const i = Math.min(sizes.length - 1, Math.max(0, Math.floor(Math.log(bytes) / Math.log(k))));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Interactive Control Handlers
async function startMonitoring() {
  try {
    const select = document.getElementById('interface-select');
    const iface = select ? select.value : 'auto';
    const res = await fetch('/api/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface: iface })
    });
    await res.json();
    fetchStatus();
  } catch (e) {
    alert('Failed to start monitoring: ' + e.message);
  }
}

async function stopMonitoring() {
  try {
    const res = await fetch('/api/stop', { method: 'POST' });
    await res.json();
    fetchStatus();
  } catch (e) {
    alert('Failed to stop monitoring: ' + e.message);
  }
}

async function simulateTraffic(type) {
  try {
    let endpoint = '/api/simulate/normal';
    let body = {};
    if (type === 'ddos') {
      endpoint = '/api/simulate/ddos';
      const attackSelect = document.getElementById('attack-select');
      body = { attack_type: attackSelect ? attackSelect.value : 'SYN_FLOOD' };
    }
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    await res.json();
    fetchStatus();
  } catch (e) {
    alert(`Simulation failed: ${e.message}`);
  }
}
