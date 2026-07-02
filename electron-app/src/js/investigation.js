// IP Investigation page logic

(function () {
  const state = {
    fileId: null,
    currentIP: null,
    reportData: null
  };

  function getSelectedFileId() {
    const id = sessionStorage.getItem('selectedFileId');
    return id ? parseInt(id, 10) : null;
  }

  function formatBytes(bytes) {
    if (!bytes && bytes !== 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  }

  function formatTimestamp(ts) {
    if (!ts) return 'N/A';
    const d = new Date(ts * 1000);
    return d.toLocaleString();
  }

  function formatDuration(seconds) {
    if (!seconds) return '0s';
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }

  function getRiskColor(riskLevel) {
    const colors = {
      'low': '#28a745',
      'medium': '#ffc107',
      'high': '#fd7e14',
      'critical': '#dc3545',
      'unknown': '#6c757d'
    };
    return colors[riskLevel] || colors.unknown;
  }

  async function loadAvailableIPs() {
    try {
      const data = await window.api.getInvestigationIPs(state.fileId);
      const ipList = document.getElementById('ipList');
      
      if (!data.ips || data.ips.length === 0) {
        ipList.innerHTML = '<span class="text-muted">No IPs found</span>';
        return;
      }

      // Show top 10 IPs by packet count
      const topIPs = data.ips.slice(0, 10);
      ipList.innerHTML = topIPs.map(item => 
        `<button class="ip-chip" data-ip="${item.ip}">${item.ip} (${item.packet_count})</button>`
      ).join('');

      // Add click handlers
      document.querySelectorAll('.ip-chip').forEach(chip => {
        chip.onclick = () => {
          const ip = chip.getAttribute('data-ip');
          document.getElementById('ipInput').value = ip;
          investigateIP(ip);
        };
      });
    } catch (e) {
      console.error('Failed to load IPs:', e);
      window.ui.showStatus('Failed to load IP list', 'error');
    }
  }

  async function investigateIP(ip) {
    if (!ip) {
      window.ui.showStatus('Please enter an IP address', 'warning');
      return;
    }

    // Show loading
    document.getElementById('loadingIndicator').style.display = 'block';
    document.getElementById('reportSection').style.display = 'none';

    try {
      const data = await window.api.investigateIP(state.fileId, ip);
      
      if (!data.success) {
        throw new Error(data.error || 'Investigation failed');
      }

      state.currentIP = ip;
      state.reportData = data;

      renderReport(data);

      // Hide loading, show report
      document.getElementById('loadingIndicator').style.display = 'none';
      document.getElementById('reportSection').style.display = 'block';

      // Load threat intelligence
      loadThreatIntelligence(ip);

      window.ui.showStatus(`Investigation complete for ${ip}`, 'success');

    } catch (e) {
      console.error('Investigation error:', e);
      document.getElementById('loadingIndicator').style.display = 'none';
      window.ui.showStatus(`Investigation failed: ${e.message}`, 'error');
    }
  }

  function renderReport(data) {
    // 1. Overview
    const overview = data.overview || {};
    document.getElementById('overviewIP').textContent = overview.ip || 'N/A';
    document.getElementById('overviewMAC').textContent = overview.mac || 'N/A';
    document.getElementById('overviewFirst').textContent = formatTimestamp(overview.first_seen);
    document.getElementById('overviewLast').textContent = formatTimestamp(overview.last_seen);
    document.getElementById('overviewDuration').textContent = formatDuration(overview.duration_sec);
    document.getElementById('overviewPackets').textContent = (overview.total_packets || 0).toLocaleString();

    // 2. AI Analysis
    const ai = data.ai_analysis || {};
    const riskLevel = (ai.risk_level || 'unknown').toUpperCase();
    const riskScore = ai.risk_score || 0;
    
    const riskBadge = document.getElementById('riskBadge');
    riskBadge.textContent = riskLevel;
    riskBadge.style.backgroundColor = getRiskColor(ai.risk_level);
    
    document.getElementById('aiSummary').innerHTML = `<p>${ai.summary || 'No summary available'}</p>`;
    
    const scoreFill = document.getElementById('scoreFill');
    scoreFill.style.width = `${riskScore}%`;
    scoreFill.style.backgroundColor = getRiskColor(ai.risk_level);
    document.getElementById('scoreValue').textContent = `${riskScore}/100`;

    // 3. Traffic Statistics
    const traffic = data.traffic || {};
    const outgoing = traffic.outgoing || {};
    const incoming = traffic.incoming || {};
    const total = traffic.total || {};

    document.getElementById('trafficOutgoing').textContent = formatBytes(outgoing.bytes);
    document.getElementById('trafficOutgoingPackets').textContent = `${(outgoing.packets || 0).toLocaleString()} packets`;
    
    document.getElementById('trafficIncoming').textContent = formatBytes(incoming.bytes);
    document.getElementById('trafficIncomingPackets').textContent = `${(incoming.packets || 0).toLocaleString()} packets`;
    
    document.getElementById('trafficTotal').textContent = formatBytes(total.bytes);
    document.getElementById('trafficTotalPackets').textContent = `${(total.packets || 0).toLocaleString()} packets`;

    // Protocol breakdown
    const protocols = traffic.protocols || {};
    const protocolList = document.getElementById('protocolList');
    if (Object.keys(protocols).length > 0) {
      protocolList.innerHTML = Object.entries(protocols)
        .map(([proto, count]) => `
          <div class="protocol-item">
            <span class="protocol-name">${proto}</span>
            <span class="protocol-count">${count.toLocaleString()}</span>
          </div>
        `).join('');
    } else {
      protocolList.innerHTML = '<p class="text-muted">No protocol data</p>';
    }

    // 4. Domains
    const domains = data.domains || {};
    document.getElementById('domainTotal').textContent = domains.total || 0;
    document.getElementById('domainSafe').textContent = domains.safe || 0;
    document.getElementById('domainSuspicious').textContent = domains.suspicious || 0;
    document.getElementById('domainMalicious').textContent = domains.malicious || 0;
    document.getElementById('domainUnknown').textContent = domains.unknown || 0;

    // Risky domains
    const riskyDomains = document.getElementById('riskyDomains');
    const risky = domains.risky_domains || [];
    if (risky.length > 0) {
      riskyDomains.style.display = 'block';
      riskyDomains.innerHTML = '<h4>⚠️ Domains Requiring Attention:</h4>' + risky.map(d => `
        <div class="risky-domain-item ${d.verdict}">
          <div class="domain-name">
            <i class="fa-solid ${d.verdict === 'malicious' ? 'fa-skull-crossbones' : 'fa-exclamation-triangle'}"></i>
            ${d.domain}
          </div>
          <div class="domain-verdict">${d.verdict.toUpperCase()}</div>
          <div class="domain-explanation">${d.explanation || 'No explanation'}</div>
          <div class="domain-count">Queried ${d.count} times</div>
        </div>
      `).join('');
    } else {
      riskyDomains.style.display = 'none';
    }

    // All domains
    const allDomains = domains.all_domains || [];
    document.getElementById('allDomainsCount').textContent = allDomains.length;
    const allDomainsList = document.getElementById('allDomainsList');
    if (allDomains.length > 0) {
      allDomainsList.innerHTML = allDomains.map(d => `
        <div class="domain-item">
          <span class="domain-name">${d.domain}</span>
          <span class="verdict-badge verdict-${d.verdict || 'unknown'}">${(d.verdict || 'unknown').toUpperCase()}</span>
          <span class="domain-count">${d.count} queries</span>
        </div>
      `).join('');
    } else {
      allDomainsList.innerHTML = '<p class="text-muted">No domains accessed</p>';
    }

    // 5. Findings
    const findings = ai.findings || [];
    const findingsList = document.getElementById('findingsList');
    if (findings.length > 0) {
      findingsList.innerHTML = findings.map(f => `<li>${f}</li>`).join('');
    } else {
      findingsList.innerHTML = '<li class="text-muted">No specific findings</li>';
    }

    // 6. Recommendations
    const recommendations = ai.recommendations || [];
    const recList = document.getElementById('recommendationsList');
    if (recommendations.length > 0) {
      recList.innerHTML = recommendations.map(r => `<li>${r}</li>`).join('');
    } else {
      recList.innerHTML = '<li class="text-muted">No recommendations</li>';
    }

    // 7. Top Connections
    const connections = data.connections || {};
    const topConns = connections.top_connections || [];
    const connsTable = document.getElementById('connectionsTable');
    if (topConns.length > 0) {
      connsTable.innerHTML = topConns.map(c => `
        <tr>
          <td>${c.destination}</td>
          <td>${c.port || 'N/A'}</td>
          <td>${c.protocol}</td>
          <td>${(c.packets || 0).toLocaleString()}</td>
          <td>${formatBytes(c.bytes)}</td>
          <td>${formatDuration(c.duration_sec)}</td>
        </tr>
      `).join('');
    } else {
      connsTable.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No connections</td></tr>';
    }
  }

  async function loadThreatIntelligence(ip) {
    const card = document.getElementById('threatIntelCard');
    const loading = document.getElementById('threatIntelLoading');
    const content = document.getElementById('threatIntelContent');
    const noData = document.getElementById('noThreatIntelData');

    // Show the card and loading state
    card.style.display = 'block';
    loading.style.display = 'flex';
    content.style.display = 'none';

    try {
      const data = await window.api.checkIPThreat(ip);

      // Hide loading
      loading.style.display = 'none';
      content.style.display = 'block';

      // Check if any services returned data
      const sources = data.sources || [];
      if (sources.length === 0) {
        noData.style.display = 'block';
        return;
      }

      noData.style.display = 'none';

      // Overall threat score
      const threatScore = data.threat_score || 0;
      const threatLevel = (data.threat_level || 'clean').toUpperCase();
      
      document.getElementById('threatScoreNumber').textContent = Math.round(threatScore);
      document.getElementById('threatLevelBadge').textContent = threatLevel;
      document.getElementById('threatLevelBadge').className = `threat-level-badge threat-${data.threat_level}`;

      // Color the score circle
      const scoreCircle = document.getElementById('threatScoreCircle');
      if (threatScore >= 80) {
        scoreCircle.className = 'score-circle critical';
      } else if (threatScore >= 60) {
        scoreCircle.className = 'score-circle high';
      } else if (threatScore >= 40) {
        scoreCircle.className = 'score-circle medium';
      } else if (threatScore >= 20) {
        scoreCircle.className = 'score-circle low';
      } else {
        scoreCircle.className = 'score-circle clean';
      }

      // Summary
      if (data.is_malicious) {
        document.getElementById('threatSummary').innerHTML = 
          '<i class="fa-solid fa-exclamation-triangle"></i> This IP has been flagged as malicious by threat intelligence sources';
      } else if (threatScore >= 40) {
        document.getElementById('threatSummary').innerHTML = 
          '<i class="fa-solid fa-exclamation-circle"></i> This IP shows suspicious activity patterns';
      } else {
        document.getElementById('threatSummary').textContent = 
          'No significant threats detected from this IP';
      }

      // VirusTotal data
      const vtSource = sources.find(s => s.source === 'VirusTotal');
      if (vtSource && !vtSource.error) {
        document.getElementById('virusTotalSection').style.display = 'block';
        document.getElementById('vtBadge').textContent = `${Math.round(vtSource.score)}%`;
        document.getElementById('vtBadge').className = 'source-badge ' + 
          (vtSource.score >= 50 ? 'badge-danger' : vtSource.score >= 20 ? 'badge-warning' : 'badge-success');
        
        document.getElementById('vtRatio').textContent = 
          `${vtSource.malicious_count}/${vtSource.total_engines}`;
        document.getElementById('vtMalicious').textContent = vtSource.malicious_count || 0;
        document.getElementById('vtSuspicious').textContent = vtSource.suspicious_count || 0;
        document.getElementById('vtASOwner').textContent = vtSource.as_owner || 'Unknown';
      }

      // AbuseIPDB data
      const abuseSource = sources.find(s => s.source === 'AbuseIPDB');
      if (abuseSource && !abuseSource.error) {
        document.getElementById('abuseIPDBSection').style.display = 'block';
        document.getElementById('abuseIPDBBadge').textContent = `${Math.round(abuseSource.score)}%`;
        document.getElementById('abuseIPDBBadge').className = 'source-badge ' + 
          (abuseSource.score >= 50 ? 'badge-danger' : abuseSource.score >= 20 ? 'badge-warning' : 'badge-success');
        
        document.getElementById('abuseConfidence').textContent = `${abuseSource.abuse_confidence_score}%`;
        document.getElementById('abuseReports').textContent = abuseSource.total_reports || 0;
        document.getElementById('abuseLastReported').textContent = 
          abuseSource.last_reported ? new Date(abuseSource.last_reported).toLocaleDateString() : 'Never';
        document.getElementById('abuseISP').textContent = abuseSource.isp || 'Unknown';
      }

    } catch (error) {
      console.error('Threat intelligence error:', error);
      loading.style.display = 'none';
      content.style.display = 'block';
      noData.style.display = 'block';
    }
  }

  async function init() {
    state.fileId = getSelectedFileId();
    
    if (!state.fileId) {
      window.ui.showStatus('No file selected. Please go to Files and analyze a PCAP first.', 'warning');
      document.querySelector('.search-section').style.opacity = '0.5';
      document.querySelector('.search-section').style.pointerEvents = 'none';
      return;
    }

    // Load available IPs
    await loadAvailableIPs();

    // Wire up search button
    document.getElementById('investigateBtn').onclick = () => {
      const ip = document.getElementById('ipInput').value.trim();
      investigateIP(ip);
    };

    // Enter key support
    document.getElementById('ipInput').onkeypress = (e) => {
      if (e.key === 'Enter') {
        const ip = document.getElementById('ipInput').value.trim();
        investigateIP(ip);
      }
    };

    // Threat intel refresh button
    const refreshBtn = document.getElementById('refreshThreatIntel');
    if (refreshBtn) {
      refreshBtn.onclick = () => {
        if (state.currentIP) {
          loadThreatIntelligence(state.currentIP);
        }
      };
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
