// Analysis page logic: loads summary and paginated tables for the selected PCAP

(function () {
  const state = {
    fileId: null,
    ipsPage: 1,
    domainsPage: 1,
    devicesPage: 1,
    flowsPage: 1,
    pageSize: 10,
  };

  function getSelectedFileId() {
    // Reuse selection from files page
    const id = sessionStorage.getItem('selectedFileId');
    return id ? parseInt(id, 10) : null;
  }

  function setPageInfo(elId, page, total, pageSize) {
    const el = document.getElementById(elId);
    if (!el) return;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    el.textContent = `Page ${page} of ${totalPages} • ${total} total`;
  }

  function fmtBytes(bytes) {
    if (!bytes && bytes !== 0) return '';
    const k = 1024; const sizes = ['B','KB','MB','GB','TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  }

  function fmtTs(ts) {
    if (!ts && ts !== 0) return '';
    const d = new Date(ts * 1000);
    return d.toLocaleString();
  }

  function fmtDuration(seconds) {
    if (seconds == null) return '';
    const s = Math.max(0, Math.floor(seconds));
    const m = Math.floor(s / 60);
    const h = Math.floor(m / 60);
    const mm = m % 60;
    const ss = s % 60;
    if (h > 0) return `${h}h ${mm}m ${ss}s`;
    if (m > 0) return `${m}m ${ss}s`;
    return `${s}s`;
  }

  function renderSummary(data) {
    const summary = data.captureSummary || {};
    const cards = [
      { label: 'Packets', value: summary.totalPackets || 0 },
      { label: 'Bytes', value: fmtBytes(summary.totalBytes || 0) },
      { label: 'TCP', value: (summary.protocols || {}).TCP || 0 },
      { label: 'UDP', value: (summary.protocols || {}).UDP || 0 },
      { label: 'ICMP', value: (summary.protocols || {}).ICMP || 0 },
      { label: 'ARP', value: (summary.protocols || {}).ARP || 0 },
    ];
    const grid = document.getElementById('summaryCards');
    grid.innerHTML = cards.map(c => `
      <div class="summary-card">
        <div class="summary-label">${c.label}</div>
        <div class="summary-value">${c.value}</div>
      </div>
    `).join('');

    const periodEl = document.getElementById('summaryPeriod');
    const startTs = summary.startTs; const endTs = summary.endTs;
    const durSec = summary.durationSec || 0;
    const minutes = Math.max(0, (durSec / 60).toFixed(1));
    periodEl.textContent = startTs && endTs
      ? `Time period: ${fmtTs(startTs)} → ${fmtTs(endTs)} (${minutes} minutes)`
      : 'Time period: n/a';
  }

  function renderTbody(tbodyId, rows) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    if (!rows || rows.length === 0) {
      tbody.innerHTML = `<tr><td class="text-center" colspan="10">No data</td></tr>`;
      return;
    }
    tbody.innerHTML = rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('');
  }

  async function loadSummary() {
    const data = await window.api.getAnalysisSummary(state.fileId);
    renderSummary(data);
  }

  async function loadIPs() {
  const res = await window.api.getIPs(state.fileId, state.ipsPage, state.pageSize);
  renderTbody('ipsTbody', res.items.map(i => [i.ip, i.count, fmtTs(i.first_seen), fmtTs(i.last_seen), fmtDuration(i.duration_sec), fmtBytes(i.bytes_sent || 0)]));
    setPageInfo('ipsPageInfo', res.page, res.total, res.page_size);
    const badge = document.getElementById('ipsBadge'); if (badge) badge.textContent = res.total;
    document.getElementById('ipsPrev').disabled = state.ipsPage <= 1;
    document.getElementById('ipsNext').disabled = (res.page * res.page_size) >= res.total;
  }

  async function loadDomains() {
    try {
      console.log(`[DOMAINS] Loading domains for fileId=${state.fileId}, page=${state.domainsPage}, pageSize=${state.pageSize}`);
      const res = await window.api.getDomains(state.fileId, state.domainsPage, state.pageSize);
      console.log('[DOMAINS] API response:', res);
      
      if (!res || !res.items) {
        console.error('[DOMAINS] Invalid response from API:', res);
        renderTbody('domainsTbody', []);
        return;
      }
      
      console.log(`[DOMAINS] Got ${res.items.length} domains, total=${res.total}`);
      
      const rows = res.items.map(i => {
        const domainCell = i.domain;
        const verdict = (i.verdict || 'unknown').toLowerCase();
        const badgeCls = verdict === 'malicious' ? 'verdict-badge verdict-malicious' : verdict === 'suspicious' ? 'verdict-badge verdict-suspicious' : verdict === 'safe' ? 'verdict-badge verdict-benign' : 'verdict-badge verdict-unknown';
        const verdictCell = `<span class="${badgeCls}">${verdict}</span>`;
        const explanationCell = i.explanation || '';
        const ipCell = i.ip || '';
        return [domainCell, i.source, ipCell, i.count, verdictCell, explanationCell];
      });
      
      console.log('[DOMAINS] Rendering rows:', rows.length);
      renderTbody('domainsTbody', rows);
      setPageInfo('domainsPageInfo', res.page, res.total, res.page_size);
      const badge = document.getElementById('domainsBadge'); if (badge) badge.textContent = res.total;
      document.getElementById('domainsPrev').disabled = state.domainsPage <= 1;
      document.getElementById('domainsNext').disabled = (res.page * res.page_size) >= res.total;
    } catch (error) {
      console.error('[DOMAINS] Error loading domains:', error);
      renderTbody('domainsTbody', []);
    }
  }

  async function loadDevices() {
    const res = await window.api.getDevices(state.fileId, state.devicesPage, state.pageSize);
    renderTbody('devicesTbody', res.items.map(i => [i.ip, i.mac || '', i.hostname || '', i.first_seen || '', i.last_seen || '']));
    setPageInfo('devicesPageInfo', res.page, res.total, res.page_size);
    const badge = document.getElementById('devicesBadge'); if (badge) badge.textContent = res.total;
    document.getElementById('devicesPrev').disabled = state.devicesPage <= 1;
    document.getElementById('devicesNext').disabled = (res.page * res.page_size) >= res.total;
  }

  async function loadFlows() {
    const res = await window.api.getFlows(state.fileId, state.flowsPage, state.pageSize);
    renderTbody('flowsTbody', res.items.map(i => [i.src_ip, i.src_port, i.dst_ip, i.dst_port, i.protocol, i.packet_count, i.byte_count, i.first_seen || '', i.last_seen || '']));
    setPageInfo('flowsPageInfo', res.page, res.total, res.page_size);
    const badge = document.getElementById('flowsBadge'); if (badge) badge.textContent = res.total;
    document.getElementById('flowsPrev').disabled = state.flowsPage <= 1;
    document.getElementById('flowsNext').disabled = (res.page * res.page_size) >= res.total;
  }

  async function init() {
    state.fileId = getSelectedFileId();
    if (!state.fileId) {
      window.ui.showStatus('No file selected for analysis. Go to Files and click Analyze.', 'warning');
      return;
    }

    // Ensure analysis exists (trigger if missing)
    try {
      await loadSummary();
    } catch (e) {
      // Try to run analysis first
      try {
        await window.api.triggerAnalysis(state.fileId);
        await loadSummary();
      } catch (err) {
        window.ui.showStatus(`Failed to analyze: ${err.message || err}`, 'error');
        return;
      }
    }

    await Promise.all([
      loadIPs(),
      loadDomains(),
      loadDevices(),
      loadFlows(),
    ]);

    // Wire pagination
    document.getElementById('ipsPrev').onclick = () => { state.ipsPage = Math.max(1, state.ipsPage - 1); loadIPs(); };
    document.getElementById('ipsNext').onclick = () => { state.ipsPage += 1; loadIPs(); };

    document.getElementById('domainsPrev').onclick = () => { state.domainsPage = Math.max(1, state.domainsPage - 1); loadDomains(); };
    document.getElementById('domainsNext').onclick = () => { state.domainsPage += 1; loadDomains(); };

    document.getElementById('devicesPrev').onclick = () => { state.devicesPage = Math.max(1, state.devicesPage - 1); loadDevices(); };
    document.getElementById('devicesNext').onclick = () => { state.devicesPage += 1; loadDevices(); };

    document.getElementById('flowsPrev').onclick = () => { state.flowsPage = Math.max(1, state.flowsPage - 1); loadFlows(); };
    document.getElementById('flowsNext').onclick = () => { state.flowsPage += 1; loadFlows(); };
  }

  // Init when DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
