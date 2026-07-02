/**
 * Network Visualization Module
 * Interactive network graph using Vis.js
 */

(function() {
    'use strict';

    let network = null;
    let nodes = null;
    let edges = null;
    let allNodesData = [];
    let allEdgesData = [];
    let currentPcapId = null;

    // Initialize
    document.addEventListener('DOMContentLoaded', init);

    function init() {
        loadFilesList();
        setupEventListeners();
    }

    function setupEventListeners() {
        document.getElementById('loadBtn').addEventListener('click', loadNetwork);
        document.getElementById('showInternal').addEventListener('change', filterGraph);
        document.getElementById('showExternal').addEventListener('change', filterGraph);
        document.getElementById('physicsEnabled').addEventListener('change', togglePhysics);
        document.getElementById('showLabels').addEventListener('change', toggleLabels);
        document.getElementById('layoutSelect').addEventListener('change', changeLayout);
        document.getElementById('resetView').addEventListener('click', resetView);
        document.getElementById('exportBtn').addEventListener('click', exportGraph);
        document.getElementById('closeDetails').addEventListener('click', closeDetailsPanel);
    }

    async function loadFilesList() {
        try {
            const data = await window.api.get('/files');
            const files = data.files || [];
            const select = document.getElementById('fileSelect');
            select.innerHTML = '<option value="">Select a file...</option>';
            
            files.forEach(file => {
                const option = document.createElement('option');
                option.value = file.id;
                option.textContent = `${file.filename} (${formatBytes(file.size)})`;
                select.appendChild(option);
            });
            
            console.log(`Loaded ${files.length} PCAP files`);
        } catch (error) {
            console.error('Failed to load files:', error);
            window.ui.showStatus('Failed to load files: ' + error.message, 'error');
        }
    }

    async function loadNetwork() {
        const fileId = document.getElementById('fileSelect').value;
        if (!fileId) {
            window.ui.showStatus('Please select a PCAP file', 'warning');
            return;
        }

        currentPcapId = fileId;

        // Show loading
        document.getElementById('emptyState').style.display = 'none';
        document.getElementById('loadingGraph').style.display = 'flex';
        document.getElementById('networkGraph').style.display = 'none';

        try {
            const data = await window.api.getNetworkGraph(fileId);
            
            allNodesData = data.nodes;
            allEdgesData = data.edges;

            // Update stats
            updateStats(data.stats);

            // Create network
            createNetwork(data.nodes, data.edges);

            // Show graph
            document.getElementById('loadingGraph').style.display = 'none';
            document.getElementById('networkGraph').style.display = 'block';
            document.getElementById('graphControls').style.display = 'flex';
            document.getElementById('statsBar').style.display = 'flex';

            window.ui.showStatus('Network graph loaded successfully', 'success');
        } catch (error) {
            document.getElementById('loadingGraph').style.display = 'none';
            document.getElementById('emptyState').style.display = 'flex';
            window.ui.showStatus('Failed to load network: ' + error.message, 'error');
        }
    }

    function createNetwork(nodesData, edgesData) {
        const container = document.getElementById('networkGraph');

        // Transform nodes for vis.js
        const visNodes = nodesData.map(node => {
            let color = getNodeColor(node);
            let size = Math.max(20, Math.min(50, Math.log(node.bytes + 1) * 3));

            return {
                id: node.id,
                label: node.hostname || node.ip,
                title: getNodeTooltip(node),
                color: color,
                size: size,
                font: { color: '#e5e7eb', size: 12 },
                data: node // Store full node data
            };
        });

        // Transform edges for vis.js
        const visEdges = edgesData.map(edge => {
            let color = getEdgeColor(edge);
            let width = Math.max(1, Math.min(10, Math.log(edge.bytes + 1) / 2));

            return {
                from: edge.from,
                to: edge.to,
                title: getEdgeTooltip(edge),
                color: color,
                width: width,
                arrows: 'to',
                smooth: { type: 'continuous' },
                data: edge // Store full edge data
            };
        });

        nodes = new vis.DataSet(visNodes);
        edges = new vis.DataSet(visEdges);

        const data = { nodes: nodes, edges: edges };

        const options = {
            nodes: {
                shape: 'dot',
                borderWidth: 2,
                borderWidthSelected: 4,
                font: {
                    color: '#e5e7eb',
                    size: 12,
                    face: 'Arial'
                }
            },
            edges: {
                smooth: {
                    type: 'continuous',
                    roundness: 0.5
                },
                color: {
                    inherit: false
                }
            },
            physics: {
                enabled: true,
                forceAtlas2Based: {
                    gravitationalConstant: -50,
                    centralGravity: 0.01,
                    springLength: 200,
                    springConstant: 0.08,
                    damping: 0.4,
                    avoidOverlap: 0.5
                },
                maxVelocity: 50,
                minVelocity: 0.1,
                solver: 'forceAtlas2Based',
                stabilization: {
                    enabled: true,
                    iterations: 100,
                    updateInterval: 25
                }
            },
            interaction: {
                hover: true,
                tooltipDelay: 200,
                zoomView: true,
                dragView: true
            }
        };

        // Create network
        if (network) {
            network.destroy();
        }

        network = new vis.Network(container, data, options);

        // Event listeners
        network.on('click', onNodeClick);
        network.on('doubleClick', onDoubleClick);
    }

    function getNodeColor(node) {
        // Threat level takes priority
        if (node.threat_level === 'malicious') {
            return {
                background: '#ef4444',
                border: '#dc2626',
                highlight: { background: '#f87171', border: '#dc2626' }
            };
        }
        if (node.threat_level === 'suspicious') {
            return {
                background: '#f59e0b',
                border: '#d97706',
                highlight: { background: '#fbbf24', border: '#d97706' }
            };
        }

        // Type-based colors
        if (node.type === 'internal') {
            return {
                background: '#3b82f6',
                border: '#2563eb',
                highlight: { background: '#60a5fa', border: '#2563eb' }
            };
        } else {
            return {
                background: '#8b5cf6',
                border: '#7c3aed',
                highlight: { background: '#a78bfa', border: '#7c3aed' }
            };
        }
    }

    function getEdgeColor(edge) {
        const protocol = edge.protocol.toUpperCase();
        
        if (protocol === 'TCP') {
            return { color: '#22d3ee', highlight: '#06b6d4' };
        } else if (protocol === 'UDP') {
            return { color: '#10b981', highlight: '#059669' };
        } else if (protocol === 'ICMP') {
            return { color: '#f59e0b', highlight: '#d97706' };
        } else {
            return { color: '#6b7280', highlight: '#9ca3af' };
        }
    }

    function getNodeTooltip(node) {
        let tooltip = `<b>${node.ip}</b><br>`;
        if (node.hostname) tooltip += `Hostname: ${node.hostname}<br>`;
        if (node.mac) tooltip += `MAC: ${node.mac}<br>`;
        tooltip += `Type: ${node.type}<br>`;
        tooltip += `Connections: ${node.connections}<br>`;
        tooltip += `Traffic: ${formatBytes(node.bytes)}<br>`;
        if (node.threat_level !== 'safe') {
            tooltip += `<b style="color: #ef4444">Threat: ${node.threat_level}</b>`;
        }
        return tooltip;
    }

    function getEdgeTooltip(edge) {
        return `<b>${edge.from} → ${edge.to}</b><br>
                Protocol: ${edge.protocol}<br>
                Packets: ${edge.packets}<br>
                Bytes: ${formatBytes(edge.bytes)}`;
    }

    function onNodeClick(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = nodes.get(nodeId);
            showNodeDetails(node.data);
        }
    }

    function onDoubleClick(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = nodes.get(nodeId);
            
            // Navigate to investigation page
            if (node.data.ip) {
                window.location.href = `investigation.html?pcap_id=${currentPcapId}&ip=${node.data.ip}`;
            }
        }
    }

    function showNodeDetails(nodeData) {
        const panel = document.getElementById('nodeDetails');
        const content = document.getElementById('nodeContent');
        
        let html = `
            <div class="detail-section">
                <h4><i class="fas fa-network-wired"></i> Network Information</h4>
                <div class="detail-row">
                    <span class="detail-label">IP Address:</span>
                    <span class="detail-value monospace">${nodeData.ip}</span>
                </div>
                ${nodeData.hostname ? `
                <div class="detail-row">
                    <span class="detail-label">Hostname:</span>
                    <span class="detail-value">${nodeData.hostname}</span>
                </div>` : ''}
                ${nodeData.mac ? `
                <div class="detail-row">
                    <span class="detail-label">MAC Address:</span>
                    <span class="detail-value monospace">${nodeData.mac}</span>
                </div>` : ''}
                <div class="detail-row">
                    <span class="detail-label">Type:</span>
                    <span class="detail-value badge badge-${nodeData.type}">${nodeData.type}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Threat Level:</span>
                    <span class="detail-value badge badge-${nodeData.threat_level}">${nodeData.threat_level}</span>
                </div>
            </div>

            <div class="detail-section">
                <h4><i class="fas fa-chart-line"></i> Traffic Statistics</h4>
                <div class="detail-row">
                    <span class="detail-label">Total Connections:</span>
                    <span class="detail-value">${nodeData.connections}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Total Traffic:</span>
                    <span class="detail-value">${formatBytes(nodeData.bytes)}</span>
                </div>
            </div>
        `;

        if (nodeData.domains && nodeData.domains.length > 0) {
            html += `
                <div class="detail-section">
                    <h4><i class="fas fa-globe"></i> Accessed Domains</h4>
                    <div class="domains-list">
            `;
            
            nodeData.domains.slice(0, 10).forEach(domain => {
                html += `
                    <div class="domain-item">
                        <span class="domain-name">${domain.domain}</span>
                        <span class="verdict-badge verdict-${domain.verdict}">${domain.verdict}</span>
                        <span class="domain-count">${domain.count}x</span>
                    </div>
                `;
            });

            if (nodeData.domains.length > 10) {
                html += `<p class="text-muted">+ ${nodeData.domains.length - 10} more domains</p>`;
            }

            html += `</div></div>`;
        }

        html += `
            <div class="detail-actions">
                <button class="btn btn-primary btn-sm" onclick="window.location.href='investigation.html?pcap_id=${currentPcapId}&ip=${nodeData.ip}'">
                    <i class="fas fa-search"></i> Investigate IP
                </button>
            </div>
        `;

        content.innerHTML = html;
        panel.style.display = 'block';
        document.getElementById('nodeTitle').textContent = nodeData.hostname || nodeData.ip;
    }

    function closeDetailsPanel() {
        document.getElementById('nodeDetails').style.display = 'none';
    }

    function filterGraph() {
        const showInternal = document.getElementById('showInternal').checked;
        const showExternal = document.getElementById('showExternal').checked;

        const filteredNodes = allNodesData.filter(node => {
            if (node.type === 'internal' && !showInternal) return false;
            if (node.type === 'external' && !showExternal) return false;
            return true;
        });

        const nodeIds = new Set(filteredNodes.map(n => n.id));
        const filteredEdges = allEdgesData.filter(edge => 
            nodeIds.has(edge.from) && nodeIds.has(edge.to)
        );

        createNetwork(filteredNodes, filteredEdges);
    }

    function togglePhysics() {
        const enabled = document.getElementById('physicsEnabled').checked;
        network.setOptions({ physics: { enabled: enabled } });
    }

    function toggleLabels() {
        const show = document.getElementById('showLabels').checked;
        if (show) {
            nodes.forEach(node => {
                nodes.update({ id: node.id, label: node.data.hostname || node.data.ip });
            });
        } else {
            nodes.forEach(node => {
                nodes.update({ id: node.id, label: '' });
            });
        }
    }

    function changeLayout() {
        const layout = document.getElementById('layoutSelect').value;
        
        if (layout === 'hierarchical') {
            network.setOptions({
                layout: {
                    hierarchical: {
                        enabled: true,
                        direction: 'UD',
                        sortMethod: 'directed'
                    }
                },
                physics: { enabled: false }
            });
        } else {
            network.setOptions({
                layout: { hierarchical: { enabled: false } },
                physics: {
                    enabled: true,
                    solver: layout
                }
            });
        }
    }

    function resetView() {
        if (network) {
            network.fit({
                animation: {
                    duration: 1000,
                    easingFunction: 'easeInOutQuad'
                }
            });
        }
    }

    function exportGraph() {
        if (!network) return;
        
        const canvas = document.querySelector('#networkGraph canvas');
        if (canvas) {
            const link = document.createElement('a');
            link.download = `network-graph-${currentPcapId}-${Date.now()}.png`;
            link.href = canvas.toDataURL('image/png');
            link.click();
            window.ui.showStatus('Network graph exported successfully', 'success');
        }
    }

    function updateStats(stats) {
        document.getElementById('statNodes').textContent = stats.total_nodes;
        document.getElementById('statEdges').textContent = stats.total_edges;
        document.getElementById('statInternal').textContent = stats.internal_nodes;
        document.getElementById('statExternal').textContent = stats.external_nodes;
        document.getElementById('statThreats').textContent = stats.threats;
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

})();
