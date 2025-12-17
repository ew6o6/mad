/**
 * MCP Forensics Analyzer - Main Application
 */

const API_BASE = '';
let analysisResult = null;
let uploadedFiles = [];

// DOM Elements
const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const fileList = document.getElementById('fileList');
const fileQueue = document.getElementById('fileQueue');
const fileCount = document.getElementById('fileCount');
const analyzeBtn = document.getElementById('analyzeBtn');
const clearFilesBtn = document.getElementById('clearFilesBtn');
const loading = document.getElementById('loading');
const errorToast = document.getElementById('errorToast');
const errorMessage = document.getElementById('errorMessage');
const closeError = document.getElementById('closeError');
const statsBar = document.getElementById('statsBar');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initUpload();
    initButtons();
    loadDefaultComparison();
});

// Navigation
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const section = item.dataset.section;
            switchSection(section);
        });
    });
}

function switchSection(sectionName) {
    // Update nav
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.section === sectionName);
    });

    // Update sections
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });

    const sectionId = sectionName + 'Section';
    const section = document.getElementById(sectionId);
    if (section) {
        section.classList.add('active');
    }

    // Update header title
    const titles = {
        upload: { h1: 'Upload Artifacts', p: 'Select MCP artifact files for analysis' },
        analysis: { h1: 'Analysis Results', p: 'Extracted entities and raw data' },
        timeline: { h1: 'Event Timeline', p: 'Chronological event sequence' },
        comparison: { h1: 'Server Comparison', p: 'Local vs Remote forensic capabilities' }
    };

    const title = titles[sectionName];
    if (title) {
        document.querySelector('.header-title h1').textContent = title.h1;
        document.querySelector('.header-title p').textContent = title.p;
    }
}

// Upload
function initUpload() {
    uploadArea.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', handleFileSelect);

    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });

    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover');
    });

    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        handleFiles(e.dataTransfer.files);
    });
}

function handleFileSelect(e) {
    handleFiles(e.target.files);
}

function handleFiles(files) {
    for (const file of files) {
        if (!isValidFile(file)) {
            showError(`Invalid file type: ${file.name}`);
            continue;
        }
        if (!uploadedFiles.find(f => f.name === file.name)) {
            uploadedFiles.push(file);
        }
    }
    renderFileList();
}

function isValidFile(file) {
    const validExtensions = ['.json', '.log', '.jsonl', '.pcap', '.pcapng', '.har', '.vscdb', '.db', '.sqlite'];
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    return validExtensions.includes(ext);
}

function renderFileList() {
    if (uploadedFiles.length === 0) {
        fileQueue.style.display = 'none';
        return;
    }

    fileQueue.style.display = 'block';
    fileCount.textContent = `${uploadedFiles.length} file${uploadedFiles.length > 1 ? 's' : ''}`;

    fileList.innerHTML = uploadedFiles.map((file, index) => `
        <div class="file-item">
            <div class="file-name">
                <svg class="file-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                </svg>
                <span>${file.name}</span>
                <span class="file-size">${formatFileSize(file.size)}</span>
            </div>
            <button class="remove-btn" onclick="removeFile(${index})">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        </div>
    `).join('');
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function removeFile(index) {
    uploadedFiles.splice(index, 1);
    renderFileList();
}

function clearFiles() {
    uploadedFiles = [];
    renderFileList();
    fileInput.value = '';
}

// Buttons
function initButtons() {
    analyzeBtn.addEventListener('click', analyzeArtifacts);
    clearFilesBtn.addEventListener('click', clearFiles);
    closeError.addEventListener('click', hideError);

    document.getElementById('copyJsonBtn')?.addEventListener('click', copyJson);
    document.getElementById('downloadJsonBtn')?.addEventListener('click', downloadJson);
}

// Analysis
async function analyzeArtifacts() {
    if (uploadedFiles.length === 0) return;

    showLoading(true);
    hideError();

    const formData = new FormData();
    uploadedFiles.forEach(file => {
        formData.append('files', file);
    });

    try {
        const response = await fetch(`${API_BASE}/api/analyze`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        analysisResult = await response.json();

        if (analysisResult.errors && analysisResult.errors.length > 0) {
            showError(analysisResult.errors.join(', '));
        }

        displayResults(analysisResult);
        switchSection('analysis');

    } catch (error) {
        console.error('Analysis failed:', error);
        showError('Analysis failed: ' + error.message);
    } finally {
        showLoading(false);
    }
}

function displayResults(result) {
    // Show stats bar
    statsBar.style.display = 'grid';

    const serverCount = result.entities?.servers?.length || 0;
    // Use tool_count if tools array is empty
    const toolCount = result.entities?.servers?.reduce((acc, s) => {
        const toolsLen = s.tools?.length || 0;
        const toolCountVal = s.tool_count || 0;
        return acc + (toolsLen > 0 ? toolsLen : toolCountVal);
    }, 0) || 0;
    const eventCount = result.timeline?.events?.length || 0;
    const sourceCount = result.stats?.files_processed || 0;

    document.getElementById('statServers').textContent = serverCount;
    document.getElementById('statTools').textContent = toolCount;
    document.getElementById('statEvents').textContent = eventCount;
    document.getElementById('statSources').textContent = sourceCount;

    // Update badges
    document.getElementById('serverCount').textContent = serverCount;
    document.getElementById('toolCount').textContent = toolCount;

    // Display entities
    displayEntities(result.entities);

    // Display MCP server usage from vscdb_analysis
    if (result.vscdb_analysis?.mcp_server_usage) {
        displayServerUsage(result.vscdb_analysis.mcp_server_usage);
    }

    // Display forensic metadata from remote MCP servers
    displayForensicMetadata(result.entities);

    // Display timeline
    if (typeof displayTimeline === 'function') {
        displayTimeline(result.timeline);
    }

    // Display comparison
    if (result.comparison && typeof displayComparison === 'function') {
        displayComparison(result.comparison);
    }

    // Display raw JSON
    displayRawJson(result);

    // Update server filter (include timeline for server discovery from events)
    updateServerFilter(result.entities, result.timeline);
}

function displayEntities(entities) {
    const serverList = document.getElementById('serverList');
    const toolList = document.getElementById('toolList');

    if (entities?.servers?.length > 0) {
        serverList.innerHTML = entities.servers.map(server => {
            const typeClass = server.server_type === 'local' ? 'local' :
                              server.server_type === 'official_remote' ? 'official' : 'remote';
            const toolCount = server.tool_count || server.tools?.length || 0;
            return `
                <div class="entity-item">
                    <div class="entity-name">
                        ${server.name}
                        <span class="type-badge ${typeClass}">${server.server_type}</span>
                    </div>
                    <div class="entity-meta">
                        <span>Transport: ${server.transport}</span>
                        <span>Tools: ${toolCount}</span>
                        <span>Calls: ${server.total_tool_calls || 0}</span>
                    </div>
                    ${server.command ? `<div class="entity-command">Command: ${server.command}</div>` : ''}
                </div>
            `;
        }).join('');
    } else {
        serverList.innerHTML = '<div class="empty-state"><p>No servers found</p></div>';
    }

    const allTools = [];
    entities?.servers?.forEach(server => {
        server.tools?.forEach(tool => {
            allTools.push({ ...tool, serverName: server.name });
        });
    });

    if (allTools.length > 0) {
        toolList.innerHTML = allTools.map(tool => `
            <div class="entity-item">
                <div class="entity-name">${tool.name}</div>
                <div class="entity-meta">
                    <span>Server: ${tool.serverName}</span>
                    ${tool.call_count ? `<span>Calls: ${tool.call_count}</span>` : ''}
                </div>
            </div>
        `).join('');
    } else {
        toolList.innerHTML = '<div class="empty-state"><p>No tools found</p></div>';
    }
}

function displayServerUsage(serverUsage) {
    const panel = document.getElementById('serverUsagePanel');
    const list = document.getElementById('serverUsageList');

    if (!serverUsage || Object.keys(serverUsage).length === 0) {
        panel.style.display = 'none';
        return;
    }

    panel.style.display = 'block';

    // Sort by call count descending
    const sortedUsage = Object.entries(serverUsage)
        .sort((a, b) => b[1] - a[1]);

    const totalCalls = sortedUsage.reduce((acc, [_, count]) => acc + count, 0);

    list.innerHTML = sortedUsage.map(([serverName, callCount]) => {
        const percentage = Math.round((callCount / totalCalls) * 100);
        return `
            <div class="entity-item usage-item">
                <div class="entity-name">
                    ${serverName}
                    <span class="call-count">${callCount} tool calls</span>
                </div>
                <div class="usage-bar-container">
                    <div class="usage-bar" style="width: ${percentage}%"></div>
                    <span class="usage-percentage">${percentage}%</span>
                </div>
            </div>
        `;
    }).join('');
}

function displayForensicMetadata(entities) {
    const panel = document.getElementById('forensicMetadataPanel');
    const list = document.getElementById('forensicMetadataList');
    const badge = document.getElementById('forensicServerCount');

    // Find servers with forensic_metadata
    const serversWithMetadata = entities?.servers?.filter(s => s.forensic_metadata) || [];

    if (serversWithMetadata.length === 0) {
        panel.style.display = 'none';
        return;
    }

    panel.style.display = 'block';
    badge.textContent = serversWithMetadata.length;

    list.innerHTML = serversWithMetadata.map(server => {
        const fm = server.forensic_metadata;
        const serverName = server.display_name || server.name;
        const serverType = server.server_type;

        let sectionsHtml = '';

        // Identity Info Section
        if (fm.identity_info && Object.keys(fm.identity_info).length > 0) {
            const identity = fm.identity_info;
            sectionsHtml += `
                <div class="forensic-section">
                    <div class="forensic-section-header">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                            <circle cx="12" cy="7" r="4"/>
                        </svg>
                        Identity Info
                    </div>
                    <div class="forensic-section-content">
                        ${identity.name ? `<div class="forensic-item"><span class="label">Name:</span> ${escapeHtml(identity.name)}</div>` : ''}
                        ${identity.id ? `<div class="forensic-item"><span class="label">ID:</span> <code>${escapeHtml(identity.id)}</code></div>` : ''}
                        ${identity.email ? `<div class="forensic-item"><span class="label">Email:</span> ${escapeHtml(identity.email)}</div>` : ''}
                        ${identity.type ? `<div class="forensic-item"><span class="label">Type:</span> ${escapeHtml(identity.type)}</div>` : ''}
                    </div>
                </div>`;
        }

        // Bot User (Notion specific)
        if (fm.bot_user) {
            const bot = fm.bot_user;
            sectionsHtml += `
                <div class="forensic-section">
                    <div class="forensic-section-header">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                        </svg>
                        Bot User
                    </div>
                    <div class="forensic-section-content">
                        ${bot.name ? `<div class="forensic-item"><span class="label">Name:</span> ${escapeHtml(bot.name)}</div>` : ''}
                        ${bot.id ? `<div class="forensic-item"><span class="label">ID:</span> <code>${escapeHtml(bot.id)}</code></div>` : ''}
                        ${bot.avatar_url ? `<div class="forensic-item avatar-item"><span class="label">Avatar:</span> <img src="${escapeHtml(bot.avatar_url)}" alt="avatar" class="bot-avatar"/></div>` : ''}
                    </div>
                </div>`;
        }

        // Teams Section
        if (fm.teams && fm.teams.length > 0) {
            const teamsHtml = fm.teams.map(team => `
                <div class="forensic-list-item">
                    <span class="item-name">${escapeHtml(team.name || 'Unknown')}</span>
                    ${team.role ? `<span class="item-badge role">${escapeHtml(team.role)}</span>` : ''}
                    ${team.id ? `<span class="item-id">${escapeHtml(team.id.substring(0, 8))}...</span>` : ''}
                </div>
            `).join('');

            sectionsHtml += `
                <div class="forensic-section">
                    <div class="forensic-section-header">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
                            <circle cx="9" cy="7" r="4"/>
                            <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
                            <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
                        </svg>
                        Teams/Workspaces (${fm.teams.length})
                    </div>
                    <div class="forensic-section-content">
                        ${teamsHtml}
                    </div>
                </div>`;
        }

        // Tool Calls Section
        if (fm.tool_calls && fm.tool_calls.length > 0) {
            const toolCallsHtml = fm.tool_calls.slice(0, 10).map(tc => `
                <div class="forensic-list-item">
                    <span class="item-name tool-name">${escapeHtml(tc.tool)}</span>
                    ${tc.has_result ? '<span class="item-badge success">OK</span>' : '<span class="item-badge error">No Result</span>'}
                    ${tc.arguments && Object.keys(tc.arguments).length > 0 ?
                        `<span class="item-args">${escapeHtml(JSON.stringify(tc.arguments).substring(0, 50))}...</span>` : ''}
                </div>
            `).join('');

            sectionsHtml += `
                <div class="forensic-section">
                    <div class="forensic-section-header">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
                        </svg>
                        Tool Calls (${fm.tool_calls.length})
                    </div>
                    <div class="forensic-section-content">
                        ${toolCallsHtml}
                        ${fm.tool_calls.length > 10 ? `<div class="more-items">+${fm.tool_calls.length - 10} more...</div>` : ''}
                    </div>
                </div>`;
        }

        // Accessed Resources Section
        if (fm.accessed_resources && fm.accessed_resources.length > 0) {
            const resourcesHtml = fm.accessed_resources.slice(0, 10).map(res => `
                <div class="forensic-list-item">
                    ${res.title ? `<span class="item-name">${escapeHtml(res.title)}</span>` : ''}
                    ${res.type ? `<span class="item-badge">${escapeHtml(res.type)}</span>` : ''}
                    ${res.url ? `<a href="${escapeHtml(res.url)}" target="_blank" class="item-link">Link</a>` : ''}
                </div>
            `).join('');

            sectionsHtml += `
                <div class="forensic-section">
                    <div class="forensic-section-header">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                            <polyline points="14 2 14 8 20 8"/>
                        </svg>
                        Accessed Resources (${fm.accessed_resources.length})
                    </div>
                    <div class="forensic-section-content">
                        ${resourcesHtml}
                        ${fm.accessed_resources.length > 10 ? `<div class="more-items">+${fm.accessed_resources.length - 10} more...</div>` : ''}
                    </div>
                </div>`;
        }

        // Accessed Pages (Notion specific)
        if (fm.accessed_pages && fm.accessed_pages.length > 0) {
            const pagesHtml = fm.accessed_pages.slice(0, 10).map(page => `
                <div class="forensic-list-item">
                    <span class="item-name">${escapeHtml(page.title || 'Untitled')}</span>
                    ${page.type ? `<span class="item-badge">${escapeHtml(page.type)}</span>` : ''}
                    ${page.url ? `<a href="${escapeHtml(page.url)}" target="_blank" class="item-link">Open</a>` : ''}
                </div>
            `).join('');

            sectionsHtml += `
                <div class="forensic-section">
                    <div class="forensic-section-header">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/>
                            <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>
                        </svg>
                        Accessed Pages (${fm.accessed_pages.length})
                    </div>
                    <div class="forensic-section-content">
                        ${pagesHtml}
                        ${fm.accessed_pages.length > 10 ? `<div class="more-items">+${fm.accessed_pages.length - 10} more...</div>` : ''}
                    </div>
                </div>`;
        }

        // Sensitive Data Section
        if (fm.sensitive_data && fm.sensitive_data.length > 0) {
            const sensitiveHtml = fm.sensitive_data.map(item => `
                <div class="forensic-list-item sensitive">
                    <span class="item-badge warning">${escapeHtml(item.type)}</span>
                    <span class="item-value">${escapeHtml(item.value)}</span>
                    <span class="item-source">from: ${escapeHtml(item.source_tool)}</span>
                </div>
            `).join('');

            sectionsHtml += `
                <div class="forensic-section warning">
                    <div class="forensic-section-header">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                        Sensitive Data Detected (${fm.sensitive_data.length})
                    </div>
                    <div class="forensic-section-content">
                        ${sensitiveHtml}
                    </div>
                </div>`;
        }

        const typeClass = serverType === 'official_remote' ? 'official' : 'remote';

        return `
            <div class="forensic-server-card">
                <div class="forensic-server-header">
                    <div class="server-info">
                        <span class="server-name">${escapeHtml(serverName)}</span>
                        <span class="type-badge ${typeClass}">${serverType}</span>
                    </div>
                    ${server.version ? `<span class="server-version">v${escapeHtml(server.version)}</span>` : ''}
                </div>
                <div class="forensic-sections">
                    ${sectionsHtml}
                </div>
            </div>
        `;
    }).join('');
}

function updateServerFilter(entities, timeline) {
    const serverFilter = document.getElementById('serverFilter');
    if (!serverFilter) return;

    // Collect confirmed servers from entities (these are the canonical names)
    const confirmedServers = new Set();
    entities?.servers?.forEach(server => {
        if (server.name) confirmedServers.add(server.name);
    });

    // Build a mapping from canonical patterns to confirmed server names
    // e.g., "notion" -> "user-Notion", "filesystem" -> "user-filesystem"
    const canonicalToConfirmed = {};
    const patterns = ['notion', 'filesystem', 'github', 'git', 'browser', 'slack',
                      'database', 'search', 'memory', 'fetch', 'docker', 'kubernetes', 'aws', 'obsidian'];

    confirmedServers.forEach(serverName => {
        const serverLower = serverName.toLowerCase();
        patterns.forEach(pattern => {
            if (serverLower.includes(pattern)) {
                canonicalToConfirmed[pattern] = serverName;
            }
        });
    });

    // Collect all server names and normalize them
    const serverSet = new Set(confirmedServers);

    timeline?.events?.forEach(event => {
        const processServerName = (name) => {
            if (!name) return;

            // Remove (estimated) suffix
            const baseName = name.replace(' (estimated)', '').toLowerCase();

            // Try to map to confirmed server
            let mapped = false;
            for (const [pattern, confirmed] of Object.entries(canonicalToConfirmed)) {
                if (baseName.includes(pattern) || pattern.includes(baseName)) {
                    serverSet.add(confirmed);
                    mapped = true;
                    break;
                }
            }

            // If no mapping found and it's not a weird fragment, add as-is
            if (!mapped && baseName.length > 2 && !['mcp', 'server', 'remote', 'local'].includes(baseName)) {
                serverSet.add(name.replace(' (estimated)', ''));
            }
        };

        processServerName(event.server_name);
        event.details?.mcp_servers_used?.forEach(processServerName);
    });

    // Build dropdown with confirmed servers first, then others
    serverFilter.innerHTML = '<option value="">All Servers</option>';
    const sortedServers = Array.from(serverSet).sort((a, b) => {
        // Confirmed servers first
        const aConfirmed = confirmedServers.has(a);
        const bConfirmed = confirmedServers.has(b);
        if (aConfirmed && !bConfirmed) return -1;
        if (!aConfirmed && bConfirmed) return 1;
        return a.localeCompare(b);
    });

    sortedServers.forEach(serverName => {
        serverFilter.innerHTML += `<option value="${serverName}">${serverName}</option>`;
    });
}

function displayRawJson(result) {
    const jsonViewer = document.getElementById('jsonViewer');
    if (jsonViewer) {
        jsonViewer.textContent = JSON.stringify(result, null, 2);
    }
}

function copyJson() {
    if (analysisResult) {
        navigator.clipboard.writeText(JSON.stringify(analysisResult, null, 2));
        // Could add a toast notification here
    }
}

function downloadJson() {
    if (analysisResult) {
        const blob = new Blob([JSON.stringify(analysisResult, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'mcp-forensics-analysis.json';
        a.click();
        URL.revokeObjectURL(url);
    }
}

// Loading & Errors
function showLoading(show) {
    loading.style.display = show ? 'flex' : 'none';
}

function showError(message) {
    errorMessage.textContent = message;
    errorToast.style.display = 'flex';
    setTimeout(hideError, 5000);
}

function hideError() {
    errorToast.style.display = 'none';
}

// Default Comparison
async function loadDefaultComparison() {
    try {
        const response = await fetch(`${API_BASE}/api/comparison/matrix`);
        if (response.ok) {
            const data = await response.json();
            displayComparisonMatrix(data);
        }
    } catch (error) {
        console.log('Could not load default comparison:', error);
    }
}

function displayComparisonMatrix(data) {
    if (data.artifact_availability) {
        const tbody = document.querySelector('#artifactMatrix tbody');
        if (tbody) {
            tbody.innerHTML = '';
            for (const [artifact, values] of Object.entries(data.artifact_availability)) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${formatName(artifact)}</td>
                    <td class="${getAvailClass(values['Local STDIO'])}">${values['Local STDIO']}</td>
                    <td class="${getAvailClass(values['Custom Remote'])}">${values['Custom Remote']}</td>
                    <td class="${getAvailClass(values['Official Remote'])}">${values['Official Remote']}</td>
                `;
                tbody.appendChild(row);
            }
        }
    }

    if (data.forensic_capabilities) {
        const tbody = document.querySelector('#capabilityMatrix tbody');
        if (tbody) {
            tbody.innerHTML = '';
            for (const [cap, values] of Object.entries(data.forensic_capabilities)) {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${formatName(cap)}</td>
                    <td class="${getCapClass(values['Local STDIO'])}">${values['Local STDIO']}</td>
                    <td class="${getCapClass(values['Custom Remote'])}">${values['Custom Remote']}</td>
                    <td class="${getCapClass(values['Official Remote'])}">${values['Official Remote']}</td>
                `;
                tbody.appendChild(row);
            }
        }
    }
}

function getAvailClass(value) {
    if (!value) return '';
    const lower = value.toLowerCase();
    if (lower === 'full') return 'avail-full';
    if (lower.includes('partial')) return 'avail-partial';
    if (lower === 'none') return 'avail-none';
    return '';
}

function getCapClass(value) {
    if (!value) return '';
    const lower = value.toLowerCase();
    if (lower === 'high') return 'cap-high';
    if (lower === 'medium') return 'cap-medium';
    if (lower === 'low') return 'cap-low';
    return '';
}

function formatName(name) {
    return name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// Conversations Display
let allConversations = [];
let filteredConversations = [];

function displayConversations(vscdbAnalysis) {
    const conversations = vscdbAnalysis.conversations || [];
    allConversations = conversations;
    filteredConversations = [...conversations];

    // Update stats
    const totalMessages = conversations.reduce((acc, conv) => acc + (conv.messages?.length || 0), 0);
    const userQueries = conversations.reduce((acc, conv) =>
        acc + (conv.messages?.filter(m => m.type === 1).length || 0), 0);
    const aiResponses = conversations.reduce((acc, conv) =>
        acc + (conv.messages?.filter(m => m.type === 2).length || 0), 0);

    document.getElementById('convCount').textContent = conversations.length;
    document.getElementById('queryCount').textContent = userQueries;
    document.getElementById('responseCount').textContent = aiResponses;

    // Populate conversation filter
    const conversationFilter = document.getElementById('conversationFilter');
    conversationFilter.innerHTML = '<option value="">All Conversations</option>';
    conversations.forEach((conv, index) => {
        const firstMsg = conv.messages?.[0];
        const preview = firstMsg?.text?.substring(0, 30) || `Conversation ${index + 1}`;
        conversationFilter.innerHTML += `<option value="${conv.conversation_id}">${preview}...</option>`;
    });

    // Add filter event listener
    conversationFilter.addEventListener('change', filterConversations);

    renderConversations();
}

function filterConversations() {
    const filterValue = document.getElementById('conversationFilter').value;

    if (filterValue) {
        filteredConversations = allConversations.filter(conv => conv.conversation_id === filterValue);
    } else {
        filteredConversations = [...allConversations];
    }

    renderConversations();
}

function renderConversations() {
    const conversationsView = document.getElementById('conversationsView');

    if (filteredConversations.length === 0) {
        conversationsView.innerHTML = `
            <div class="empty-state">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
                </svg>
                <p>No conversations found</p>
            </div>`;
        return;
    }

    conversationsView.innerHTML = filteredConversations.map(conv => {
        const messages = conv.messages || [];
        const messagesHtml = messages.map(msg => {
            const isUser = msg.type === 1;
            const msgClass = isUser ? 'user' : 'assistant';
            const label = isUser ? 'User' : 'AI';
            const time = formatConversationTime(msg.timestamp);
            const text = formatMessageText(msg.text || '');

            let thinkingHtml = '';
            if (msg.thinking) {
                const thinkingText = msg.thinking.length > 500
                    ? msg.thinking.substring(0, 500) + '...'
                    : msg.thinking;
                thinkingHtml = `
                    <div class="thinking-block">
                        <div class="thinking-label">Reasoning</div>
                        <div class="thinking-content">${escapeHtml(thinkingText)}</div>
                    </div>`;
            }

            let toolsHtml = '';
            if (msg.tool_results_count > 0) {
                toolsHtml = `<div class="tool-indicator">${msg.tool_results_count} tool call${msg.tool_results_count > 1 ? 's' : ''}</div>`;
            }

            let modelHtml = '';
            if (msg.model_name && msg.model_name !== 'default' && !isUser) {
                modelHtml = `<span class="model-badge">${msg.model_name}</span>`;
            }

            return `
                <div class="message ${msgClass}">
                    <div class="message-header">
                        <span class="message-role">${label}</span>
                        ${modelHtml}
                        <span class="message-time">${time}</span>
                    </div>
                    <div class="message-content">${text}</div>
                    ${thinkingHtml}
                    ${toolsHtml}
                </div>`;
        }).join('');

        return `
            <div class="conversation-group">
                <div class="conversation-header">
                    <span class="conversation-id">Conversation: ${conv.conversation_id?.substring(0, 8) || 'Unknown'}...</span>
                    <span class="message-count">${messages.length} messages</span>
                </div>
                <div class="messages-container">
                    ${messagesHtml}
                </div>
            </div>`;
    }).join('');
}

function formatConversationTime(timestamp) {
    if (!timestamp) return '';
    try {
        const date = new Date(timestamp);
        return date.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch {
        return '';
    }
}

function formatMessageText(text) {
    if (!text) return '<em>No content</em>';
    // Escape HTML and preserve newlines
    const escaped = escapeHtml(text);
    return escaped.replace(/\n/g, '<br>');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
