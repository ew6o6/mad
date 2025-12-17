/**
 * MCP Forensics Analyzer - Comparison Module
 * Local vs Remote MCP Comparison Analysis
 */

/**
 * Display comparison analysis results
 */
function displayComparison(comparison) {
    if (!comparison) return;

    // Display artifact matrix
    displayArtifactMatrix(comparison.artifact_matrix);

    // Display capability matrix
    displayCapabilityMatrix(comparison.capability_matrix);

    // Display findings
    displayFindings(comparison.findings);

    // Display recommendations
    displayRecommendations(comparison.recommendations);
}

/**
 * Display artifact availability matrix
 */
function displayArtifactMatrix(matrix) {
    if (!matrix) return;

    const tbody = document.querySelector('#artifactMatrix tbody');
    tbody.innerHTML = '';

    // Get all server names
    const serverNames = new Set();
    for (const values of Object.values(matrix)) {
        Object.keys(values).forEach(name => serverNames.add(name));
    }
    const servers = Array.from(serverNames);

    // Update header
    const thead = document.querySelector('#artifactMatrix thead tr');
    thead.innerHTML = '<th>Artifact</th>';
    servers.forEach(server => {
        thead.innerHTML += `<th>${formatServerName(server)}</th>`;
    });

    // Add rows
    for (const [artifact, values] of Object.entries(matrix)) {
        const row = document.createElement('tr');
        row.innerHTML = `<td>${formatArtifactName(artifact)}</td>`;

        servers.forEach(server => {
            const value = values[server] || 'unknown';
            row.innerHTML += `<td class="${getAvailabilityClass(value)}">${formatAvailability(value)}</td>`;
        });

        tbody.appendChild(row);
    }
}

/**
 * Display forensic capability matrix
 */
function displayCapabilityMatrix(matrix) {
    if (!matrix) return;

    const tbody = document.querySelector('#capabilityMatrix tbody');
    tbody.innerHTML = '';

    // Get all server names
    const serverNames = new Set();
    for (const values of Object.values(matrix)) {
        Object.keys(values).forEach(name => serverNames.add(name));
    }
    const servers = Array.from(serverNames);

    // Update header
    const thead = document.querySelector('#capabilityMatrix thead tr');
    thead.innerHTML = '<th>Capability</th>';
    servers.forEach(server => {
        thead.innerHTML += `<th>${formatServerName(server)}</th>`;
    });

    // Add rows
    for (const [capability, values] of Object.entries(matrix)) {
        const row = document.createElement('tr');
        row.innerHTML = `<td>${formatCapabilityName(capability)}</td>`;

        servers.forEach(server => {
            const value = values[server] || 'unknown';
            row.innerHTML += `<td class="${getCapabilityClass(value)}">${formatCapability(value)}</td>`;
        });

        tbody.appendChild(row);
    }
}

/**
 * Display findings
 */
function displayFindings(findings) {
    const list = document.getElementById('findingsList');

    if (!findings || findings.length === 0) {
        list.innerHTML = '<li>No significant findings</li>';
        return;
    }

    list.innerHTML = findings.map(finding => `<li>${finding}</li>`).join('');
}

/**
 * Display recommendations
 */
function displayRecommendations(recommendations) {
    const list = document.getElementById('recommendationsList');

    if (!recommendations || recommendations.length === 0) {
        list.innerHTML = '<li>No specific recommendations</li>';
        return;
    }

    list.innerHTML = recommendations.map(rec => `<li>${rec}</li>`).join('');
}

// ==================== Formatting Helpers ====================

function formatServerName(name) {
    const names = {
        'local': 'Local STDIO',
        'custom_remote': 'Custom Remote',
        'official_remote': 'Official Remote',
        'default_local': 'Local STDIO',
        'default_custom_remote': 'Custom Remote',
        'default_official_remote': 'Official Remote'
    };
    return names[name] || name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function formatArtifactName(name) {
    const names = {
        'mcp_config': 'MCP Config',
        'cursor_main_log': 'Cursor Main Log',
        'cursor_ext_log': 'Cursor Extension Log',
        'server_request_log': 'Server Request Log',
        'server_response_log': 'Server Response Log',
        'file_access_log': 'File Access Log',
        'network_capture': 'Network Capture',
        'session_id': 'Session ID',
        'json_rpc_trace': 'JSON-RPC Trace',
        'tool_definitions': 'Tool Definitions',
        'error_log': 'Error Log'
    };
    return names[name] || name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function formatCapabilityName(name) {
    const names = {
        'timeline_reconstruction': 'Timeline Reconstruction',
        'action_attribution': 'Action Attribution',
        'data_exfiltration_tracking': 'Data Exfiltration Tracking',
        'tool_usage_analysis': 'Tool Usage Analysis',
        'session_correlation': 'Session Correlation',
        'error_analysis': 'Error Analysis',
        'security_event_detection': 'Security Event Detection'
    };
    return names[name] || name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function formatAvailability(value) {
    const formats = {
        'full': 'Full',
        'partial': 'Partial',
        'none': 'None',
        'unknown': 'Unknown'
    };
    return formats[value] || value;
}

function formatCapability(value) {
    const formats = {
        'high': 'High',
        'medium': 'Medium',
        'low': 'Low',
        'none': 'None',
        'unknown': 'Unknown'
    };
    return formats[value] || value;
}

function getAvailabilityClass(value) {
    const classes = {
        'full': 'avail-full',
        'partial': 'avail-partial',
        'none': 'avail-none'
    };
    return classes[value] || '';
}

function getCapabilityClass(value) {
    const classes = {
        'high': 'cap-high',
        'medium': 'cap-medium',
        'low': 'cap-low',
        'none': 'cap-low'
    };
    return classes[value] || '';
}

// ==================== Comparison Analysis ====================

/**
 * Generate comparison summary
 */
function generateComparisonSummary(comparison) {
    if (!comparison) return null;

    const summary = {
        totalArtifacts: Object.keys(comparison.artifact_matrix || {}).length,
        totalCapabilities: Object.keys(comparison.capability_matrix || {}).length,
        findingsCount: (comparison.findings || []).length,
        recommendationsCount: (comparison.recommendations || []).length,
        serverComparison: {}
    };

    // Calculate coverage per server type
    const serverTypes = new Set();
    for (const values of Object.values(comparison.artifact_matrix || {})) {
        Object.keys(values).forEach(name => serverTypes.add(name));
    }

    serverTypes.forEach(server => {
        let fullCount = 0;
        let partialCount = 0;
        let noneCount = 0;

        for (const values of Object.values(comparison.artifact_matrix || {})) {
            const value = values[server];
            if (value === 'full') fullCount++;
            else if (value === 'partial') partialCount++;
            else if (value === 'none') noneCount++;
        }

        summary.serverComparison[server] = {
            full: fullCount,
            partial: partialCount,
            none: noneCount,
            coverage: summary.totalArtifacts > 0
                ? ((fullCount + partialCount * 0.5) / summary.totalArtifacts * 100).toFixed(1)
                : 0
        };
    });

    return summary;
}

/**
 * Export comparison as report
 */
function exportComparisonReport(comparison) {
    if (!comparison) {
        alert('No comparison data to export');
        return;
    }

    const report = {
        title: 'MCP Forensics Comparison Report',
        generated: new Date().toISOString(),
        platform: 'Cursor IDE',
        framework: 'MCP Forensics Analyzer',
        artifact_availability: comparison.artifact_matrix,
        forensic_capabilities: comparison.capability_matrix,
        findings: comparison.findings,
        recommendations: comparison.recommendations,
        summary: generateComparisonSummary(comparison)
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'mcp-comparison-report.json';
    a.click();
    URL.revokeObjectURL(url);
}
