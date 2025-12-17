/**
 * MCP Forensics Analyzer - Timeline Module
 */

// Timeline state
let allEvents = [];
let filteredEvents = [];

// Initialize timeline filters
document.addEventListener('DOMContentLoaded', () => {
    const serverFilter = document.getElementById('serverFilter');
    const eventTypeFilter = document.getElementById('eventTypeFilter');

    serverFilter.addEventListener('change', filterEvents);
    eventTypeFilter.addEventListener('change', filterEvents);
});

/**
 * Display timeline from analysis result
 */
function displayTimeline(timeline) {
    allEvents = timeline.events || [];
    filteredEvents = [...allEvents];
    renderTimeline();
}

/**
 * Filter events based on selected criteria
 */
function filterEvents() {
    const serverFilter = document.getElementById('serverFilter').value;
    const eventTypeFilter = document.getElementById('eventTypeFilter').value;

    filteredEvents = allEvents.filter(event => {
        // Server filter - check both server_name and details.mcp_servers_used
        if (serverFilter) {
            const eventServerName = event.server_name || '';
            const mcpServersUsed = event.details?.mcp_servers_used || [];

            // Extract canonical pattern from filter (e.g., "user-Notion" -> "notion")
            const filterLower = serverFilter.toLowerCase();
            const patterns = ['notion', 'filesystem', 'github', 'git', 'browser', 'slack',
                              'database', 'search', 'memory', 'fetch', 'docker', 'kubernetes', 'aws', 'obsidian'];
            const matchPattern = patterns.find(p => filterLower.includes(p));

            // Check if any server matches
            const matchesServer = (name) => {
                if (!name) return false;
                const nameLower = name.toLowerCase().replace(' (estimated)', '');
                // Exact match
                if (name === serverFilter || nameLower === filterLower) return true;
                // Pattern match (e.g., "user-Notion" matches "notion (estimated)")
                if (matchPattern && nameLower.includes(matchPattern)) return true;
                return false;
            };

            const serverMatches = matchesServer(eventServerName) ||
                mcpServersUsed.some(s => matchesServer(s));

            if (!serverMatches) {
                return false;
            }
        }

        // Event type filter
        if (eventTypeFilter && event.event_type !== eventTypeFilter) {
            return false;
        }

        return true;
    });

    renderTimeline();
}

/**
 * Check if event has meaningful content to display
 */
function hasMeaningfulContent(event) {
    // Check for conversation text
    if (event.details?.text && event.details.text.trim().length > 0) {
        return true;
    }

    // Check for tool call info
    if (event.arguments || event.result !== undefined || event.tool_name) {
        return true;
    }

    // Check for user intent info (from HAR analysis)
    if (event.user_intent || event.query_text || event.result_summary) {
        return true;
    }

    // Check for file access info
    if (event.path || event.url) {
        return true;
    }

    // Check for error info
    if (event.error_message) {
        return true;
    }

    // Check for model name (non-default)
    if (event.details?.model_name && event.details.model_name !== 'default') {
        return true;
    }

    return false;
}

/**
 * Render timeline events
 */
function renderTimeline() {
    const timelineView = document.getElementById('timelineView');

    // Filter out events without meaningful content
    const meaningfulEvents = filteredEvents.filter(hasMeaningfulContent);

    if (meaningfulEvents.length === 0) {
        timelineView.innerHTML = '<p class="no-data">No events to display</p>';
        return;
    }

    timelineView.innerHTML = meaningfulEvents.map((event, index) => {
        const eventClass = event.event_type.replace('_', '-');
        const time = formatTimestamp(event.timestamp);
        const eventType = formatEventType(event.event_type);
        const { shortDetails, fullDetails, needsExpand } = formatEventDetailsWithExpand(event);

        // Collect all server references (deduplicated)
        const serverSet = new Set();
        if (event.server_name) serverSet.add(event.server_name);
        (event.details?.mcp_servers_used || []).forEach(s => serverSet.add(s));

        // Build server label
        let serverLabel = '';
        if (serverSet.size > 0) {
            const servers = Array.from(serverSet);
            const isEstimated = servers.some(s => s.includes('(estimated)'));
            const labelClass = isEstimated ? 'mcp-server-tag estimated' : 'mcp-server-tag';
            serverLabel = `<span class="${labelClass}">${servers.join(', ')}</span>`;
        }

        // Build user intent section for tool calls
        const intentSection = buildIntentSection(event);

        return `
            <div class="timeline-event ${eventClass}">
                <div class="time">${time}</div>
                <div class="content">
                    <div class="event-header">
                        <span class="event-type">${eventType}</span>
                        ${serverLabel}
                    </div>
                    ${event.tool_name ? `<div class="tool-name">Tool: ${event.tool_name}</div>` : ''}
                    ${intentSection}
                    <div class="event-details" id="details-short-${index}">${shortDetails}</div>
                    ${needsExpand ? `
                        <div class="event-details-full" id="details-full-${index}" style="display:none;">${fullDetails}</div>
                        <button class="expand-btn" onclick="toggleEventDetails(${index})">
                            <span class="expand-text">Show more</span>
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="6 9 12 15 18 9"/>
                            </svg>
                        </button>
                    ` : ''}
                </div>
            </div>
        `;
    }).join('');
}

/**
 * Build user intent section for tool call events
 */
function buildIntentSection(event) {
    // Only for tool_call events with intent info
    if (event.event_type !== 'tool_call') {
        return '';
    }

    const parts = [];

    // User intent (WHY)
    if (event.user_intent) {
        parts.push(`
            <div class="intent-item intent-why">
                <span class="intent-label">Intent:</span>
                <span class="intent-value">${escapeHtml(event.user_intent)}</span>
            </div>
        `);
    }

    // Query text (WHAT - search query etc)
    if (event.query_text) {
        parts.push(`
            <div class="intent-item intent-query">
                <span class="intent-label">Query:</span>
                <span class="intent-value query-text">"${escapeHtml(event.query_text)}"</span>
            </div>
        `);
    }

    // Result summary (OUTCOME)
    if (event.result_summary) {
        const countBadge = event.result_count !== null && event.result_count !== undefined
            ? `<span class="result-count-badge">${event.result_count}</span>`
            : '';
        parts.push(`
            <div class="intent-item intent-result">
                <span class="intent-label">Result:</span>
                ${countBadge}
                <span class="intent-value">${escapeHtml(event.result_summary)}</span>
            </div>
        `);
    }

    if (parts.length === 0) {
        return '';
    }

    return `<div class="intent-section">${parts.join('')}</div>`;
}

/**
 * Format timestamp for display
 */
function formatTimestamp(timestamp) {
    if (!timestamp) return '--:--:--';

    try {
        const date = new Date(timestamp);
        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    } catch {
        return timestamp;
    }
}

/**
 * Format event type for display
 */
function formatEventType(eventType) {
    const types = {
        'connection_init': 'Connection Initialize',
        'connection_ready': 'Connection Ready',
        'connection_close': 'Connection Close',
        'connection_error': 'Connection Error',
        'tool_list': 'Tool List',
        'tool_call': 'Tool Call',
        'tool_result': 'Tool Result',
        'tool_error': 'Tool Error',
        'resource_list': 'Resource List',
        'resource_read': 'Resource Read',
        'file_access': 'File Access',
        'file_access_denied': 'File Access Denied',
        'http_request': 'HTTP Request',
        'http_response': 'HTTP Response',
        'notification': 'Notification',
        'user_query': 'User Query',
        'ai_response': 'AI Response',
        'unknown': 'Unknown'
    };
    return types[eventType] || eventType;
}

/**
 * Toggle event details expand/collapse
 */
function toggleEventDetails(index) {
    const shortEl = document.getElementById(`details-short-${index}`);
    const fullEl = document.getElementById(`details-full-${index}`);
    const btn = shortEl.parentElement.querySelector('.expand-btn');
    const btnText = btn.querySelector('.expand-text');
    const btnSvg = btn.querySelector('svg');

    if (fullEl.style.display === 'none') {
        shortEl.style.display = 'none';
        fullEl.style.display = 'block';
        btnText.textContent = 'Show less';
        btnSvg.style.transform = 'rotate(180deg)';
    } else {
        shortEl.style.display = 'block';
        fullEl.style.display = 'none';
        btnText.textContent = 'Show more';
        btnSvg.style.transform = 'rotate(0deg)';
    }
}

/**
 * Format event details with expand support
 */
function formatEventDetailsWithExpand(event) {
    const SHORT_LIMIT = 150;
    let fullText = '';
    let shortText = '';
    let needsExpand = false;

    // VSCDB conversation events (user_query, ai_response)
    if (event.details?.text) {
        const rawText = event.details.text;
        const escapedFull = escapeHtml(rawText);

        if (rawText.length > SHORT_LIMIT) {
            shortText = escapeHtml(rawText.substring(0, SHORT_LIMIT)) + '...';
            fullText = `<div class="full-text-content">${escapedFull}</div>`;
            needsExpand = true;
        } else {
            shortText = escapedFull;
            fullText = escapedFull;
        }

        // Add metadata
        const meta = [];
        if (event.details.model_name && event.details.model_name !== 'default') {
            meta.push(`Model: ${event.details.model_name}`);
        }
        if (event.details.is_agentic) {
            meta.push('Agentic');
        }
        if (event.details.tool_results_count > 0) {
            meta.push(`Tools: ${event.details.tool_results_count}`);
        }
        // Show MCP tool calls if available
        if (event.details.mcp_tool_calls?.length > 0) {
            const toolNames = event.details.mcp_tool_calls.map(tc => tc.tool_name).join(', ');
            meta.push(`MCP Tools: ${toolNames}`);
        }
        if (meta.length > 0) {
            const metaStr = `<div class="event-meta">${meta.join(' | ')}</div>`;
            shortText = shortText + metaStr;
            fullText = fullText + metaStr;
        }

        return { shortDetails: shortText, fullDetails: fullText, needsExpand };
    }

    // Tool call arguments
    if (event.arguments) {
        const argStr = JSON.stringify(event.arguments, null, 2);
        fullText = `<pre class="code-block">${escapeHtml(argStr)}</pre>`;
        if (argStr.length > SHORT_LIMIT) {
            shortText = `Args: ${argStr.substring(0, SHORT_LIMIT)}...`;
            needsExpand = true;
        } else {
            shortText = `Args: ${argStr}`;
        }
        return { shortDetails: shortText, fullDetails: fullText, needsExpand };
    }

    // Tool result
    if (event.result !== undefined && event.result !== null) {
        const resultStr = typeof event.result === 'object'
            ? JSON.stringify(event.result, null, 2)
            : String(event.result);
        fullText = `<pre class="code-block">${escapeHtml(resultStr)}</pre>`;
        if (resultStr.length > SHORT_LIMIT) {
            shortText = `Result: ${resultStr.substring(0, SHORT_LIMIT)}...`;
            needsExpand = true;
        } else {
            shortText = `Result: ${resultStr}`;
        }
        return { shortDetails: shortText, fullDetails: fullText, needsExpand };
    }

    // Other details - just build simple text
    const parts = [];
    if (event.error_message) parts.push(`Error: ${event.error_message}`);
    if (event.path) parts.push(`Path: ${event.path}`);
    if (event.url) parts.push(`URL: ${event.url}`);
    if (event.status_code) parts.push(`Status: ${event.status_code}`);

    shortText = parts.join(' | ') || '';
    return { shortDetails: shortText, fullDetails: shortText, needsExpand: false };
}

/**
 * Escape HTML characters
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Export timeline as CSV
 */
function exportTimelineCSV() {
    if (filteredEvents.length === 0) {
        alert('No events to export');
        return;
    }

    const headers = ['Timestamp', 'Event Type', 'Server', 'Tool', 'Severity', 'Details'];
    const rows = filteredEvents.map(event => [
        event.timestamp,
        event.event_type,
        event.server_name || '',
        event.tool_name || '',
        event.severity || '',
        JSON.stringify(event.details || {})
    ]);

    const csv = [headers, ...rows]
        .map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
        .join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'mcp-timeline.csv';
    a.click();
    URL.revokeObjectURL(url);
}

/**
 * Get timeline summary statistics
 */
function getTimelineSummary() {
    if (allEvents.length === 0) {
        return null;
    }

    const summary = {
        totalEvents: allEvents.length,
        eventsByType: {},
        eventsByServer: {},
        eventsBySeverity: {},
        timeRange: {
            start: null,
            end: null
        }
    };

    allEvents.forEach(event => {
        // By type
        summary.eventsByType[event.event_type] =
            (summary.eventsByType[event.event_type] || 0) + 1;

        // By server
        if (event.server_name) {
            summary.eventsByServer[event.server_name] =
                (summary.eventsByServer[event.server_name] || 0) + 1;
        }

        // By severity
        if (event.severity) {
            summary.eventsBySeverity[event.severity] =
                (summary.eventsBySeverity[event.severity] || 0) + 1;
        }

        // Time range
        if (event.timestamp) {
            const ts = new Date(event.timestamp);
            if (!summary.timeRange.start || ts < summary.timeRange.start) {
                summary.timeRange.start = ts;
            }
            if (!summary.timeRange.end || ts > summary.timeRange.end) {
                summary.timeRange.end = ts;
            }
        }
    });

    return summary;
}
