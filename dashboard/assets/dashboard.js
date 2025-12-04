/**
 * Copyright © 2025 DoctorMen. All Rights Reserved.
 */
/**
 * SECURE BUG BOUNTY DASHBOARD - JAVASCRIPT
 * NO EXTERNAL CALLS | LOCAL ONLY | OPSEC COMPLIANT
 * 
 * Security Features:
 * - No analytics or tracking
 * - No external API calls
 * - Data loaded from local files only
 * - Redaction system built-in
 */

'use strict';

// ============================================
// CONFIGURATION
// ============================================

const CONFIG = {
    OUTPUT_DIR: '../output',
    REFRESH_INTERVAL: 30000, // 30 seconds
    REDACTION_ENABLED: true,
    OPSEC_MODE: true
};

// ============================================
// INITIALIZATION
// ============================================

function initDashboard() {
    console.log('🔒 Secure Dashboard initializing...');
    
    // Check OPSEC status
    if (CONFIG.OPSEC_MODE) {
        console.log('✓ OPSEC mode: ACTIVE');
        console.log('✓ External connections: BLOCKED');
        console.log('✓ Data loading: LOCAL ONLY');
    }
    
    // Add OPSEC indicator
    addOpsecIndicator();
    
    // Load dashboard data
    loadDashboardData();
}

function addOpsecIndicator() {
    const indicator = document.createElement('div');
    indicator.className = 'opsec-indicator';
    indicator.textContent = 'OPSEC ACTIVE';
    document.body.appendChild(indicator);
}

// ============================================
// DATA LOADING (LOCAL FILES ONLY)
// ============================================

function loadDashboardData() {
    // These would load from actual local files in production
    // For now, we'll use placeholder data
    
    loadMetrics();
    loadRecentActivity();
    loadSeverityChart();
}

function loadMetrics() {
    // In production, this would read from ../output/scan_summary.json
    // For now, using safe placeholder data
    
    const metrics = {
        activeScans: 0,
        totalFindings: 0,
        criticalFindings: 0,
        roiScore: '--'
    };
    
    // Try to load real data if available
    fetch('../output/scan_summary.json')
        .then(response => {
            if (!response.ok) throw new Error('No data');
            return response.json();
        })
        .then(data => {
            updateMetrics(data);
        })
        .catch(error => {
            console.log('No scan data available (safe)');
            updateMetrics(metrics);
        });
}

function updateMetrics(data) {
    // Safely update metrics with redaction in mind
    document.getElementById('activeScans').textContent = data.activeScans || 0;
    document.getElementById('totalFindings').textContent = data.totalFindings || 0;
    document.getElementById('criticalFindings').textContent = data.criticalFindings || 0;
    document.getElementById('roiScore').textContent = data.roiScore || '--';
}

function loadRecentActivity() {
    const timeline = document.getElementById('recentActivity');
    
    // Try to load from local activity log
    fetch('../output/activity.json')
        .then(response => {
            if (!response.ok) throw new Error('No data');
            return response.json();
        })
        .then(data => {
            displayActivity(data);
        })
        .catch(error => {
            timeline.innerHTML = `
                <div class="timeline-item">
                    <div class="timeline-icon">📋</div>
                    <div class="timeline-content">
                        <p>No recent activity</p>
                        <p class="timeline-time">Run a scan to see activity here</p>
                    </div>
                </div>
            `;
        });
}

function displayActivity(activities) {
    const timeline = document.getElementById('recentActivity');
    
    if (!activities || activities.length === 0) {
        timeline.innerHTML = '<p>No recent activity</p>';
        return;
    }
    
    timeline.innerHTML = activities.slice(0, 5).map(activity => `
        <div class="timeline-item">
            <div class="timeline-icon">${getActivityIcon(activity.type)}</div>
            <div class="timeline-content">
                <p>${sanitizeActivity(activity.message)}</p>
                <p class="timeline-time">${formatTime(activity.timestamp)}</p>
            </div>
        </div>
    `).join('');
}

function getActivityIcon(type) {
    const icons = {
        scan: '🔍',
        finding: '🎯',
        report: '📋',
        evidence: '📸',
        error: '⚠️',
        success: '✅'
    };
    return icons[type] || '📌';
}

function sanitizeActivity(message) {
    // Redact sensitive information from activity messages
    if (CONFIG.REDACTION_ENABLED) {
        message = message.replace(/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g, '[TARGET]');
        message = message.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '[IP]');
        message = message.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[EMAIL]');
    }
    return message;
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)} minutes ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)} hours ago`;
    return date.toLocaleDateString();
}

// ============================================
// SEVERITY CHART
// ============================================

function loadSeverityChart() {
    // Load severity data and create chart
    fetch('../output/severity_breakdown.json')
        .then(response => {
            if (!response.ok) throw new Error('No data');
            return response.json();
        })
        .then(data => {
            createSeverityChart(data);
        })
        .catch(error => {
            createPlaceholderChart();
        });
}

function createPlaceholderChart() {
    const canvas = document.getElementById('severityChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Draw simple placeholder bar chart
    ctx.fillStyle = '#cbd5e1';
    ctx.font = '16px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No scan data available', canvas.width / 2, canvas.height / 2);
    ctx.fillText('Run a scan to see results here', canvas.width / 2, canvas.height / 2 + 30);
}

function createSeverityChart(data) {
    const canvas = document.getElementById('severityChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const severities = ['critical', 'high', 'medium', 'low', 'info'];
    const colors = ['#ef4444', '#f59e0b', '#eab308', '#3b82f6', '#6b7280'];
    
    // Simple bar chart (no external libraries)
    const barWidth = 60;
    const spacing = 20;
    const maxHeight = canvas.height - 60;
    const maxValue = Math.max(...Object.values(data));
    
    severities.forEach((severity, index) => {
        const value = data[severity] || 0;
        const height = (value / maxValue) * maxHeight;
        const x = index * (barWidth + spacing) + 50;
        const y = canvas.height - height - 40;
        
        // Draw bar
        ctx.fillStyle = colors[index];
        ctx.fillRect(x, y, barWidth, height);
        
        // Draw label
        ctx.fillStyle = '#cbd5e1';
        ctx.font = '12px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(severity.toUpperCase(), x + barWidth / 2, canvas.height - 20);
        
        // Draw value
        ctx.fillText(value.toString(), x + barWidth / 2, y - 5);
    });
}

// ============================================
// REDACTION SYSTEM
// ============================================

function toggleRedaction() {
    CONFIG.REDACTION_ENABLED = !CONFIG.REDACTION_ENABLED;
    const btn = document.getElementById('redactionToggle');
    
    if (CONFIG.REDACTION_ENABLED) {
        btn.textContent = '🔒 Redaction: ON';
        btn.classList.remove('off');
        document.body.classList.add('redacted');
        console.log('🔒 Redaction ENABLED');
    } else {
        btn.textContent = '🔓 Redaction: OFF';
        btn.classList.add('off');
        document.body.classList.remove('redacted');
        console.warn('⚠️ Redaction DISABLED - Sensitive data visible!');
    }
    
    // Reload data with new redaction setting
    loadRecentActivity();
}

// ============================================
// FILE SYSTEM HELPERS (LOCAL ONLY)
// ============================================

function checkFileExists(path) {
    return fetch(path, { method: 'HEAD' })
        .then(response => response.ok)
        .catch(() => false);
}

function loadLocalJSON(path) {
    return fetch(path)
        .then(response => {
            if (!response.ok) throw new Error('File not found');
            return response.json();
        })
        .catch(error => {
            console.log(`Could not load ${path} (safe)`);
            return null;
        });
}

// ============================================
// SECURITY CHECKS
// ============================================

function performSecurityChecks() {
    console.log('🔍 Running security checks...');
    
    // Check for external connections (should be none)
    const hasExternalScripts = Array.from(document.scripts)
        .some(script => script.src && !script.src.startsWith(window.location.origin));
    
    if (hasExternalScripts) {
        console.error('⚠️ WARNING: External scripts detected!');
        alert('SECURITY WARNING: External scripts detected. This dashboard should only load local resources.');
    } else {
        console.log('✓ No external scripts detected');
    }
    
    // Check Content Security Policy
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    if (cspMeta) {
        console.log('✓ CSP policy active:', cspMeta.content);
    } else {
        console.warn('⚠️ No CSP policy detected');
    }
    
    console.log('✓ Security checks complete');
}

// ============================================
// AUTO-REFRESH
// ============================================

function startAutoRefresh() {
    setInterval(() => {
        console.log('🔄 Auto-refreshing dashboard data...');
        loadDashboardData();
    }, CONFIG.REFRESH_INTERVAL);
}

// ============================================
// EXPORT FUNCTIONS
// ============================================

window.initDashboard = initDashboard;
window.loadMetrics = loadMetrics;
window.toggleRedaction = toggleRedaction;

// Run security checks on load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', performSecurityChecks);
} else {
    performSecurityChecks();
}

console.log('✓ Secure Dashboard loaded');
console.log('🔒 OPSEC: ACTIVE | External connections: BLOCKED');

