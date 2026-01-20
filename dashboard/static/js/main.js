// Main Dashboard JavaScript (Fix #7: Missing static/js/main.js)
//
// Fetches data from Flask API and renders charts

// Global charts
let cpuChart, memChart, riskChart, syscallChart;

// Initialize dashboard
async function initDashboard() {
    console.log('[Dashboard] Initializing...');

    try {
        // Fetch summary data
        await loadSummary();

        // Fetch analytics
        await loadAnalytics();

        // Setup auto-refresh
        setInterval(loadSummary, 30000); // Refresh every 30s

        console.log('[Dashboard] Initialized successfully');
    } catch (error) {
        console.error('[Dashboard] Initialization failed:', error);
        showError('Failed to load dashboard data');
    }
}

async function loadSummary() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();

        console.log('[API] /api/stats:', data);

        // Update summary cards
        document.getElementById('totalRuns').textContent = data.total_runs || 0;
        document.getElementById('avgCpu').textContent = (data.avg_cpu || data.cpu_avg || 0).toFixed(1) + '%';
        document.getElementById('avgMem').textContent = Math.round(data.avg_mem || data.mem_avg || 0) + ' KB';

        // Update runs list if exists
        if (data.runs && data.runs.length > 0) {
            updateRunsList(data.runs);
            updateRiskChart(data.runs);
        }

    } catch (error) {
        console.error('[API] /api/stats failed:', error);
    }
}

async function loadAnalytics() {
    try {
        const response = await fetch('/api/analytics');
        const data = await response.json();

        console.log('[API] /api/analytics:', data);

        // Update analytics cards
        if (data.benign_count !== undefined) {
            document.getElementById('benignCount').textContent = data.benign_count;
        }
        if (data.malicious_count !== undefined) {
            document.getElementById('maliciousCount').textContent = data.malicious_count;
        }

    } catch (error) {
        console.error('[API] /api/analytics failed:', error);
    }
}

function updateRunsList(runs) {
    const container = document.getElementById('runsList');
    if (!container) return;

    container.innerHTML = '';

    runs.slice(0, 10).forEach(run => {
        const div = document.createElement('div');
        div.className = 'run-item';
        div.innerHTML = `
            <strong>${run.program || 'Unknown'}</strong>
            <span>CPU: ${(run.cpu_avg || run.peak_cpu_percent || 0).toFixed(1)}%</span>
            <span>MEM: ${Math.round(run.mem_avg || run.peak_memory_kb || 0)} KB</span>
            <span class="risk-${run.prediction || 'unknown'}">${run.prediction || 'N/A'}</span>
        `;
        container.appendChild(div);
    });
}

function updateRiskChart(runs) {
    const canvas = document.getElementById('riskChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    // Destroy existing chart
    if (riskChart) {
        riskChart.destroy();
    }

    // Extract risk series from first run with timeline
    const runWithTimeline = runs.find(r => r.risk_series || r.risk_samples);

    if (!runWithTimeline) {
        console.log('[Chart] No risk series data available');
        return;
    }

    const riskData = runWithTimeline.risk_series || runWithTimeline.risk_samples || [];

    riskChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: riskData.map((_, i) => i),
            datasets: [{
                label: 'Risk Score',
                data: riskData,
                borderColor: '#f56565',
                backgroundColor: 'rgba(245, 101, 101, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            },
            plugins: {
                legend: {
                    display: true,
                    labels: {
                        color: '#e0e6ed'
                    }
                }
            }
        }
    });
}

function showError(message) {
    const container = document.getElementById('errorContainer');
    if (container) {
        container.textContent = message;
        container.style.display = 'block';
        setTimeout(() => {
            container.style.display = 'none';
        }, 5000);
    }
}

// Initialize when DOM loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDashboard);
} else {
    initDashboard();
}

console.log('[Main.js] Loaded successfully');
