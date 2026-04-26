document.addEventListener('DOMContentLoaded', () => {
    
    // Format bytes to a human readable string
    function formatBytes(bytes, decimals = 2) {
        if (!+bytes) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
    }

    // Format time duration
    function formatDuration(seconds) {
        if (seconds < 60) return `${seconds.toFixed(1)}s`;
        const mins = Math.floor(seconds / 60);
        const secs = (seconds % 60).toFixed(0);
        return `${mins}m ${secs}s`;
    }

    function getFlagEmoji(countryCode) {
        if (!countryCode || countryCode === 'UN' || countryCode === 'LOCAL') return '🌐';
        return countryCode.toUpperCase().replace(/./g, char => String.fromCodePoint(char.charCodeAt(0) + 127397));
    }

    // Global variable to hold banned IPs
    let bannedIps = [];

    window.blockIP = function(ip) {
        if (!confirm(`Are you sure you want to block ${ip}?`)) return;
        
        fetch('/api/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                bannedIps.push(ip);
                fetchStats(); // Refresh UI
            } else {
                alert('Failed to block IP: ' + data.error);
            }
        });
    };

    function createAttackCard(attack) {
        const flag = getFlagEmoji(attack.countryCode);
        const isBanned = bannedIps.includes(attack.ip);
        const btnHtml = isBanned 
            ? `<button class="btn btn-blocked" disabled>Blocked</button>`
            : `<button class="btn btn-block" onclick="blockIP('${attack.ip}')">Block IP</button>`;

        return `
            <div class="attack-card">
                <div class="attack-card-header">
                    <span class="ip-addr">${attack.ip} <span title="${attack.country}">${flag}</span></span>
                    ${btnHtml}
                </div>
                <div class="attack-details">
                    <div class="detail-item">
                        <span class="detail-label">Requests</span>
                        <span class="detail-value">${attack.requests}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Exfiltrated</span>
                        <span class="detail-value">${formatBytes(attack.bytes_exfiltrated)}</span>
                    </div>
                    <div class="detail-item" style="grid-column: span 2;">
                        <span class="detail-label">Origin</span>
                        <span class="detail-value">${attack.country} ${flag}</span>
                    </div>
                    ${attack.payload ? `
                    <div class="detail-item" style="grid-column: span 2;">
                        <span class="detail-label">Attack Payload</span>
                        <span class="detail-value" style="color: #ef4444; font-family: monospace; word-break: break-all; font-size: 0.85rem; background: rgba(239, 68, 68, 0.1); padding: 4px; border-radius: 4px;">${attack.payload}</span>
                    </div>
                    ` : ''}
                    <div class="detail-item" style="grid-column: span 2;">
                        <span class="detail-label">Last Seen</span>
                        <span class="detail-value">${attack.end_time}</span>
                    </div>
                </div>
            </div>
        `;
    }

    function updatePanel(panelId, countId, data) {
        const panel = document.getElementById(panelId);
        const count = document.getElementById(countId);
        
        count.textContent = data.length;
        
        if (data.length === 0) {
            panel.innerHTML = '<div class="no-data">No threats detected</div>';
            return;
        }

        // Limit data to max 8 items and sort by end_time descending
        const displayData = data
            .sort((a, b) => new Date(b.end_time) - new Date(a.end_time))
            .slice(0, 8);

        let html = '';
        displayData.forEach(attack => {
            html += createAttackCard(attack);
        });
        
        panel.innerHTML = html;
    }

    // Initialize Chart
    const ctx = document.getElementById('attackChart').getContext('2d');
    let attackChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#ef4444', // Red (SQLi)
                    '#f97316', // Orange (Cred)
                    '#a855f7', // Purple (Exfil)
                    '#3b82f6'  // Blue (DoS)
                ],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#e2e8f0', font: { family: 'Inter' } }
                }
            },
            cutout: '70%'
        }
    });

    function fetchChartData() {
        fetch('/api/chart_data')
            .then(res => res.json())
            .then(data => {
                attackChart.data.labels = data.labels;
                attackChart.data.datasets[0].data = data.data;
                attackChart.update();
            });
    }

    function fetchStats() {
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    console.error('Error fetching data:', data.error);
                    return;
                }
                
                bannedIps = data.banned_ips || [];
                
                updatePanel('sqli-list', 'sqli-count', data.sqli || []);
                updatePanel('cred-list', 'cred-count', data.cred_stuffing || []);
                updatePanel('exfil-list', 'exfil-count', data.exfiltration || []);
                updatePanel('dos-list', 'dos-count', data.dos || []);
                
                // Fetch chart data after stats update the DB
                fetchChartData();
            })
            .catch(error => {
                console.error('Fetch error:', error);
            });
    }

    // Initial fetch
    fetchStats();

    // Polling every 3 seconds for real-time updates
    setInterval(fetchStats, 3000);
});
