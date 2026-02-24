// app.js

// --- Mock API Data ---
const api = {
    getSystemStatus: () => Promise.resolve({ status: 'CRITICAL', risk: 0.85 }),
    getDetectionsCount: () => Promise.resolve({ count: 14 }),
    getLatestDetection: () =>
        Promise.resolve({
            file     : 'ransomransom.exe',
            date     : '4 March 2026',
            time     : '19:05:36',
            device   : 'LBJ - PC02',
            severity : 'Critical'
        }),
    getReports: () =>
        Promise.resolve([
            { id: 'R74', name: '2025 July Detailed Report' },
            { id: 'R73', name: '2025 June Detailed Report' },
            { id: 'R72', name: '2025 May Detailed Report' }
        ])
};

// --- Gauge Drawing ---
function drawGauge(canvas, value) {
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Gauge arc
    const start = Math.PI, end = 2 * Math.PI;
    const centerX = canvas.width / 2;
    const centerY = canvas.height - 6;
    const radius = Math.min(centerX - 30, centerY - 30);
    const maxValue = 100;
    const clampedValue = Math.max(0, Math.min(maxValue, value));

    // Gradient
    const grad = ctx.createLinearGradient(0, 0, canvas.width, 0);
    grad.addColorStop(0, '#43a047'); // green
    grad.addColorStop(0.5, '#fbc02d'); // yellow
    grad.addColorStop(1, '#c62828'); // red

    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, start, end, false);
    ctx.lineWidth = Math.max(14, Math.round(radius * 0.2));
    ctx.strokeStyle = grad;
    ctx.stroke();

    // Number labels (0..100)
    ctx.fillStyle = '#26336c';
    ctx.font = '12px Segoe UI, Arial, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    for (let i = 0; i <= 10; i += 1) {
        const labelValue = i * 10;
        const angle = start + (labelValue / maxValue) * (end - start);
        const labelRadius = radius + Math.max(20, Math.round(radius * 0.01));
        const x = centerX + Math.cos(angle) * labelRadius;
        const y = centerY + Math.sin(angle) * labelRadius;
        ctx.fillText(String(labelValue), x, y);
    }

    // Needle
    const angle = start + (clampedValue / maxValue) * (end - start);
    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.lineTo(
        centerX + Math.cos(angle) * (radius - 12),
        centerY + Math.sin(angle) * (radius - 12)
    );
    ctx.lineWidth = 4;
    ctx.strokeStyle = '#c62828';
    ctx.stroke();

    // Center dot
    ctx.beginPath();
    ctx.arc(centerX, centerY, 7, 0, 2 * Math.PI);
    ctx.fillStyle = '#c62828';
    ctx.fill();
}

function getStatusForValue(value) {
    const clampedValue = Math.max(0, Math.min(100, value));

    if (clampedValue <= 33.33) {
        return { label: 'NORMAL', color: '#2e7d32' };
    }

    if (clampedValue <= 66.66) {
        return { label: 'ELEVATED', color: '#ef6c00' };
    }

    return { label: 'CRITICAL', color: '#c62828' };
}

// --- Populate UI ---
async function populateDashboard() {
    // Panel 1
    await api.getSystemStatus();
    const a = 75; //status score api
    const statusInfo = getStatusForValue(a);
    const statusEl = document.getElementById('system-status');
    statusEl.textContent = `System Status: ${statusInfo.label}`;
    statusEl.style.color = statusInfo.color;
    drawGauge(document.getElementById('gauge'), a);

    // Panel 2
    const detections = await api.getDetectionsCount();
    document.getElementById('detections-count').innerHTML =
        `<span class="panel2-count">${detections.count}</span>` +
        `<span class="panel2-sub">New Detections</span>`;

    // Panel 3
    const latest = await api.getLatestDetection();
    document.getElementById('latest-file').textContent = latest.file;
    document.getElementById('latest-date').textContent = latest.date;
    document.getElementById('latest-time').textContent = latest.time;
    document.getElementById('latest-device').textContent = latest.device;
    document.getElementById('latest-severity').textContent = latest.severity;

    // Panel 4
    const reports = await api.getReports();
    const tbody = document.getElementById('reports-tbody');
    tbody.innerHTML = '';
    reports.forEach(r => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${r.id}</td>
            <td>${r.name}</td>
            <td><span class="eye-icon">&#128065;</span></td>
        `;
        tbody.appendChild(tr);
    });
}

// --- Button Handlers (stub navigation) ---
document.addEventListener('DOMContentLoaded', () => {
    populateDashboard();
});