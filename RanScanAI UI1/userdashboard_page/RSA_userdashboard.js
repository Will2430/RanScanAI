// app.js

// --- API Configuration ---
const API_BASE = 'http://127.0.0.1:8000';

// --- API helpers (fetch from backend) ---
const api = {
    async getSystemStatus() {
        try {
            const res = await fetch(`${API_BASE}/health`);
            if (!res.ok) throw new Error('Backend offline');
            const data = await res.json();
            // Derive a risk score from backend health info
            return { status: data.status, model_loaded: data.model_loaded };
        } catch {
            return { status: 'offline', model_loaded: false };
        }
    },

    async getDetectionsCount() {
        try {
            const res = await fetch(`${API_BASE}/api/detections?limit=1`);
            if (!res.ok) return { count: 0, malware: 0 };
            const data = await res.json();
            return { count: data.count ?? 0, malware: 0 };
        } catch {
            return { count: 0, malware: 0 };
        }
    },

    async getLatestDetection() {
        try {
            const res = await fetch(`${API_BASE}/api/detections?limit=1&malicious_only=false`);
            if (!res.ok) return { file: '—', date: '—', time: '—', device: '—', severity: 'low', confidence: 0 };
            const data = await res.json();
            if (!data.detections || data.detections.length === 0) {
                return { file: '—', date: '—', time: '—', device: '—', severity: 'low', confidence: 0 };
            }
            const d = data.detections[0];
            const dt = d.timestamp ? new Date(d.timestamp) : null;
            const dateStr = dt ? dt.toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' }) : '—';
            const timeStr = dt ? dt.toLocaleTimeString('en-GB') : '—';
            const severity = d.is_malicious
                ? (d.confidence >= 0.9 ? 'critical' : d.confidence >= 0.7 ? 'high' : 'medium')
                : 'low';
            return {
                file: d.file_name || '—',
                date: dateStr,
                time: timeStr,
                device: '—',
                severity,
                confidence: d.confidence || 0
            };
        } catch {
            return { file: '—', date: '—', time: '—', device: '—', severity: 'low', confidence: 0 };
        }
    },

    async getReports() {
        try {
            const res = await fetch(`${API_BASE}/api/reports?limit=5`);
            if (!res.ok) return [];
            const data = await res.json();
            return data.reports || [];
        } catch {
            return [];
        }
    },

    async getScanStats() {
        try {
            // Fetch all detections to derive dashboard stats
            const res = await fetch(`${API_BASE}/api/detections?limit=1000`);
            if (!res.ok) return null;
            const data = await res.json();
            const detections = data.detections || [];
            const total = data.count || 0;
            const malicious = detections.filter(d => d.is_malicious).length;
            const detection_rate = total > 0 ? Math.round((malicious / total) * 100) : 0;
            return { total_scans: total, malware_detected: malicious, detection_rate, detections };
        } catch {
            return null;
        }
    }
};

// --- Gauge Drawing (modernised) ---
function drawGauge(canvas, value) {
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;

    // High-DPI canvas
    const cssW = canvas.clientWidth || canvas.width;
    const cssH = canvas.clientHeight || canvas.height;
    canvas.width = cssW * dpr;
    canvas.height = cssH * dpr;
    canvas.style.width = cssW + 'px';
    canvas.style.height = cssH + 'px';
    ctx.scale(dpr, dpr);

    ctx.clearRect(0, 0, cssW, cssH);

    const start = Math.PI;
    const end = 2 * Math.PI;
    const centerX = cssW / 2;
    const padTop = 20;
    const padBottom = 14;
    const padSide = 24;
    const centerY = cssH - padBottom;
    const maxValue = 100;
    const clampedValue = Math.max(0, Math.min(maxValue, value));
    const maxRadiusByWidth = Math.max(20, (cssW - padSide * 2) / 2);
    let radius = Math.min(maxRadiusByWidth, Math.max(20, cssH - padTop - padBottom - 24));
    let lineWidth = Math.max(14, Math.round(radius * 0.16));
    const labelOffset = Math.max(10, Math.round(lineWidth * 0.65));
    radius = Math.min(radius, Math.max(20, cssH - padTop - padBottom - labelOffset - lineWidth / 2));
    lineWidth = Math.max(14, Math.round(radius * 0.16));

    // Background arc (track)
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, start, end, false);
    ctx.lineWidth = lineWidth;
    ctx.strokeStyle = '#E8EAF0';
    ctx.lineCap = 'round';
    ctx.stroke();

    // Coloured arc (progress)
    const valueAngle = start + (clampedValue / maxValue) * (end - start);
    const grad = ctx.createLinearGradient(centerX - radius, centerY, centerX + radius, centerY);
    grad.addColorStop(0, '#16A34A');
    grad.addColorStop(0.45, '#FACC15');
    grad.addColorStop(0.7, '#F97316');
    grad.addColorStop(1, '#DC2626');

    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, start, valueAngle, false);
    ctx.lineWidth = lineWidth;
    ctx.strokeStyle = grad;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Tick labels (0..100)
    ctx.fillStyle = '#8B92A8';
    ctx.font = `500 11px Inter, Segoe UI, sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    for (let i = 0; i <= 10; i++) {
        const labelValue = i * 10;
        const angle = start + (labelValue / maxValue) * (end - start);
        const labelR = radius + lineWidth / 2 + labelOffset;
        const x = centerX + Math.cos(angle) * labelR;
        const y = centerY + Math.sin(angle) * labelR;
        ctx.fillText(String(labelValue), x, y);
    }

    // Centre value text
    ctx.fillStyle = '#111A3A';
    ctx.font = `800 ${Math.round(radius * 0.42)}px Inter, Segoe UI, sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'alphabetic';
    ctx.fillText(String(Math.round(clampedValue)), centerX, centerY - 8);

    // Needle
    const needleAngle = start + (clampedValue / maxValue) * (end - start);
    const needleLength = radius - lineWidth / 2 - 6;
    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.lineTo(
        centerX + Math.cos(needleAngle) * needleLength,
        centerY + Math.sin(needleAngle) * needleLength
    );
    ctx.lineWidth = 3;
    ctx.strokeStyle = '#111A3A';
    ctx.lineCap = 'round';
    ctx.stroke();

    // Centre dot
    ctx.beginPath();
    ctx.arc(centerX, centerY, 6, 0, 2 * Math.PI);
    ctx.fillStyle = '#111A3A';
    ctx.fill();
    ctx.beginPath();
    ctx.arc(centerX, centerY, 3, 0, 2 * Math.PI);
    ctx.fillStyle = '#ffffff';
    ctx.fill();
}

function getStatusForValue(value) {
    const clampedValue = Math.max(0, Math.min(100, value));
    if (clampedValue <= 33.33) return { label: 'NORMAL', cssClass: 'status-normal' };
    if (clampedValue <= 66.66) return { label: 'ELEVATED', cssClass: 'status-elevated' };
    return { label: 'CRITICAL', cssClass: 'status-critical' };
}

// --- Animated counter ---
function animateCount(element, target, duration = 800) {
    const startTime = performance.now();
    const startVal = 0;

    function step(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        // Ease-out cubic
        const ease = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(startVal + (target - startVal) * ease);
        element.textContent = current;
        if (progress < 1) requestAnimationFrame(step);
    }

    requestAnimationFrame(step);
}

// --- Animated gauge ---
function animateGauge(canvas, target, duration = 1000) {
    const startTime = performance.now();

    function step(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3);
        const current = ease * target;
        drawGauge(canvas, current);
        if (progress < 1) requestAnimationFrame(step);
    }

    requestAnimationFrame(step);
}

// ============================================================
// Chart helpers
// ============================================================

const MONTHS_SHORT = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

// --- Chart data (populated from API) ---
let currentGaugeValue = 0; // shared with resize handler
let detectionHistoryData = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // Jan-Dec
let verdictData = {
    labels : MONTHS_SHORT,
    series : [
        { label: 'Ransomware', color: '#DC2626', values: [0,0,0,0,0,0,0,0,0,0,0,0] },
        { label: 'Suspicious', color: '#E67E22', values: [0,0,0,0,0,0,0,0,0,0,0,0] },
        { label: 'Benign',     color: '#16A34A', values: [0,0,0,0,0,0,0,0,0,0,0,0] }
    ]
};

function buildChartDataFromDetections(detections) {
    const histData  = [0,0,0,0,0,0,0,0,0,0,0,0];
    const malicious = [0,0,0,0,0,0,0,0,0,0,0,0];
    const suspicious= [0,0,0,0,0,0,0,0,0,0,0,0];
    const benign    = [0,0,0,0,0,0,0,0,0,0,0,0];
    const currentYear = new Date().getFullYear();
    detections.forEach(d => {
        if (!d.timestamp) return;
        const dt = new Date(d.timestamp);
        if (dt.getFullYear() !== currentYear) return;
        const m = dt.getMonth();
        histData[m]++;
        if (d.is_malicious) {
            if (d.confidence >= 0.8) malicious[m]++;
            else suspicious[m]++;
        } else {
            benign[m]++;
        }
    });
    detectionHistoryData = histData;
    verdictData.series[0].values = malicious;
    verdictData.series[1].values = suspicious;
    verdictData.series[2].values = benign;
}

// ---- Shared canvas setup (HiDPI) ----
function setupCanvas(canvas) {
    const dpr  = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width  = rect.width  * dpr;
    canvas.height = rect.height * dpr;
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    return { ctx, w: rect.width, h: rect.height };
}

// ============================================================
// LINE CHART — Detection History
// ============================================================
function drawLineChart(progress) {
    const canvas = document.getElementById('line-chart');
    if (!canvas) return;
    const { ctx, w, h } = setupCanvas(canvas);

    const pad   = { top: 20, right: 20, bottom: 36, left: 44 };
    const cw    = w - pad.left - pad.right;
    const ch    = h - pad.top  - pad.bottom;
    const data  = detectionHistoryData;
    const maxV  = Math.max(...data);
    const gridLines = 5;

    ctx.clearRect(0, 0, w, h);

    // Grid lines + Y labels
    ctx.textBaseline = 'middle';
    ctx.font = `500 11px Inter, sans-serif`;
    ctx.fillStyle = '#8B92A8';
    ctx.textAlign = 'right';
    for (let i = 0; i <= gridLines; i++) {
        const val = Math.round((maxV / gridLines) * i);
        const y   = pad.top + ch - (i / gridLines) * ch;
        ctx.fillText(val, pad.left - 8, y);
        ctx.beginPath();
        ctx.moveTo(pad.left, y);
        ctx.lineTo(pad.left + cw, y);
        ctx.strokeStyle = i === 0 ? '#C8CCDA' : '#E4E7EF';
        ctx.lineWidth   = 1;
        ctx.stroke();
    }

    // X labels
    ctx.textAlign    = 'center';
    ctx.textBaseline = 'top';
    const step = cw / (data.length - 1);
    data.forEach((_, i) => {
        const x = pad.left + i * step;
        ctx.fillStyle = '#8B92A8';
        ctx.fillText(MONTHS_SHORT[i], x, pad.top + ch + 8);
    });

    // Points up to progress
    const totalPts  = data.length;
    const ptsDrawn  = Math.max(2, Math.ceil(progress * totalPts));
    const subProg   = (progress * totalPts) - (ptsDrawn - 1); // 0..1 interpolation within last segment

    const pts = data.slice(0, ptsDrawn).map((v, i) => ({
        x: pad.left + i * step,
        y: pad.top + ch - (v / maxV) * ch
    }));
    // Interpolate last point
    if (ptsDrawn < totalPts) {
        const prev = pts[pts.length - 1];
        const next = {
            x: pad.left + ptsDrawn * step,
            y: pad.top + ch - (data[ptsDrawn] / maxV) * ch
        };
        pts[pts.length - 1] = {
            x: prev.x + (next.x - prev.x) * subProg,
            y: prev.y + (next.y - prev.y) * subProg
        };
    }

    // Gradient fill
    const grad = ctx.createLinearGradient(0, pad.top, 0, pad.top + ch);
    grad.addColorStop(0,   'rgba(59,81,196,0.18)');
    grad.addColorStop(1,   'rgba(59,81,196,0)');
    ctx.beginPath();
    ctx.moveTo(pts[0].x, pad.top + ch);
    pts.forEach(p => ctx.lineTo(p.x, p.y));
    ctx.lineTo(pts[pts.length-1].x, pad.top + ch);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Line
    ctx.beginPath();
    pts.forEach((p, i) => i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y));
    ctx.strokeStyle = '#3B51C4';
    ctx.lineWidth   = 2.5;
    ctx.lineJoin    = 'round';
    ctx.lineCap     = 'round';
    ctx.stroke();

    // Dots
    pts.forEach((p, i) => {
        ctx.beginPath();
        ctx.arc(p.x, p.y, i === pts.length - 1 ? 5 : 3.5, 0, 2 * Math.PI);
        ctx.fillStyle   = '#3B51C4';
        ctx.strokeStyle = '#fff';
        ctx.lineWidth   = 2;
        ctx.fill();
        ctx.stroke();
    });
}

function animateLineChart(duration = 1200) {
    const start = performance.now();
    function step(now) {
        const p = Math.min((now - start) / duration, 1);
        const ease = 1 - Math.pow(1 - p, 3);
        drawLineChart(ease);
        if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

// ============================================================
// BAR CHART — Prediction Verdict History
// ============================================================
function drawBarChart(progress) {
    const canvas = document.getElementById('bar-chart');
    if (!canvas) return;
    const { ctx, w, h } = setupCanvas(canvas);

    const pad       = { top: 20, right: 20, bottom: 36, left: 44 };
    const cw        = w - pad.left - pad.right;
    const ch        = h - pad.top  - pad.bottom;
    const { labels, series } = verdictData;
    const nGroups   = labels.length;
    const nSeries   = series.length;
    const groupGap  = 0.3;
    const totalW    = cw / nGroups;
    const barW      = (totalW * (1 - groupGap)) / nSeries;
    const maxVal    = Math.max(...series.flatMap(s => s.values));
    const gridLines = 5;

    ctx.clearRect(0, 0, w, h);

    // Grid + Y labels
    ctx.font      = `500 11px Inter, sans-serif`;
    ctx.fillStyle = '#8B92A8';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (let i = 0; i <= gridLines; i++) {
        const val = Math.round((maxVal / gridLines) * i);
        const y   = pad.top + ch - (i / gridLines) * ch;
        ctx.fillText(val, pad.left - 8, y);
        ctx.beginPath();
        ctx.moveTo(pad.left, y);
        ctx.lineTo(pad.left + cw, y);
        ctx.strokeStyle = i === 0 ? '#C8CCDA' : '#E4E7EF';
        ctx.lineWidth   = 1;
        ctx.stroke();
    }

    // X labels
    ctx.textAlign    = 'center';
    ctx.textBaseline = 'top';
    labels.forEach((lbl, gi) => {
        const gx = pad.left + gi * totalW + totalW * (groupGap / 2);
        const cx = gx + (barW * nSeries) / 2;
        ctx.fillStyle = '#8B92A8';
        ctx.fillText(lbl, cx, pad.top + ch + 8);
    });

    // Bars
    series.forEach((s, si) => {
        s.values.forEach((val, gi) => {
            const gx      = pad.left + gi * totalW + totalW * (groupGap / 2);
            const bx      = gx + si * barW;
            const fullH   = (val / maxVal) * ch;
            const animH   = fullH * progress;
            const by      = pad.top + ch - animH;
            const radius  = Math.min(4, animH / 2);

            ctx.beginPath();
            ctx.moveTo(bx + radius, by);
            ctx.lineTo(bx + barW - radius, by);
            ctx.quadraticCurveTo(bx + barW, by, bx + barW, by + radius);
            ctx.lineTo(bx + barW, pad.top + ch);
            ctx.lineTo(bx, pad.top + ch);
            ctx.lineTo(bx, by + radius);
            ctx.quadraticCurveTo(bx, by, bx + radius, by);
            ctx.closePath();
            ctx.fillStyle = s.color;
            ctx.globalAlpha = 0.9;
            ctx.fill();
            ctx.globalAlpha = 1;
        });
    });
}

function animateBarChart(duration = 1000) {
    const start = performance.now();
    function step(now) {
        const p    = Math.min((now - start) / duration, 1);
        const ease = 1 - Math.pow(1 - p, 3);
        drawBarChart(ease);
        if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

function buildBarLegend() {
    const el = document.getElementById('bar-legend');
    if (!el) return;
    el.innerHTML = verdictData.series.map(s =>
        `<span class="legend-item">
            <span class="legend-dot" style="background:${s.color}"></span>
            ${s.label}
        </span>`
    ).join('');
}

// --- Ring chart animation ---
function animateRing(targetPct, severity, duration = 1000) {
    const circle = document.getElementById('ring-progress');
    const pctEl  = document.getElementById('threat-pct');
    if (!circle || !pctEl) return;

    const circumference = 2 * Math.PI * 50; // 314.16
    const colorMap = {
        critical : '#DC2626',
        high     : '#EA580C',
        medium   : '#E67E22',
        low      : '#16A34A'
    };
    const sev = (severity || 'critical').toLowerCase();
    circle.style.stroke = colorMap[sev] || colorMap.critical;
    circle.style.strokeDasharray = `0 ${circumference}`;

    const startTime = performance.now();
    function step(now) {
        const elapsed  = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const ease     = 1 - Math.pow(1 - progress, 3);
        const current  = ease * targetPct;
        const dash     = (current / 100) * circumference;
        circle.style.strokeDasharray = `${dash} ${circumference}`;
        pctEl.textContent = Math.round(current);
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

// --- Severity badge helper ---
function applySeverityBadge(element, severity) {
    const s = severity.toLowerCase();
    element.textContent = severity;
    element.classList.remove('severity-critical', 'severity-high', 'severity-medium', 'severity-low');
    if (s === 'critical') element.classList.add('severity-critical');
    else if (s === 'high') element.classList.add('severity-high');
    else if (s === 'medium') element.classList.add('severity-medium');
    else element.classList.add('severity-low');
}

// --- Date/Time display ---
function updateDateTime() {
    const el = document.getElementById('current-datetime');
    if (!el) return;
    const now = new Date();
    const options = { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
    el.textContent = now.toLocaleDateString('en-GB', options);
}

// --- Populate UI ---
async function populateDashboard() {
    // Date/Time
    updateDateTime();
    setInterval(updateDateTime, 30000);

    // Hero Panel — derive score from real data
    const systemStatus = await api.getSystemStatus();
    const stats = await api.getScanStats();
    // Compute risk score: detection_rate from backend (0-100), default 0
    const a = stats ? Math.round(stats.detection_rate ?? 0) : 0;
    const statusInfo = getStatusForValue(a);
    const statusEl = document.getElementById('system-status');
    statusEl.className = 'status-pill ' + statusInfo.cssClass;
    statusEl.querySelector('.status-text').textContent = `System Status: ${statusInfo.label}`;

    // Hero title + icon
    const heroWrap  = document.getElementById('hero-icon-wrap');
    const heroTitle = document.getElementById('hero-title');
    const heroSub   = document.getElementById('hero-sub');
    if (statusInfo.label === 'NORMAL') {
        heroWrap.className  = 'hero-icon-wrap hero-normal';
        heroTitle.textContent = 'System is Secure';
        heroSub.textContent   = 'No active threats detected. All systems operating normally.';
    } else if (statusInfo.label === 'ELEVATED') {
        heroWrap.className  = 'hero-icon-wrap hero-elevated';
        heroTitle.textContent = 'Elevated Risk Detected';
        heroSub.textContent   = 'Suspicious activity found. Review detections and take action.';
    } else {
        heroWrap.className  = 'hero-icon-wrap hero-critical';
        heroTitle.textContent = 'Critical Risk Detected';
        heroSub.textContent   = 'High-severity threats are active. Immediate action is recommended.';
    }

    animateGauge(document.getElementById('gauge'), a);
    currentGaugeValue = a; // keep in sync for resize

    // Panel 2 — reuse already-fetched stats
    const countSpan = document.getElementById('detections-count-val');
    animateCount(countSpan, stats ? (stats.total_scans ?? 0) : 0);

    // Panel 3
    const latest = await api.getLatestDetection();
    document.getElementById('latest-file').textContent   = latest.file;
    document.getElementById('latest-date').textContent   = latest.date;
    document.getElementById('latest-time').textContent   = latest.time;
    document.getElementById('latest-device').textContent = latest.device;
    applySeverityBadge(document.getElementById('latest-severity'), latest.severity);
    // Animate ring chart — use confidence from latest detection (or gauge score as fallback)
    const ringPct = latest.confidence ? Math.round(latest.confidence * 100) : a;
    animateRing(ringPct, latest.severity);

    // Panel 4
    const reports = await api.getReports();
    const tbody = document.getElementById('reports-tbody');
    tbody.innerHTML = '';
    if (reports.length === 0) {
        tbody.innerHTML = `<tr><td colspan="3" style="text-align:center;padding:20px;color:#8B92A8;font-size:.8rem;">No reports available yet.</td></tr>`;
    } else {
        reports.forEach(r => {
            const tr = document.createElement('tr');
            const detailUrl = `../viewallreports_page/viewreportdetail.html?year=${r.year}&month=${r.month}`;
            tr.innerHTML = `
                <td>${r.id}</td>
                <td>${r.label}</td>
                <td>
                    <button class="eye-btn" aria-label="View report ${r.id}" onclick="window.location.href='${detailUrl}'">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    // Charts — build from real detection data if available
    if (stats && stats.detections) {
        buildChartDataFromDetections(stats.detections);
    }
    buildBarLegend();
    animateLineChart();
    animateBarChart();
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
    populateDashboard();

    // Redraw on resize (debounced) — uses the live score, not a hardcoded value
    let resizeTimer;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            drawGauge(document.getElementById('gauge'), currentGaugeValue);
            drawLineChart(1);
            drawBarChart(1);
        }, 150);
    });
});