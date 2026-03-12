// app.js

// --- API Configuration ---
const API_BASE = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
    ? 'http://127.0.0.1:8000'
    : 'https://ranscanaix.azurewebsites.net';

// --- Auth helper ---
function authHeaders() {
    const token = localStorage.getItem('access_token');
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}

// --- API helpers (fetch from backend) ---
const api = {
    async getSystemStatus() {
        try {
            const res = await fetch(`${API_BASE}/health`);
            if (!res.ok) throw new Error('Backend offline');
            const data = await res.json();
            return { status: data.status, model_loaded: data.model_loaded };
        } catch {
            return { status: 'offline', model_loaded: false };
        }
    },

    async getDetectionsCount() {
        try {
            const res = await fetch(`${API_BASE}/scan-history`, { headers: authHeaders() });
            if (!res.ok) return { count: 0, malware: 0 };
            const data = await res.json();
            return { count: data.count ?? 0, malware: 0 };
        } catch {
            return { count: 0, malware: 0 };
        }
    },

    async getLatestDetection() {
        try {
            const res = await fetch(`${API_BASE}/api/detections?limit=1&malicious_only=false`, { headers: authHeaders() });
            if (!res.ok) return { file: '—', date: '—', time: '—', severity: 'low', confidence: 0 };
            const data = await res.json();
            if (!data.detections || data.detections.length === 0) {
                return { file: '—', date: '—', time: '—', severity: 'low', confidence: 0 };
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
                severity,
                confidence: d.confidence || 0
            };
        } catch {
            return { file: '—', date: '—', time: '—', device: '—', severity: 'low', confidence: 0 };
        }
    },

    async getReports() {
        try {
            const res = await fetch(`${API_BASE}/api/reports?limit=5`, { headers: authHeaders() });
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
            const res = await fetch(`${API_BASE}/api/detections?limit=1000`, { headers: authHeaders() });
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

// ============================================================
// Chart helpers
// ============================================================

const MONTHS_SHORT = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

// --- Chart data (populated from API) ---
let allDetections = [];    // cached for period switching
let currentBarPeriod  = 'year';
let currentLinePeriod = 'year';
let lineChartLabels = MONTHS_SHORT.slice();
let detectionHistoryData = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // Jan-Dec
let verdictData = {
    labels : MONTHS_SHORT,
    series : [
        { label: 'Ransomware', color: '#DC2626', values: [0,0,0,0,0,0,0,0,0,0,0,0] },
        { label: 'Suspicious', color: '#E67E22', values: [0,0,0,0,0,0,0,0,0,0,0,0] },
        { label: 'Benign',     color: '#16A34A', values: [0,0,0,0,0,0,0,0,0,0,0,0] }
    ]
};

/**
 * Compute chart bucket data for a given time period.
 * @param {Array} detections - detection objects from the API
 * @param {'week'|'month'|'year'} period
 * @returns {{ labels: string[], histData: number[], malicious: number[], suspicious: number[], benign: number[] }}
 */
function computePeriodData(detections, period) {
    const now = new Date();
    const DAYS_SHORT = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    let labels, histData, malicious, suspicious, benign;

    if (period === 'week') {
        // Last 7 days — one bucket per day
        labels    = [];
        histData  = new Array(7).fill(0);
        malicious = new Array(7).fill(0);
        suspicious= new Array(7).fill(0);
        benign    = new Array(7).fill(0);

        for (let i = 6; i >= 0; i--) {
            const dd = new Date(now);
            dd.setDate(dd.getDate() - i);
            labels.push(DAYS_SHORT[dd.getDay()]);
        }
        const nowDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        detections.forEach(d => {
            if (!d.timestamp) return;
            const dt = new Date(d.timestamp);
            const dtDate = new Date(dt.getFullYear(), dt.getMonth(), dt.getDate());
            const diffDays = Math.floor((nowDate - dtDate) / 86400000);
            if (diffDays < 0 || diffDays > 6) return;
            const idx = 6 - diffDays;
            histData[idx]++;
            if (d.is_malicious) {
                if (d.confidence >= 0.8) malicious[idx]++;
                else suspicious[idx]++;
            } else { benign[idx]++; }
        });

    } else if (period === 'month') {
        // Last 4 weeks — one bucket per week
        labels    = ['Wk 1', 'Wk 2', 'Wk 3', 'Wk 4'];
        histData  = new Array(4).fill(0);
        malicious = new Array(4).fill(0);
        suspicious= new Array(4).fill(0);
        benign    = new Array(4).fill(0);

        const nowDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        detections.forEach(d => {
            if (!d.timestamp) return;
            const dt = new Date(d.timestamp);
            const dtDate = new Date(dt.getFullYear(), dt.getMonth(), dt.getDate());
            const diffDays = Math.floor((nowDate - dtDate) / 86400000);
            if (diffDays < 0 || diffDays > 27) return;
            const weekIdx = Math.min(3, Math.floor(diffDays / 7));
            const idx = 3 - weekIdx; // chronological order (oldest → newest)
            histData[idx]++;
            if (d.is_malicious) {
                if (d.confidence >= 0.8) malicious[idx]++;
                else suspicious[idx]++;
            } else { benign[idx]++; }
        });

    } else {
        // Year — 12 monthly buckets for the current year
        labels    = MONTHS_SHORT.slice();
        histData  = new Array(12).fill(0);
        malicious = new Array(12).fill(0);
        suspicious= new Array(12).fill(0);
        benign    = new Array(12).fill(0);
        const currentYear = now.getFullYear();

        detections.forEach(d => {
            if (!d.timestamp) return;
            const dt = new Date(d.timestamp);
            if (dt.getFullYear() !== currentYear) return;
            const m = dt.getMonth();
            histData[m]++;
            if (d.is_malicious) {
                if (d.confidence >= 0.8) malicious[m]++;
                else suspicious[m]++;
            } else { benign[m]++; }
        });
    }

    return { labels, histData, malicious, suspicious, benign };
}

/** Apply computed period data to the bar chart state. */
function applyBarChartData(period) {
    currentBarPeriod = period;
    const data = computePeriodData(allDetections, period);
    verdictData.labels = data.labels;
    verdictData.series[0].values = data.malicious;
    verdictData.series[1].values = data.suspicious;
    verdictData.series[2].values = data.benign;
}

/** Apply computed period data to the line chart state. */
function applyLineChartData(period) {
    currentLinePeriod = period;
    const data = computePeriodData(allDetections, period);
    lineChartLabels = data.labels;
    detectionHistoryData = data.histData;
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
    const maxV  = Math.max(1, Math.max(...data)); // at least 1 to avoid div-by-zero
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
        ctx.fillText(lineChartLabels[i] || '', x, pad.top + ch + 8);
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
    const maxVal    = Math.max(1, Math.max(...series.flatMap(s => s.values)));
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

// --- Refresh sidebar + charts (called on init and after each scan) ---
async function refreshDashboardStats() {
    // Stats + detection count
    const stats = await api.getScanStats();
    const countSpan = document.getElementById('detections-count-val');
    animateCount(countSpan, stats ? (stats.total_scans ?? 0) : 0);

    // Latest detection panel
    const latest = await api.getLatestDetection();
    document.getElementById('latest-file').textContent = latest.file;
    document.getElementById('latest-date').textContent = latest.date;
    document.getElementById('latest-time').textContent = latest.time;
    applySeverityBadge(document.getElementById('latest-severity'), latest.severity);
    const ringPct = latest.confidence ? Math.round(latest.confidence * 100) : 0;
    animateRing(ringPct, latest.severity);

    // Reports table
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

    // Charts
    if (stats && stats.detections) {
        allDetections = stats.detections;
        applyBarChartData(currentBarPeriod);
        applyLineChartData(currentLinePeriod);
    }
    buildBarLegend();
    animateLineChart();
    animateBarChart();
}

// --- Populate UI ---
async function populateDashboard() {
    updateDateTime();
    setInterval(updateDateTime, 30000);
    await refreshDashboardStats();
}

// ============================================================
// SCAN PIPELINE — File Upload & Analysis
// ============================================================

let scanEs              = null;   // active EventSource
let scanFile            = null;   // currently selected file
let scanResult          = null;   // last result object
let scanLogs            = [];     // analysis log entries
let quarantinedFiles    = [];     // quarantine list
let scanLogsVisible     = true;   // show/hide logs toggle
let scanFileInfo        = null;   // { name, size, type, hash }
let scanBehavioralPatterns = [];

function scanFormatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

function scanGetFileType(name) {
    const ext = name.split('.').pop().toLowerCase();
    const types = {
        exe: 'Executable', dll: 'Dynamic Library', pdf: 'PDF Document',
        doc: 'Word Document', docx: 'Word Document', zip: 'Archive',
        rar: 'Archive', js: 'JavaScript', py: 'Python Script',
        bat: 'Batch File', ps1: 'PowerShell Script', msi: 'Installer',
    };
    return types[ext] || 'File';
}

async function scanComputeHash(fileObj) {
    const buffer = await fileObj.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function scanSetProgress(pct) {
    const bar   = document.getElementById('scan-progress-bar');
    const pctEl = document.getElementById('scan-progress-pct');
    const lbl   = document.getElementById('scan-progress-label');
    if (bar) {
        bar.style.width = pct + '%';
        bar.className = 'scan-progress-bar' +
            (pct === 100 ? (scanResult && scanResult.is_malicious ? ' bar-danger' : ' bar-safe') : '');
    }
    if (pctEl) pctEl.textContent = pct + ' %';
    if (lbl) {
        if (pct === 0)        lbl.textContent = 'Ready';
        else if (pct === 100) lbl.textContent = 'Scan complete';
        else                  lbl.textContent = 'Scanning file...';
    }
}

function scanRenderLogEntry(log) {
    var text = log.text || '';

    // Stage RESULT line — only when score/confidence present
    var stageMatch = text.match(/stage\s*([\d.]+)[^:]*:\s*([A-Z_]+)(?:[^(]*\(([^)]*)\))?/i);
    if (stageMatch) {
        var stageNum = stageMatch[1];
        var verdict  = stageMatch[2].toUpperCase();
        var extra    = stageMatch[3] || '';
        var scoreM   = extra.match(/score\s*[=:]\s*([\d.]+)/i);
        var confM    = extra.match(/conf(?:idence)?\s*[=:]\s*([\d.]+)/i);
        var score    = scoreM ? parseFloat(scoreM[1]) : null;
        var conf     = confM  ? parseFloat(confM[1])  : null;
        if (score !== null || conf !== null) {
            var isClean  = /clean|benign|safe/i.test(verdict);
            var isMal    = /malicious|malware|ransomware/i.test(verdict);
            var accent   = isClean ? '#4ADE80' : isMal ? '#F87171' : '#FCD34D';
            var bg       = isClean ? 'rgba(74,222,128,0.12)' : isMal ? 'rgba(248,113,113,0.12)' : 'rgba(252,211,77,0.12)';
            var emoji    = isClean ? '✅' : isMal ? '🚨' : '⚠️';
            var scoreHtml = score !== null
                ? '<span style="color:#94A3B8;font-size:0.88rem;font-family:monospace">score: <strong style="color:#E2E8F0">' + score.toFixed(4) + '</strong></span>'
                : '';
            var confHtml  = conf !== null
                ? '<span style="background:rgba(255,255,255,0.08);color:' + accent + ';border:1px solid ' + accent + '55;border-radius:4px;padding:2px 8px;font-size:0.88rem;font-weight:700">conf: ' + (conf * 100).toFixed(1) + '%</span>'
                : '';
            return '<div style="display:flex;align-items:center;flex-wrap:wrap;gap:7px;background:' + bg + ';border-left:3px solid ' + accent + ';border-radius:6px;padding:8px 12px;margin-bottom:8px">' +
                '<span style="font-size:1.05rem">' + emoji + '</span>' +
                '<span style="background:#1E293B;color:#94A3B8;border-radius:4px;padding:2px 8px;font-size:0.80rem;font-weight:700;letter-spacing:0.07em">STAGE ' + stageNum + '</span>' +
                '<span style="background:' + accent + ';color:#0F172A;border-radius:4px;padding:2px 10px;font-size:0.88rem;font-weight:800">' + verdict + '</span>' +
                scoreHtml + confHtml +
                '</div>';
        }
    }

    // Soft voting
    if (/soft\s*vot/i.test(text)) {
        return '<div style="display:flex;align-items:center;gap:8px;background:rgba(139,92,246,0.12);border-left:3px solid #A78BFA;border-radius:6px;padding:7px 12px;margin-bottom:8px">' +
            '<span style="color:#C4B5FD;font-size:0.95rem;font-family:monospace">' + text + '</span>' +
            '</div>';
    }

    // Final classification
    if (/final\s*class/i.test(text)) {
        var isMalFinal  = /malicious|malware|ransomware/i.test(text);
        var accentFinal = isMalFinal ? '#F87171' : '#4ADE80';
        return '<div style="display:flex;align-items:center;gap:10px;background:' + (isMalFinal ? 'rgba(248,113,113,0.15)' : 'rgba(74,222,128,0.15)') + ';border:1.5px solid ' + accentFinal + ';border-radius:7px;padding:10px 14px;margin-top:8px;margin-bottom:4px">' +
            '<span style="font-size:1.15rem">' + (isMalFinal ? '🚨' : '✅') + '</span>' +
            '<span style="color:' + accentFinal + ';font-weight:700;font-size:1.0rem">' + text + '</span>' +
            '</div>';
    }

    // Plain text
    return '<div style="padding:3px 12px;margin-bottom:6px">' +
        '<span style="color:#CBD5E1;font-size:0.95rem;line-height:1.6">' + text + '</span>' +
        '</div>';
}

function scanAddLog(text, status) {
    if (!status) status = 'success';
    scanLogs.push({ text, status });

    // Inline log list
    const list = document.getElementById('scan-logs-list');
    if (list) {
        list.insertAdjacentHTML('beforeend', scanRenderLogEntry({ text, status }));
        list.scrollTop = list.scrollHeight;
    }
    const section = document.getElementById('scan-logs-section');
    if (section) section.style.display = '';

    // Live-append to the expanded modal if it is currently open
    const overlay = document.getElementById('logs-modal-overlay');
    if (overlay && overlay.style.display !== 'none') {
        const modalBody = document.getElementById('logs-modal-body');
        if (modalBody) {
            modalBody.insertAdjacentHTML('beforeend', scanRenderLogEntry({ text, status }));
            modalBody.scrollTop = modalBody.scrollHeight;
        }
    }
}

function scanRenderQuarantine() {
    const iconEl    = document.getElementById('quarantine-icon');
    const contentEl = document.getElementById('quarantine-content');
    if (!contentEl) return;
    if (iconEl) {
        iconEl.className = 'quarantine-icon ' + (quarantinedFiles.length === 0 ? 'quarantine-clean' : 'quarantine-alert');
        iconEl.textContent = quarantinedFiles.length === 0 ? '✅' : '⚠️';
    }
    if (quarantinedFiles.length === 0) {
        contentEl.innerHTML = '<p class="quarantine-empty">No quarantined files</p>';
    } else {
        contentEl.innerHTML = '<ul class="quarantine-list">' +
            quarantinedFiles.map((qf, i) =>
                '<li class="quarantine-item">' +
                    '<div>' +
                        '<span class="quarantine-file-name">' + qf.name + '</span>' +
                        '<span class="quarantine-meta">' + qf.confidence + ' \u00b7 ' + qf.date + '</span>' +
                    '</div>' +
                    '<button class="quarantine-remove" data-idx="' + i + '" title="Remove from quarantine">\u2715</button>' +
                '</li>'
            ).join('') +
        '</ul>';
        contentEl.querySelectorAll('.quarantine-remove').forEach(btn => {
            btn.addEventListener('click', () => {
                quarantinedFiles.splice(parseInt(btn.dataset.idx, 10), 1);
                scanRenderQuarantine();
            });
        });
    }
}

function scanShowResults() {
    const placeholder = document.getElementById('scan-placeholder');
    const results     = document.getElementById('scan-results-area');
    if (placeholder) placeholder.style.display = 'none';
    if (results)     results.style.display = '';
}

function scanRenderConfidence() {
    const bar   = document.getElementById('scan-confidence-bar');
    const lbl   = document.getElementById('scan-confidence-label');
    const badge = document.getElementById('scan-confidence-badge');
    if (!scanResult || !bar) return;
    bar.style.display = '';
    bar.className = 'scan-confidence-bar ' + (scanResult.is_malicious ? 'confidence-danger' : 'confidence-safe');
    if (lbl)   lbl.textContent = 'Model Confidence: ' + scanResult.confidence + '%';
    if (badge) {
        badge.textContent = scanResult.prediction;
        badge.className   = 'confidence-badge ' + (scanResult.is_malicious ? 'badge-malware' : 'badge-benign');
    }
}

function scanRenderModal() {
    const body       = document.getElementById('logs-modal-body');
    const title      = document.getElementById('logs-modal-title');
    const banner     = document.getElementById('logs-modal-banner');
    const footer     = document.getElementById('logs-modal-footer');
    const confEl     = document.getElementById('logs-modal-confidence');
    if (!body) return;

    if (title && scanFileInfo) title.textContent = 'AI Analysis Logs: ' + scanFileInfo.name;

    if (banner) {
        if (scanResult) {
            banner.style.display = '';
            banner.className = 'logs-modal-banner ' + (scanResult.is_malicious ? 'banner-danger' : 'banner-safe');
            banner.textContent = 'Scan Completed\u00a0|\u00a0Model Confidence: ' + scanResult.confidence + '%';
        } else {
            banner.style.display = 'none';
        }
    }

    body.innerHTML = scanLogs.map(log => {
        const entry = (log.status === 'success' && log.text.indexOf('hash') !== -1 && scanFileInfo)
            ? { text: log.text + ' (' + scanFileInfo.hash + ')', status: log.status }
            : log;
        return scanRenderLogEntry(entry);
    }).join('');

    scanAppendModalResult(body);

    if (footer) {
        if (scanResult) {
            footer.style.display = '';
            if (confEl) confEl.textContent = 'Model Confidence: ' + scanResult.confidence + '%';
        } else {
            footer.style.display = 'none';
        }
    }
}

// Append behavioral patterns + final classification to the modal body, then update footer.
// Called both from scanRenderModal (full rebuild) and from the live result handler.
function scanAppendModalResult(bodyEl) {
    if (!scanResult) return;
    const body   = bodyEl || document.getElementById('logs-modal-body');
    const footer = document.getElementById('logs-modal-footer');
    const confEl = document.getElementById('logs-modal-confidence');
    const banner = document.getElementById('logs-modal-banner');
    if (!body) return;

    // Update banner
    if (banner) {
        banner.style.display = '';
        banner.className = 'logs-modal-banner ' + (scanResult.is_malicious ? 'banner-danger' : 'banner-safe');
        banner.textContent = 'Scan Completed\u00a0|\u00a0Model Confidence: ' + scanResult.confidence + '%';
    }

    body.scrollTop = body.scrollHeight;

    // Footer
    if (footer) {
        footer.style.display = '';
        if (confEl) confEl.textContent = 'Model Confidence: ' + scanResult.confidence + '%';
    }
}

async function handleScan(selectedFile) {
    if (!selectedFile) return;
    if (scanEs) { scanEs.close(); scanEs = null; }

    scanFile               = selectedFile;
    scanResult             = null;
    scanLogs               = [];
    scanBehavioralPatterns = [];
    scanLogsVisible        = true;

    scanShowResults();

    const logsList = document.getElementById('scan-logs-list');
    if (logsList)   logsList.innerHTML = '';
    const logsSection = document.getElementById('scan-logs-section');
    if (logsSection) logsSection.style.display = 'none';
    const confBar = document.getElementById('scan-confidence-bar');
    if (confBar)   confBar.style.display = 'none';
    const stopBtn = document.getElementById('scan-stop-btn');
    if (stopBtn)   stopBtn.style.display = '';

    scanSetProgress(5);

    const hash  = await scanComputeHash(selectedFile);
    scanFileInfo = {
        name : selectedFile.name,
        size : scanFormatFileSize(selectedFile.size),
        type : scanGetFileType(selectedFile.name),
        hash,
    };

    const nameEl = document.getElementById('scan-file-name');
    if (nameEl) nameEl.textContent = 'Scanning: ' + selectedFile.name;

    const metaGrid = document.getElementById('scan-meta-grid');
    if (metaGrid) {
        metaGrid.innerHTML =
            '<div><span class="scan-meta-label">File Name:</span> <span>' + scanFileInfo.name + '</span></div>' +
            '<div><span class="scan-meta-label">Size:</span> <span>' + scanFileInfo.size + '</span></div>' +
            '<div><span class="scan-meta-label">Type:</span> <span>' + scanFileInfo.type + '</span></div>' +
            '<div><span class="scan-meta-label">Hash:</span> <span class="scan-hash">' + scanFileInfo.hash + '</span></div>';
    }

    const token = localStorage.getItem('access_token');

    try {
        const formData = new FormData();
        formData.append('file', selectedFile);

        const res = await fetch(API_BASE + '/predict/staged?run_sandbox=true', {
            method  : 'POST',
            headers : token ? { 'Authorization': 'Bearer ' + token } : {},
            body    : formData,
        });

        if (!res.ok) {
            const msg = await res.text();
            throw new Error('HTTP ' + res.status + ': ' + msg);
        }

        const { job_id } = await res.json();

        const es = new EventSource(API_BASE + '/scan/' + job_id + '/stream?token=' + encodeURIComponent(token || ''));
        scanEs = es;
        let logCount = 0;

        es.onmessage = (e) => {
            let msg;
            try { msg = JSON.parse(e.data); } catch { return; }

            if (msg.type === 'log') {
                logCount++;
                scanSetProgress(Math.min(90, 5 + logCount * 6));
                scanAddLog(msg.msg, 'success');

            } else if (msg.type === 'result') {
                const data = msg.data;
                scanSetProgress(100);
                scanAddLog('✔ Final classification: ' + data.prediction_label, 'success');
                scanResult = {
                    confidence   : (data.confidence * 100).toFixed(1),
                    is_malicious : data.is_malicious,
                    prediction   : data.prediction_label,
                    method       : data.detection_method,
                    scan_id      : data.scan_id || null,
                };

                if (data.is_malicious) {
                    quarantinedFiles.push({
                        name       : selectedFile.name,
                        date       : new Date().toLocaleString(),
                        confidence : (data.confidence * 100).toFixed(1) + '%',
                    });
                    scanRenderQuarantine();
                }

                const overlay = document.getElementById('logs-modal-overlay');
                if (overlay && overlay.style.display !== 'none') {
                    scanAppendModalResult(null);
                }

                scanRenderConfidence();
                if (stopBtn) stopBtn.style.display = 'none';
                es.close();
                scanEs = null;
                // Sync sidebar + charts with the new detection
                refreshDashboardStats();

            } else if (msg.type === 'error') {
                scanAddLog(msg.msg, 'error');
                scanSetProgress(0);
                if (stopBtn) stopBtn.style.display = 'none';
                es.close();
                scanEs = null;
            }
        };

        es.onerror = () => {
            scanAddLog('Stream connection lost', 'error');
            if (stopBtn) stopBtn.style.display = 'none';
            es.close();
            scanEs = null;
        };

    } catch (err) {
        console.error('Scan error:', err);
        scanAddLog('Scan failed \u2014 ' + err.message, 'error');
        scanSetProgress(0);
        if (stopBtn) stopBtn.style.display = 'none';
    }
}

function handleStop() {
    if (scanEs) { scanEs.close(); scanEs = null; }
    scanSetProgress(0);
    scanAddLog('Scan stopped by user', 'error');
    const stopBtn = document.getElementById('scan-stop-btn');
    if (stopBtn) stopBtn.style.display = 'none';
}

function initScanPanel() {
    const fileBtn      = document.getElementById('scan-file-btn');
    const fileInput    = document.getElementById('scan-file-input');
    const dropzone     = document.getElementById('scan-dropzone');
    const stopBtn      = document.getElementById('scan-stop-btn');
    const expandBtn    = document.getElementById('scan-logs-expand');
    const toggleBtn    = document.getElementById('scan-logs-toggle');
    const overlay      = document.getElementById('logs-modal-overlay');
    const closeBtn     = document.getElementById('logs-modal-close');
    const closeBtnFt   = document.getElementById('logs-modal-close-btn');

    if (fileBtn)   fileBtn.addEventListener('click', () => fileInput && fileInput.click());

    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            const f = e.target.files[0];
            if (f) handleScan(f);
        });
    }

    if (dropzone) {
        dropzone.addEventListener('dragover',  (e) => { e.preventDefault(); dropzone.classList.add('scan-dropzone-active'); });
        dropzone.addEventListener('dragleave', ()  => dropzone.classList.remove('scan-dropzone-active'));
        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('scan-dropzone-active');
            const f = e.dataTransfer.files[0];
            if (f) handleScan(f);
        });
    }

    if (stopBtn)   stopBtn.addEventListener('click', handleStop);

    if (expandBtn) {
        expandBtn.addEventListener('click', () => {
            scanRenderModal();
            if (overlay) overlay.style.display = '';
        });
    }

    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            scanLogsVisible = !scanLogsVisible;
            const list = document.getElementById('scan-logs-list');
            if (list) list.style.display = scanLogsVisible ? '' : 'none';
            toggleBtn.textContent = scanLogsVisible ? 'Hide Scan Logs' : 'Show Scan Logs';
        });
    }

    if (overlay) {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) overlay.style.display = 'none';
        });
    }

    if (closeBtn)   closeBtn.addEventListener('click',   () => { if (overlay) overlay.style.display = 'none'; });
    if (closeBtnFt) closeBtnFt.addEventListener('click', () => { if (overlay) overlay.style.display = 'none'; });
}

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
    populateDashboard();

    // --- Period filter buttons ---
    document.querySelectorAll('#bar-period-filters .period-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('#bar-period-filters .period-btn').forEach(b => b.classList.remove('period-btn-active'));
            btn.classList.add('period-btn-active');
            applyBarChartData(btn.dataset.period);
            animateBarChart();
        });
    });

    document.querySelectorAll('#line-period-filters .period-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('#line-period-filters .period-btn').forEach(b => b.classList.remove('period-btn-active'));
            btn.classList.add('period-btn-active');
            applyLineChartData(btn.dataset.period);
            animateLineChart();
        });
    });

    // Redraw charts on resize (debounced)
    let resizeTimer;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            drawLineChart(1);
            drawBarChart(1);
        }, 150);
    });

    initScanPanel();
});