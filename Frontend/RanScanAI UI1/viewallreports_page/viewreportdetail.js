// ============================================================
// RanScanAI  Report Detail / Preview — JavaScript
// ============================================================

const API_BASE_URL = 'http://127.0.0.1:8000';

// ---------- Legacy Mock Data Store (kept as offline fallback) ----------
const reportDataStore = {
    'R10': {
        id: 'R10', year: 2026, month: 'February',
        startDate: '1 February 2026', endDate: '28 February 2026', generated: '26 February 2026',
        records: [
            { file: 'invoice_final.pdf', date: '2026-02-03', classification: 'Benign', confidence: 0.97, threat: '—' },
            { file: 'system_patch_v2.exe', date: '2026-02-05', classification: 'Malicious', confidence: 0.94, threat: 'Ransomware' },
            { file: 'quarterly_report.docx', date: '2026-02-07', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'browser_update.exe', date: '2026-02-08', classification: 'Malicious', confidence: 0.88, threat: 'Trojan' },
            { file: 'family_photo.jpg', date: '2026-02-10', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'setup_crack.exe', date: '2026-02-12', classification: 'Malicious', confidence: 0.96, threat: 'Ransomware' },
            { file: 'notes_meeting.txt', date: '2026-02-14', classification: 'Benign', confidence: 0.98, threat: '—' },
            { file: 'driver_update.msi', date: '2026-02-16', classification: 'Malicious', confidence: 0.82, threat: 'Suspicious' },
            { file: 'budget_2026.xlsx', date: '2026-02-18', classification: 'Benign', confidence: 0.95, threat: '—' },
            { file: 'free_vpn_setup.exe', date: '2026-02-20', classification: 'Malicious', confidence: 0.91, threat: 'Ransomware' },
            { file: 'presentation_v3.pptx', date: '2026-02-22', classification: 'Benign', confidence: 0.97, threat: '—' },
            { file: 'keylogger_tool.exe', date: '2026-02-24', classification: 'Malicious', confidence: 0.93, threat: 'Trojan' },
            { file: 'readme_instructions.pdf', date: '2026-02-25', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'network_scanner.exe', date: '2026-02-26', classification: 'Malicious', confidence: 0.87, threat: 'Suspicious' },
        ]
    },
    'R09': {
        id: 'R09', year: 2026, month: 'January',
        startDate: '1 January 2026', endDate: '31 January 2026', generated: '31 January 2026',
        records: [
            { file: 'tax_return_2025.pdf', date: '2026-01-02', classification: 'Benign', confidence: 0.98, threat: '—' },
            { file: 'crypto_miner.exe', date: '2026-01-04', classification: 'Malicious', confidence: 0.95, threat: 'Ransomware' },
            { file: 'holiday_pics.zip', date: '2026-01-06', classification: 'Benign', confidence: 0.96, threat: '—' },
            { file: 'adobe_crack_v3.exe', date: '2026-01-09', classification: 'Malicious', confidence: 0.92, threat: 'Trojan' },
            { file: 'company_policy.docx', date: '2026-01-11', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'win_activator.exe', date: '2026-01-13', classification: 'Malicious', confidence: 0.90, threat: 'Ransomware' },
            { file: 'recipe_book.pdf', date: '2026-01-16', classification: 'Benign', confidence: 0.97, threat: '—' },
            { file: 'backdoor_tool.bat', date: '2026-01-19', classification: 'Malicious', confidence: 0.86, threat: 'Suspicious' },
            { file: 'project_plan.xlsx', date: '2026-01-22', classification: 'Benign', confidence: 0.98, threat: '—' },
            { file: 'fake_antivirus.exe', date: '2026-01-25', classification: 'Malicious', confidence: 0.93, threat: 'Ransomware' },
            { file: 'team_photo_2026.jpg', date: '2026-01-28', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'payload_dropper.dll', date: '2026-01-30', classification: 'Malicious', confidence: 0.91, threat: 'Trojan' },
        ]
    },
    'R08': {
        id: 'R08', year: 2025, month: 'December',
        startDate: '1 December 2025', endDate: '31 December 2025', generated: '31 December 2025',
        records: [
            { file: 'xmas_card.pdf', date: '2025-12-01', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'gift_tracker.xlsx', date: '2025-12-03', classification: 'Benign', confidence: 0.97, threat: '—' },
            { file: 'wannacry_variant.exe', date: '2025-12-05', classification: 'Malicious', confidence: 0.96, threat: 'Ransomware' },
            { file: 'year_end_report.docx', date: '2025-12-08', classification: 'Benign', confidence: 0.98, threat: '—' },
            { file: 'phishing_payload.exe', date: '2025-12-11', classification: 'Malicious', confidence: 0.89, threat: 'Trojan' },
            { file: 'music_playlist.m3u', date: '2025-12-14', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'ransomware_test.exe', date: '2025-12-17', classification: 'Malicious', confidence: 0.94, threat: 'Ransomware' },
            { file: 'invoice_dec.pdf', date: '2025-12-20', classification: 'Benign', confidence: 0.98, threat: '—' },
            { file: 'exploit_kit.js', date: '2025-12-23', classification: 'Malicious', confidence: 0.85, threat: 'Suspicious' },
            { file: 'backup_config.json', date: '2025-12-28', classification: 'Benign', confidence: 0.97, threat: '—' },
        ]
    },
    'R07': {
        id: 'R07', year: 2025, month: 'November',
        startDate: '1 November 2025', endDate: '30 November 2025', generated: '30 November 2025',
        records: [
            { file: 'meeting_notes.docx', date: '2025-11-02', classification: 'Benign', confidence: 0.98, threat: '—' },
            { file: 'encryptor.exe', date: '2025-11-05', classification: 'Malicious', confidence: 0.95, threat: 'Ransomware' },
            { file: 'cv_template.pdf', date: '2025-11-08', classification: 'Benign', confidence: 0.97, threat: '—' },
            { file: 'stealer_trojan.exe', date: '2025-11-11', classification: 'Malicious', confidence: 0.91, threat: 'Trojan' },
            { file: 'database_backup.sql', date: '2025-11-14', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'fake_update.msi', date: '2025-11-17', classification: 'Malicious', confidence: 0.88, threat: 'Suspicious' },
            { file: 'todo_list.txt', date: '2025-11-20', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'locker_ransomware.exe', date: '2025-11-24', classification: 'Malicious', confidence: 0.93, threat: 'Ransomware' },
            { file: 'travel_itinerary.pdf', date: '2025-11-28', classification: 'Benign', confidence: 0.96, threat: '—' },
        ]
    },
    'R06': {
        id: 'R06', year: 2025, month: 'October',
        startDate: '1 October 2025', endDate: '31 October 2025', generated: '31 October 2025',
        records: [
            { file: 'halloween_invite.png', date: '2025-10-01', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'darkside_payload.exe', date: '2025-10-04', classification: 'Malicious', confidence: 0.97, threat: 'Ransomware' },
            { file: 'sales_q3.xlsx', date: '2025-10-07', classification: 'Benign', confidence: 0.98, threat: '—' },
            { file: 'keylog_inject.dll', date: '2025-10-10', classification: 'Malicious', confidence: 0.90, threat: 'Trojan' },
            { file: 'training_manual.pdf', date: '2025-10-14', classification: 'Benign', confidence: 0.97, threat: '—' },
            { file: 'revil_sample.exe', date: '2025-10-18', classification: 'Malicious', confidence: 0.94, threat: 'Ransomware' },
            { file: 'wallpaper.jpg', date: '2025-10-22', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'obfuscated_script.ps1', date: '2025-10-26', classification: 'Malicious', confidence: 0.86, threat: 'Suspicious' },
            { file: 'audit_log.csv', date: '2025-10-30', classification: 'Benign', confidence: 0.98, threat: '—' },
        ]
    },
    'R05': {
        id: 'R05', year: 2025, month: 'September',
        startDate: '1 September 2025', endDate: '30 September 2025', generated: '30 September 2025',
        records: [
            { file: 'employee_handbook.pdf', date: '2025-09-02', classification: 'Benign', confidence: 0.98, threat: '—' },
            { file: 'conti_dropper.exe', date: '2025-09-05', classification: 'Malicious', confidence: 0.96, threat: 'Ransomware' },
            { file: 'birthday_card.png', date: '2025-09-08', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'remote_access.exe', date: '2025-09-12', classification: 'Malicious', confidence: 0.89, threat: 'Trojan' },
            { file: 'license_agreement.txt', date: '2025-09-15', classification: 'Benign', confidence: 0.97, threat: '—' },
            { file: 'lockbit_v3.exe', date: '2025-09-19', classification: 'Malicious', confidence: 0.95, threat: 'Ransomware' },
            { file: 'product_spec.docx', date: '2025-09-23', classification: 'Benign', confidence: 0.98, threat: '—' },
            { file: 'packed_malware.bin', date: '2025-09-27', classification: 'Malicious', confidence: 0.84, threat: 'Suspicious' },
        ]
    },
    'R04': {
        id: 'R04', year: 2025, month: 'August',
        startDate: '1 August 2025', endDate: '31 August 2025', generated: '31 August 2025',
        records: [
            { file: 'summer_photos.zip', date: '2025-08-02', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'maze_ransom.exe', date: '2025-08-06', classification: 'Malicious', confidence: 0.93, threat: 'Ransomware' },
            { file: 'quarterly_review.pptx', date: '2025-08-10', classification: 'Benign', confidence: 0.97, threat: '—' },
            { file: 'info_stealer.exe', date: '2025-08-14', classification: 'Malicious', confidence: 0.91, threat: 'Trojan' },
            { file: 'workout_plan.pdf', date: '2025-08-18', classification: 'Benign', confidence: 0.98, threat: '—' },
            { file: 'ransom_note_gen.exe', date: '2025-08-22', classification: 'Malicious', confidence: 0.95, threat: 'Ransomware' },
            { file: 'contact_list.csv', date: '2025-08-26', classification: 'Benign', confidence: 0.96, threat: '—' },
        ]
    },
    'R03': {
        id: 'R03', year: 2025, month: 'July',
        startDate: '1 July 2025', endDate: '31 July 2025', generated: '31 July 2025',
        records: [
            { file: 'vacation_plan.docx', date: '2025-07-03', classification: 'Benign', confidence: 0.98, threat: '—' },
            { file: 'hive_payload.exe', date: '2025-07-07', classification: 'Malicious', confidence: 0.94, threat: 'Ransomware' },
            { file: 'menu_design.pdf', date: '2025-07-11', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'dropper_bot.exe', date: '2025-07-15', classification: 'Malicious', confidence: 0.87, threat: 'Trojan' },
            { file: 'server_logs.txt', date: '2025-07-19', classification: 'Benign', confidence: 0.97, threat: '—' },
            { file: 'cryptolocker_v4.exe', date: '2025-07-24', classification: 'Malicious', confidence: 0.96, threat: 'Ransomware' },
            { file: 'inventory_list.xlsx', date: '2025-07-28', classification: 'Benign', confidence: 0.98, threat: '—' },
        ]
    },
    'R02': {
        id: 'R02', year: 2025, month: 'June',
        startDate: '1 June 2025', endDate: '30 June 2025', generated: '30 June 2025',
        records: [
            { file: 'graduation_invite.pdf', date: '2025-06-02', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'ryuk_variant.exe', date: '2025-06-06', classification: 'Malicious', confidence: 0.95, threat: 'Ransomware' },
            { file: 'receipt_june.pdf', date: '2025-06-10', classification: 'Benign', confidence: 0.97, threat: '—' },
            { file: 'agent_tesla.exe', date: '2025-06-14', classification: 'Malicious', confidence: 0.92, threat: 'Trojan' },
            { file: 'event_schedule.xlsx', date: '2025-06-19', classification: 'Benign', confidence: 0.98, threat: '—' },
            { file: 'cerber_ransom.exe', date: '2025-06-24', classification: 'Malicious', confidence: 0.93, threat: 'Ransomware' },
        ]
    },
    'R01': {
        id: 'R01', year: 2025, month: 'May',
        startDate: '1 May 2025', endDate: '31 May 2025', generated: '31 May 2025',
        records: [
            { file: 'work_schedule.docx', date: '2025-05-03', classification: 'Benign', confidence: 0.98, threat: '—' },
            { file: 'petya_dropper.exe', date: '2025-05-07', classification: 'Malicious', confidence: 0.96, threat: 'Ransomware' },
            { file: 'garden_plan.pdf', date: '2025-05-12', classification: 'Benign', confidence: 0.99, threat: '—' },
            { file: 'emotet_dll.dll', date: '2025-05-17', classification: 'Malicious', confidence: 0.90, threat: 'Trojan' },
            { file: 'shopping_list.txt', date: '2025-05-22', classification: 'Benign', confidence: 0.97, threat: '—' },
            { file: 'sodinokibi.exe', date: '2025-05-28', classification: 'Malicious', confidence: 0.94, threat: 'Ransomware' },
        ]
    }
};

// ---------- Utility Helpers ----------

function getYearMonthFromUrl() {
    const params = new URLSearchParams(window.location.search);
    const year  = parseInt(params.get('year'),  10) || null;
    const month = parseInt(params.get('month'), 10) || null;
    return { year, month };
}

function computeStats(records) {
    const total = records.length;
    const benign = records.filter(r => r.classification === 'Benign').length;
    const malicious = total - benign;
    const rate = total > 0 ? ((malicious / total) * 100).toFixed(1) : '0.0';

    // Threat sub-types
    const threats = {};
    records.filter(r => r.classification === 'Malicious').forEach(r => {
        threats[r.threat] = (threats[r.threat] || 0) + 1;
    });

    return { total, benign, malicious, rate, threats };
}

function formatDate(dateStr) {
    const d = new Date(dateStr);
    return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
}

// ---------- DOM Population ----------

function populateReport(data) {
    const stats = computeStats(data.records);

    // Header
    document.getElementById('page-heading').textContent = `${data.month} ${data.year} Report`;
    document.getElementById('report-id-badge').textContent = data.id;
    document.getElementById('report-title').textContent = `${data.month} ${data.year} Detection Summary Report`;
    document.getElementById('report-period').textContent = `Reporting Period: ${data.startDate} – ${data.endDate}`;
    document.getElementById('report-generated').textContent = `Generated on: ${data.generated}`;

    // KPI values
    document.getElementById('kpi-total').textContent = stats.total;
    document.getElementById('kpi-benign').textContent = stats.benign;
    document.getElementById('kpi-malicious').textContent = stats.malicious;
    document.getElementById('kpi-rate').textContent = `${stats.rate}%`;

    if (stats.total === 0) {
        // No data for this month
        const tbody = document.getElementById('detail-tbody');
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:48px 16px;color:#8B92A8;font-size:.9rem;">No scan data recorded for ${data.month} ${data.year}.<br><small>Scan files to populate this report.</small></td></tr>`;
        const summaryEl = document.getElementById('summary-overview');
        if (summaryEl) summaryEl.textContent = `No scan activity was recorded during ${data.month} ${data.year}.`;
        const threatEl = document.getElementById('summary-threat');
        if (threatEl) threatEl.textContent = '';
        const recEl = document.getElementById('summary-recommendation');
        if (recEl) recEl.textContent = 'Start scanning files to generate detailed monthly reports.';
        return;
    }

    // Charts
    drawDonutChart(stats.benign, stats.malicious);
    drawBarChart(stats);

    // Table
    populateTable(data.records);

    // Summary text
    populateSummary(stats, data);
}

function populateTable(records) {
    const tbody = document.getElementById('detail-tbody');
    tbody.innerHTML = '';

    records.forEach((rec, i) => {
        const isBenign = rec.classification === 'Benign';
        const confPercent = Math.round(rec.confidence * 100);
        const confClass = confPercent >= 90 ? 'high' : confPercent >= 75 ? 'medium' : 'low';

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${i + 1}</td>
            <td>${rec.file}</td>
            <td>${formatDate(rec.date)}</td>
            <td>
                <span class="badge ${isBenign ? 'badge-benign' : 'badge-malicious'}">
                    <span class="badge-dot"></span>
                    ${rec.classification}
                </span>
            </td>
            <td>
                <span class="confidence-bar-wrap">
                    <span class="confidence-bar">
                        <span class="confidence-bar-fill ${confClass}" style="width: ${confPercent}%"></span>
                    </span>
                    <span class="confidence-text">${confPercent}%</span>
                </span>
            </td>
            <td>${rec.threat}</td>
        `;
        tbody.appendChild(tr);
    });
}

function populateSummary(stats, data) {
    document.getElementById('summary-overview').textContent =
        `During ${data.month} ${data.year}, a total of ${stats.total} files were scanned. ` +
        `${stats.benign} files were classified as benign and ${stats.malicious} were flagged as malicious, ` +
        `resulting in a ${stats.rate}% overall threat rate.`;

    if (parseFloat(stats.rate) >= 40) {
        document.getElementById('summary-threat').textContent =
            `The threat rate of ${stats.rate}% is elevated and requires immediate attention. ` +
            `The most common threat types detected were ransomware and trojan variants. Critical review is recommended.`;
    } else if (parseFloat(stats.rate) >= 20) {
        document.getElementById('summary-threat').textContent =
            `The threat rate of ${stats.rate}% indicates moderate risk. ` +
            `Malicious files were identified across multiple categories. Continuous monitoring is advised.`;
    } else {
        document.getElementById('summary-threat').textContent =
            `The threat rate of ${stats.rate}% is within acceptable levels. ` +
            `Security posture remains strong with minimal threats detected during this period.`;
    }

    document.getElementById('summary-recommendation').textContent =
        `Ensure all endpoints have up-to-date antivirus definitions. Review quarantined files promptly. ` +
        `Consider running a full system scan on devices that had malicious detections. ` +
        `Regular user security awareness training is recommended.`;
}

// ---------- Donut Chart (Canvas) ----------

function drawDonutChart(benign, malicious) {
    const canvas = document.getElementById('donut-chart');
    const ctx = canvas.getContext('2d');
    const total = benign + malicious;
    const dpr = window.devicePixelRatio || 1;

    canvas.width = 220 * dpr;
    canvas.height = 220 * dpr;
    canvas.style.width = '220px';
    canvas.style.height = '220px';
    ctx.scale(dpr, dpr);

    const cx = 110, cy = 110, radius = 85, lineWidth = 28;
    const slices = [
        { value: benign,    color: '#16A34A', label: 'Benign' },
        { value: malicious, color: '#DC2626', label: 'Malicious' },
    ];

    // Draw slices
    let startAngle = -Math.PI / 2;
    slices.forEach(slice => {
        if (slice.value === 0) return;
        const sliceAngle = (slice.value / total) * 2 * Math.PI;
        ctx.beginPath();
        ctx.arc(cx, cy, radius, startAngle, startAngle + sliceAngle);
        ctx.strokeStyle = slice.color;
        ctx.lineWidth = lineWidth;
        ctx.lineCap = 'butt';
        ctx.stroke();
        startAngle += sliceAngle;
    });

    // Centre text
    ctx.fillStyle = '#111A3A';
    ctx.font = '800 28px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total, cx, cy - 8);
    ctx.font = '500 13px Inter, sans-serif';
    ctx.fillStyle = '#8B92A8';
    ctx.fillText('Total Files', cx, cy + 14);

    // Legend
    const legendEl = document.getElementById('donut-legend');
    legendEl.innerHTML = slices.map(s => {
        const pct = total > 0 ? ((s.value / total) * 100).toFixed(1) : 0;
        return `
            <div class="legend-item">
                <span class="legend-color" style="background:${s.color}"></span>
                <span class="legend-text"><strong>${s.value}</strong> ${s.label} (${pct}%)</span>
            </div>
        `;
    }).join('');
}

// ---------- Bar Chart (CSS) ----------

function drawBarChart(stats) {
    const container = document.getElementById('bar-chart');
    container.innerHTML = '';

    // Combine benign + threat subtypes
    const entries = [
        { label: 'Benign', count: stats.benign, cls: 'benign' },
    ];

    // Sort threat types by count descending
    const sortedThreats = Object.entries(stats.threats)
        .sort((a, b) => b[1] - a[1]);
    sortedThreats.forEach(([type, count]) => {
        entries.push({ label: type, count, cls: type.toLowerCase() });
    });

    const maxCount = Math.max(...entries.map(e => e.count), 1);

    entries.forEach(entry => {
        const widthPct = Math.max((entry.count / maxCount) * 100, 4);
        const row = document.createElement('div');
        row.className = 'bar-row';
        row.innerHTML = `
            <span class="bar-label">${entry.label}</span>
            <span class="bar-track">
                <span class="bar-fill ${entry.cls}" style="width: 0%"></span>
            </span>
            <span class="bar-count">${entry.count}</span>
        `;
        container.appendChild(row);

        // Animate
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                row.querySelector('.bar-fill').style.width = `${widthPct}%`;
            });
        });
    });
}

// ---------- PDF Download ----------

function downloadPDF() {
    window.print();
}

// ---------- Initialise ----------

document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById('download-pdf-btn').addEventListener('click', downloadPDF);

    const { year, month } = getYearMonthFromUrl();

    if (!year || !month) {
        document.getElementById('report-title').textContent = 'Report not found — missing year/month in URL.';
        return;
    }

    try {
        const res = await fetch(`${API_BASE_URL}/api/reports/${year}/${month}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const apiData = await res.json();

        // Normalise API field names to match populateReport() expectations
        const data = {
            id:        apiData.id,
            year:      apiData.year,
            month:     apiData.month_name,   // populateReport uses string month
            startDate: apiData.start_date,
            endDate:   apiData.end_date,
            generated: apiData.generated,
            records:   apiData.records,
        };

        populateReport(data);

    } catch (err) {
        console.error('Failed to load report:', err);
        document.getElementById('report-title').textContent = 'Could not load report from server.';
        document.getElementById('report-period').textContent = 'Make sure the backend is running at ' + API_BASE_URL;
    }

    // Auto-print if opened with ?print=1 (from download button on report list)
    const params = new URLSearchParams(window.location.search);
    if (params.get('print') === '1') {
        setTimeout(() => window.print(), 600);
    }
});
