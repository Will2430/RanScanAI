// view all reports page — connected to backend API

const API_BASE_URL = 'http://127.0.0.1:8000';

async function fetchReports() {
    const tbody = document.getElementById('reports-tbody');
    tbody.innerHTML = `<tr><td colspan="2" style="text-align:center;padding:32px;color:#8B92A8;">Loading reports…</td></tr>`;

    try {
        const res = await fetch(`${API_BASE_URL}/api/reports?limit=60`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const reports = data.reports || [];

        tbody.innerHTML = '';

        if (reports.length === 0) {
            tbody.innerHTML = `<tr><td colspan="2" style="text-align:center;padding:48px 16px;color:#8B92A8;">
                <div style="font-size:1.1rem;font-weight:600;margin-bottom:6px;">No Reports Available Yet</div>
                <div style="font-size:.82rem;">Scan files to generate monthly reports automatically.</div>
            </td></tr>`;
            return;
        }

        reports.forEach(r => {
            const detailUrl = `viewreportdetail.html?year=${r.year}&month=${r.month}`;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${r.id}</td>
                <td>
                    <span class="report-cell">
                        <span class="report-name">${r.label}</span>
                        <span class="report-icons">
                            <button class="action-icon-btn view-btn"
                                data-year="${r.year}" data-month="${r.month}"
                                title="View Report" aria-label="View Report">
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                            </button>
                            <button class="action-icon-btn download-btn"
                                data-year="${r.year}" data-month="${r.month}"
                                title="Download Report" aria-label="Download Report">
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                            </button>
                        </span>
                    </span>
                </td>
            `;
            tbody.appendChild(tr);
        });

    } catch (err) {
        console.error('Failed to fetch reports:', err);
        tbody.innerHTML = `
            <tr>
                <td colspan="2" style="text-align:center;padding:32px;color:#C83A2B;">
                    Could not connect to the server.<br>
                    <small style="color:#8B92A8;">Make sure the backend is running at ${API_BASE_URL}</small>
                </td>
            </tr>
        `;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    fetchReports();

    // Delegate click events for view and download buttons
    document.getElementById('reports-tbody').addEventListener('click', (e) => {
        const viewBtn = e.target.closest('.view-btn');
        const downloadBtn = e.target.closest('.download-btn');

        if (viewBtn) {
            const { year, month } = viewBtn.dataset;
            window.location.href = `viewreportdetail.html?year=${year}&month=${month}`;
        }

        if (downloadBtn) {
            const { year, month } = downloadBtn.dataset;
            const win = window.open(`viewreportdetail.html?year=${year}&month=${month}&print=1`, '_blank');
            if (win) {
                win.addEventListener('afterprint', () => win.close());
            }
        }
    });
});
