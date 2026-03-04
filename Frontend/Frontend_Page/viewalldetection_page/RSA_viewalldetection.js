// view all detections page — connected to backend API

// ── Configuration ──────────────────────────────────────────────
const API_BASE_URL = 'http://127.0.0.1:8000';   // Change if backend is hosted elsewhere

// ── Auth helper ────────────────────────────────────────────────
function authHeaders() {
    const token = localStorage.getItem('access_token');
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}

// ── Helpers ────────────────────────────────────────────────────

function padId(value) {
    return `D${String(value).padStart(3, '0')}`;
}

function renderDetectionRows(rows) {
    const tbody = document.getElementById('detections-tbody');
    tbody.innerHTML = '';

    if (rows.length === 0) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="4" style="text-align:center;padding:48px 16px;color:#8B92A8;">
            <div style="font-size:1.1rem;font-weight:600;margin-bottom:6px;">No Detection Events Yet</div>
            <div style="font-size:.82rem;">Scan files using the browser extension or API to see results here.</div>
        </td>`;
        tbody.appendChild(tr);
        return;
    }

    rows.forEach((row) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${padId(row.id)}</td>
            <td>${row.file_name}</td>
            <td>${row.display_time}</td>
            <td>
                <a class="view-detail-btn" href="/detection/${row.id}" aria-label="View details for ${row.file_name}" title="View incident details">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                    <span>View Details</span>
                </a>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

let allRows = [];
let sortDirection = 'none'; // 'none' | 'asc' | 'desc'

function updateSortIcon() {
    const icon = document.getElementById('sort-icon');
    const header = document.getElementById('sort-date-header');
    if (!icon) return;
    if (sortDirection === 'asc') {
        icon.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5M5 12l7-7 7 7"/></svg>`;
        header.classList.add('active');
        header.setAttribute('aria-sort', 'ascending');
    } else if (sortDirection === 'desc') {
        icon.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12l7 7 7-7"/></svg>`;
        header.classList.add('active');
        header.setAttribute('aria-sort', 'descending');
    } else {
        icon.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12l7 7 7-7"/></svg>`;
        header.classList.remove('active');
        header.setAttribute('aria-sort', 'none');
    }
}

function toggleDateSort() {
    if (sortDirection === 'none' || sortDirection === 'desc') {
        sortDirection = 'asc';
    } else {
        sortDirection = 'desc';
    }
    updateSortIcon();
    renderDetectionRows(getSortedRows());
}

function getSortedRows() {
    const rows = [...allRows];
    if (sortDirection === 'asc') {
        rows.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    } else if (sortDirection === 'desc') {
        rows.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }
    return rows;
}

// ── Fetch from API ─────────────────────────────────────────────

async function fetchDetections() {
    const countEl = document.getElementById('detections-count');

    try {
        const response = await fetch(`${API_BASE_URL}/api/detections`, { headers: authHeaders() });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        // Update the count metric
        countEl.innerHTML =
            `<span class="detections-count">${data.count}</span>` +
            `<span class="detections-sub">New Detections</span>`;

        // Store rows for sorting
        allRows = data.detections;

        // Render (API already returns newest-first)
        renderDetectionRows(allRows);

    } catch (error) {
        console.error('Failed to fetch detections:', error);

        // Show friendly error in the UI
        countEl.innerHTML =
            `<span class="detections-count">—</span>` +
            `<span class="detections-sub">Unable to load detections</span>`;

        const tbody = document.getElementById('detections-tbody');
        tbody.innerHTML = `
            <tr>
                <td colspan="3" style="text-align:center;padding:32px;color:#C83A2B;">
                    Could not connect to the server.<br>
                    <small style="color:#8B92A8;">Make sure the backend is running at ${API_BASE_URL}</small>
                </td>
            </tr>
        `;
    }
}

// ── Initialise ─────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    fetchDetections();

    const sortHeader = document.getElementById('sort-date-header');
    sortHeader.addEventListener('click', toggleDateSort);
    sortHeader.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            toggleDateSort();
        }
    });
});
