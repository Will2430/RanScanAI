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
                <button class="eye-btn" data-id="${row.id}" aria-label="View details for ${row.file_name}" title="View scan details">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });

    // Attach click handlers
    tbody.querySelectorAll('.eye-btn').forEach(btn => {
        btn.addEventListener('click', () => openDetailModal(parseInt(btn.dataset.id, 10)));
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

// ── Detail Modal ───────────────────────────────────────────────

function formatFileSize(bytes) {
    if (bytes == null) return '—';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(2) + ' MB';
}

async function openDetailModal(detectionId) {
    const modal = document.getElementById('detail-modal');
    const body  = document.getElementById('modal-body');

    // Show loading state
    body.innerHTML = `<div class="modal-loading">Loading…</div>`;
    modal.classList.add('active');

    try {
        const res = await fetch(`${API_BASE_URL}/api/detections/${detectionId}`, { headers: authHeaders() });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();

        const outputLabel = d.is_malicious ? 'Malicious' : 'Benign';
        const outputClass = d.is_malicious ? 'detail-malicious' : 'detail-benign';
        const confidencePct = (d.confidence * 100).toFixed(1);

        body.innerHTML = `
            <div class="detail-grid">
                <div class="detail-item">
                    <span class="detail-label">File Name</span>
                    <span class="detail-value mono">${d.file_name || '—'}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">File Path</span>
                    <span class="detail-value mono">${d.file_path || '—'}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">File Size</span>
                    <span class="detail-value">${formatFileSize(d.file_size)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Output</span>
                    <span class="detail-value ${outputClass}">${outputLabel}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Prediction Label</span>
                    <span class="detail-value ${outputClass}">${d.prediction_label || '—'}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Model Type</span>
                    <span class="detail-value">${d.model_type || '—'}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Confidence</span>
                    <span class="detail-value">
                        <span class="confidence-bar-wrap">
                            <span class="confidence-bar" style="width:${confidencePct}%;background:${d.is_malicious ? '#DC2626' : '#16A34A'}"></span>
                        </span>
                        ${confidencePct}%
                    </span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Completion Time</span>
                    <span class="detail-value">${d.scan_time_ms != null ? d.scan_time_ms + ' ms' : '—'}</span>
                </div>
            </div>
        `;
    } catch (err) {
        console.error('Failed to load detection detail:', err);
        body.innerHTML = `<div class="modal-error">Failed to load details. Please try again.</div>`;
    }
}

function closeDetailModal() {
    document.getElementById('detail-modal').classList.remove('active');
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

    // Modal close handlers
    document.getElementById('modal-close').addEventListener('click', closeDetailModal);
    document.getElementById('detail-modal').addEventListener('click', (e) => {
        if (e.target === e.currentTarget) closeDetailModal();
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeDetailModal();
    });
});
