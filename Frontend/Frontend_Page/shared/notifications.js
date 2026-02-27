/**
 * RanScanAI — Notification Dropdown
 * Self-contained: inject this script on any page with a `.bell-btn` element.
 * Fetches the 8 most recent detections from the API and renders them
 * in a dropdown panel anchored to the bell button.
 */
(function () {
    'use strict';

    const API_BASE = 'http://127.0.0.1:8000';
    const MAX_ITEMS = 8;

    /* ── Auth helper ──────────────────────────────── */
    function authHeaders() {
        const t = localStorage.getItem('access_token');
        return t ? { Authorization: 'Bearer ' + t } : {};
    }

    /* ── Inject CSS (only once) ───────────────────── */
    function injectStyles() {
        if (document.getElementById('notif-panel-styles')) return;
        const style = document.createElement('style');
        style.id = 'notif-panel-styles';
        style.textContent = `
/* Notification panel wrapper — anchored to bell-btn parent */
.notif-anchor { position: relative; }

.notif-panel {
    position: absolute;
    top: calc(100% + 10px);
    right: 0;
    width: 360px;
    max-height: 460px;
    background: #ffffff;
    border-radius: 14px;
    box-shadow: 0 12px 40px rgba(15,23,42,.18), 0 2px 8px rgba(15,23,42,.08);
    z-index: 9999;
    opacity: 0;
    visibility: hidden;
    transform: translateY(-8px);
    transition: opacity .2s ease, transform .2s ease, visibility .2s;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}
.notif-panel.open {
    opacity: 1;
    visibility: visible;
    transform: translateY(0);
}

/* Header */
.notif-panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px 12px;
    border-bottom: 1px solid #F1F3F9;
}
.notif-panel-title {
    font-size: 0.92rem;
    font-weight: 700;
    color: #1E293B;
    margin: 0;
}
.notif-panel-badge {
    font-size: 0.7rem;
    font-weight: 600;
    background: #EEF2FF;
    color: #4F46E5;
    padding: 2px 8px;
    border-radius: 999px;
}

/* List */
.notif-list {
    flex: 1;
    overflow-y: auto;
    padding: 6px 0;
}

/* Single item */
.notif-item {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px 20px;
    cursor: pointer;
    transition: background .12s ease;
    text-decoration: none;
    color: inherit;
}
.notif-item:hover {
    background: #F8FAFC;
}

.notif-icon-wrap {
    flex-shrink: 0;
    width: 36px; height: 36px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
}
.notif-icon-wrap.malicious {
    background: #FEF2F2;
    color: #DC2626;
}
.notif-icon-wrap.clean {
    background: #F0FDF4;
    color: #16A34A;
}

.notif-body {
    flex: 1;
    min-width: 0;
}
.notif-file {
    font-size: 0.82rem;
    font-weight: 600;
    color: #1E293B;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.notif-meta {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 3px;
}
.notif-result {
    font-size: 0.72rem;
    font-weight: 600;
    padding: 1px 7px;
    border-radius: 4px;
}
.notif-result.malicious {
    background: #FEF2F2;
    color: #DC2626;
}
.notif-result.clean {
    background: #F0FDF4;
    color: #16A34A;
}
.notif-time {
    font-size: 0.72rem;
    color: #94A3B8;
}

/* Empty state */
.notif-empty {
    padding: 40px 20px;
    text-align: center;
    color: #94A3B8;
    font-size: 0.84rem;
}
.notif-empty svg {
    display: block;
    margin: 0 auto 10px;
    opacity: .4;
}

/* Footer */
.notif-panel-footer {
    border-top: 1px solid #F1F3F9;
    padding: 10px 20px;
    text-align: center;
}
.notif-panel-footer a {
    font-size: 0.78rem;
    font-weight: 600;
    color: #4F46E5;
    text-decoration: none;
}
.notif-panel-footer a:hover {
    text-decoration: underline;
}

/* Loading spinner */
.notif-loading {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 36px 20px;
    color: #94A3B8;
    font-size: .82rem;
    gap: 8px;
}
.notif-spinner {
    width: 18px; height: 18px;
    border: 2px solid #E2E8F0;
    border-top: 2px solid #4F46E5;
    border-radius: 50%;
    animation: notifSpin .6s linear infinite;
}
@keyframes notifSpin { to { transform: rotate(360deg); } }

/* Hide red dot when no malicious items */
.bell-btn .notif-dot.hidden { display: none; }
`;
        document.head.appendChild(style);
    }

    /* ── Build panel HTML ─────────────────────────── */
    function createPanel() {
        const panel = document.createElement('div');
        panel.className = 'notif-panel';
        panel.id = 'notif-panel';
        panel.innerHTML = `
            <div class="notif-panel-header">
                <h3 class="notif-panel-title">Notifications</h3>
                <span class="notif-panel-badge" id="notif-count">0 new</span>
            </div>
            <div class="notif-list" id="notif-list">
                <div class="notif-loading"><div class="notif-spinner"></div>Loading…</div>
            </div>
            <div class="notif-panel-footer">
                <a href="" id="notif-view-all">View All Detections</a>
            </div>
        `;
        return panel;
    }

    /* ── Time-ago helper ──────────────────────────── */
    function timeAgo(dateStr) {
        const d = new Date(dateStr);
        const now = new Date();
        const diffMs = now - d;
        const mins = Math.floor(diffMs / 60000);
        if (mins < 1) return 'Just now';
        if (mins < 60) return mins + 'm ago';
        const hrs = Math.floor(mins / 60);
        if (hrs < 24) return hrs + 'h ago';
        const days = Math.floor(hrs / 24);
        if (days < 7) return days + 'd ago';
        return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
    }

    /* ── Render items ─────────────────────────────── */
    function renderItems(detections) {
        const list = document.getElementById('notif-list');
        if (!list) return;

        if (!detections || detections.length === 0) {
            list.innerHTML = `
                <div class="notif-empty">
                    <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
                    No scan notifications yet.
                </div>`;
            return;
        }

        const maliciousCount = detections.filter(d => d.is_malicious).length;
        const badge = document.getElementById('notif-count');
        if (badge) {
            badge.textContent = maliciousCount > 0 ? maliciousCount + ' threat' + (maliciousCount > 1 ? 's' : '') : detections.length + ' scans';
            badge.style.background = maliciousCount > 0 ? '#FEF2F2' : '#EEF2FF';
            badge.style.color = maliciousCount > 0 ? '#DC2626' : '#4F46E5';
        }

        // Update red dot on bell
        const dot = document.querySelector('.bell-btn .notif-dot');
        if (dot) {
            dot.classList.toggle('hidden', maliciousCount === 0);
        }

        // Detect relative path to viewalldetection_page
        const detectionPageBase = resolveDetectionPath();

        list.innerHTML = detections.map(d => {
            const isMal = d.is_malicious;
            const icon = isMal
                ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
                : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
            const conf = d.confidence != null ? Math.round(d.confidence * 100) + '%' : '';
            return `
                <a class="notif-item" href="${detectionPageBase}">
                    <div class="notif-icon-wrap ${isMal ? 'malicious' : 'clean'}">${icon}</div>
                    <div class="notif-body">
                        <div class="notif-file" title="${d.file_name || ''}">${d.file_name || 'Unknown file'}</div>
                        <div class="notif-meta">
                            <span class="notif-result ${isMal ? 'malicious' : 'clean'}">${isMal ? 'Malicious ' + conf : 'Clean'}</span>
                            <span class="notif-time">${timeAgo(d.timestamp)}</span>
                        </div>
                    </div>
                </a>`;
        }).join('');
    }

    /* ── Resolve relative path to detection page ── */
    function resolveDetectionPath() {
        const path = window.location.pathname;
        if (path.includes('userdashboard_page')) return '../viewalldetection_page/RSA_viewalldetection.html';
        if (path.includes('viewlatestdetectiondetails_page')) return '../viewalldetection_page/RSA_viewalldetection.html';
        if (path.includes('viewalldetection_page')) return 'RSA_viewalldetection.html';
        if (path.includes('viewallreports_page')) return '../viewalldetection_page/RSA_viewalldetection.html';
        if (path.includes('userprofile_page')) return '../viewalldetection_page/RSA_viewalldetection.html';
        // Fallback
        return '/viewalldetection_page/RSA_viewalldetection.html';
    }

    /* ── Fetch detections ─────────────────────────── */
    async function fetchNotifications() {
        try {
            const res = await fetch(`${API_BASE}/api/detections?limit=${MAX_ITEMS}&malicious_only=false`, {
                headers: authHeaders()
            });
            if (!res.ok) throw new Error('API error');
            const data = await res.json();
            return data.detections || [];
        } catch (e) {
            console.warn('[Notifications] fetch failed:', e);
            return [];
        }
    }

    /* ── Init ─────────────────────────────────────── */
    function init() {
        const bellBtn = document.querySelector('.bell-btn');
        if (!bellBtn) return;

        injectStyles();

        // Wrap bell button in an anchor container for positioning
        const anchor = document.createElement('div');
        anchor.className = 'notif-anchor';
        anchor.style.display = 'inline-flex';
        bellBtn.parentNode.insertBefore(anchor, bellBtn);
        anchor.appendChild(bellBtn);

        // Create and attach panel
        const panel = createPanel();
        anchor.appendChild(panel);

        // Set "View All Detections" link
        const viewAllLink = panel.querySelector('#notif-view-all');
        if (viewAllLink) viewAllLink.href = resolveDetectionPath();

        let loaded = false;

        // Toggle panel
        bellBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            e.stopPropagation();
            const isOpen = panel.classList.toggle('open');

            if (isOpen && !loaded) {
                const detections = await fetchNotifications();
                renderItems(detections);
                loaded = true;
            }
        });

        // Close when clicking outside
        document.addEventListener('click', (e) => {
            if (!anchor.contains(e.target)) {
                panel.classList.remove('open');
            }
        });

        // Close on Escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') panel.classList.remove('open');
        });

        // Refresh data every time panel is opened after first load
        bellBtn.addEventListener('click', async () => {
            if (loaded && panel.classList.contains('open')) {
                const detections = await fetchNotifications();
                renderItems(detections);
            }
        });
    }

    // Run after DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
