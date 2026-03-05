import React, { useState, useEffect, useCallback } from 'react';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000';

function authHeaders() {
    const token = localStorage.getItem('access_token');
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}

function Badge({ active }) {
    return active ? (
        <span style={{
            background: '#d1fae5', color: '#065f46', fontSize: '0.7rem',
            fontWeight: 700, padding: '2px 8px', borderRadius: 99,
            letterSpacing: '.04em', textTransform: 'uppercase',
        }}>● Active</span>
    ) : null;
}

function VersionTable({ title, rows, activatingId, onActivate }) {
    if (!rows || rows.length === 0) {
        return (
            <div style={{ marginBottom: 24 }}>
                <h4 style={{ margin: '0 0 8px', fontSize: '0.95rem', color: '#374151' }}>{title}</h4>
                <p style={{ color: '#9ca3af', fontSize: '0.85rem' }}>No model versions found.</p>
            </div>
        );
    }

    return (
        <div style={{ marginBottom: 28 }}>
            <h4 style={{ margin: '0 0 10px', fontSize: '0.95rem', color: '#374151', fontWeight: 600 }}>
                {title}
            </h4>
            <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
                    <thead>
                        <tr style={{ background: '#f9fafb' }}>
                            {['Version', 'Accuracy', 'AUC', 'Precision', 'Samples', 'Trained', 'Status', ''].map(h => (
                                <th key={h} style={{
                                    padding: '7px 10px', textAlign: 'left', fontWeight: 600,
                                    color: '#6b7280', borderBottom: '1px solid #e5e7eb', whiteSpace: 'nowrap',
                                }}>{h}</th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {rows.map((r) => (
                            <tr key={r.id} style={{
                                background: r.is_active ? '#f0fdf4' : 'white',
                                borderBottom: '1px solid #f3f4f6',
                                transition: 'background .15s',
                            }}>
                                <td style={{ padding: '7px 10px', fontWeight: r.is_active ? 700 : 400, color: '#111827' }}>
                                    {r.version}
                                </td>
                                <td style={{ padding: '7px 10px', color: '#374151' }}>
                                    {r.accuracy != null ? (r.accuracy * 100).toFixed(2) + '%' : '—'}
                                    {r.accuracy_delta != null && r.accuracy_delta !== 0 && (
                                        <span style={{
                                            marginLeft: 5, fontSize: '0.72rem',
                                            color: r.accuracy_delta > 0 ? '#059669' : '#dc2626',
                                        }}>
                                            {r.accuracy_delta > 0 ? '▲' : '▼'}
                                            {Math.abs(r.accuracy_delta * 100).toFixed(2)}%
                                        </span>
                                    )}
                                </td>
                                <td style={{ padding: '7px 10px', color: '#374151' }}>
                                    {r.auc != null ? r.auc.toFixed(4) : '—'}
                                </td>
                                <td style={{ padding: '7px 10px', color: '#374151' }}>
                                    {r.precision != null ? (r.precision * 100).toFixed(2) + '%' : '—'}
                                </td>
                                <td style={{ padding: '7px 10px', color: '#374151' }}>
                                    {r.total_samples != null ? r.total_samples.toLocaleString() : '—'}
                                </td>
                                <td style={{ padding: '7px 10px', color: '#6b7280', whiteSpace: 'nowrap' }}>
                                    {r.trained_at ? new Date(r.trained_at).toLocaleDateString() : '—'}
                                </td>
                                <td style={{ padding: '7px 10px' }}>
                                    <Badge active={r.is_active} />
                                </td>
                                <td style={{ padding: '7px 10px' }}>
                                    {!r.is_active && (
                                        <button
                                            onClick={() => onActivate(r.id, r.version)}
                                            disabled={activatingId === r.id}
                                            style={{
                                                padding: '4px 12px', fontSize: '0.78rem', fontWeight: 600,
                                                background: activatingId === r.id ? '#e5e7eb' : '#2563eb',
                                                color: activatingId === r.id ? '#9ca3af' : 'white',
                                                border: 'none', borderRadius: 6, cursor: activatingId === r.id ? 'not-allowed' : 'pointer',
                                                transition: 'background .15s',
                                            }}
                                        >
                                            {activatingId === r.id ? 'Activating…' : 'Set Active'}
                                        </button>
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

const ModelVersionSelector = () => {
    const [cnnVersions, setCnnVersions]     = useState([]);
    const [xgbVersions, setXgbVersions]     = useState([]);
    const [loading, setLoading]             = useState(true);
    const [error, setError]                 = useState('');
    const [activatingId, setActivatingId]   = useState(null);
    const [toast, setToast]                 = useState(null); // {msg, ok}
    const [expanded, setExpanded]           = useState(false);

    const fetchVersions = useCallback(async () => {
        setLoading(true);
        setError('');
        try {
            const res = await fetch(`${API_BASE}/api/models/versions`, {
                headers: authHeaders(),
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            setCnnVersions(data.cnn || []);
            setXgbVersions(data.xgboost || []);
        } catch (err) {
            setError('Could not load model versions: ' + err.message);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { fetchVersions(); }, [fetchVersions]);

    const handleActivate = async (recordId, version) => {
        setActivatingId(recordId);
        setToast(null);
        try {
            const res = await fetch(
                `${API_BASE}/api/models/set-active?record_id=${recordId}`,
                { method: 'POST', headers: authHeaders() }
            );
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

            const reloadNote = data.reload_ok
                ? ' — model_service reloaded.'
                : ` — model_service reload: ${data.reload_msg}`;
            setToast({ ok: data.reload_ok, msg: `Activated v${version}.${reloadNote}` });
            await fetchVersions();          // refresh table to show new active badge
        } catch (err) {
            setToast({ ok: false, msg: 'Activation failed: ' + err.message });
        } finally {
            setActivatingId(null);
            setTimeout(() => setToast(null), 6000);
        }
    };

    // Determine currently displayed active summary for the collapsed header
    const activeCNN = cnnVersions.find(r => r.is_active);
    const activeXGB = xgbVersions.find(r => r.is_active);
    const headerSummary = [
        activeCNN ? `CNN: v${activeCNN.version}` : 'CNN: none',
        activeXGB ? `XGBoost: v${activeXGB.version}` : 'XGBoost: none',
    ].join('  ·  ');

    return (
        <div style={{
            background: 'white', borderRadius: 12, border: '1px solid #e5e7eb',
            boxShadow: '0 1px 4px rgba(0,0,0,.07)', marginBottom: 24,
            overflow: 'hidden',
        }}>
            {/* Collapsible header */}
            <button
                onClick={() => setExpanded(v => !v)}
                style={{
                    width: '100%', padding: '14px 20px', background: 'none', border: 'none',
                    cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 12,
                    textAlign: 'left',
                }}
            >
                <span style={{ fontSize: '1.1rem' }}>🧠</span>
                <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 700, color: '#111827', fontSize: '0.95rem' }}>
                        Active Model Versions
                    </div>
                    {!expanded && !loading && (
                        <div style={{ fontSize: '0.78rem', color: '#6b7280', marginTop: 2 }}>
                            {headerSummary}
                        </div>
                    )}
                </div>
                <span style={{ color: '#9ca3af', fontSize: '0.9rem', transition: 'transform .2s', transform: expanded ? 'rotate(180deg)' : 'none' }}>▼</span>
            </button>

            {expanded && (
                <div style={{ padding: '0 20px 20px' }}>
                    {toast && (
                        <div style={{
                            padding: '10px 14px', borderRadius: 8, marginBottom: 16,
                            background: toast.ok ? '#d1fae5' : '#fee2e2',
                            color: toast.ok ? '#065f46' : '#991b1b',
                            fontSize: '0.85rem', fontWeight: 500,
                        }}>
                            {toast.msg}
                        </div>
                    )}

                    {error && (
                        <div style={{ color: '#dc2626', fontSize: '0.85rem', marginBottom: 12 }}>{error}</div>
                    )}

                    {loading ? (
                        <div style={{ color: '#9ca3af', padding: '20px 0', textAlign: 'center', fontSize: '0.85rem' }}>
                            Loading model versions…
                        </div>
                    ) : (
                        <>
                            <VersionTable
                                title="1D CNN — Sequential API Analysis"
                                rows={cnnVersions}
                                activatingId={activatingId}
                                onActivate={handleActivate}
                            />
                            <VersionTable
                                title="XGBoost — PE Feature Classification"
                                rows={xgbVersions}
                                activatingId={activatingId}
                                onActivate={handleActivate}
                            />
                        </>
                    )}

                    <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                        <button
                            onClick={fetchVersions}
                            disabled={loading}
                            style={{
                                padding: '6px 14px', fontSize: '0.8rem', background: 'none',
                                border: '1px solid #d1d5db', borderRadius: 6, cursor: 'pointer',
                                color: '#374151', fontWeight: 500,
                            }}
                        >
                            ↺ Refresh
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ModelVersionSelector;
