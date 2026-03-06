import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import '../AdminDash.css';

const ROWS_PER_PAGE = 10;
const RETRAINING_THRESHOLD = 100;
const THEME = {
    pageBg: '#f5f5f5',
    surface: '#ffffff',
    surfaceAlt: '#fafafa',
    border: '#e8e8e8',
    text: '#1a1a1a',
    muted: '#666666',
    primary: '#004E89',
    primaryDark: '#003366',
    danger: '#C83A2B',
    dangerDark: '#a02d22',
    success: '#28a745',
    warning: '#FF9500',
};

// ── Badge helpers ────────────────────────────────────────────────────────────

const VtBadge = ({ status }) => {
    const base = {
        padding: '2px 10px', borderRadius: '10px',
        fontSize: '0.75rem', fontWeight: 600, whiteSpace: 'nowrap',
    };
    if (!status) return <span style={{ ...base, background: '#eee', color: '#999' }}>—</span>;
    const map = {
        PENDING:   { background: '#e8e8e8', color: '#666' },
        UPLOADING: { background: '#fff3cd', color: '#856404' },
        SCANNING:  { background: '#fff3cd', color: '#856404' },
        VALIDATED: { background: '#d4edda', color: '#155724' },
        FAILED:    { background: '#f8d7da', color: '#721c24' },
    };
    const style = map[status] || map.PENDING;
    const label = (status === 'UPLOADING' || status === 'SCANNING')
        ? 'In Review'
        : status.charAt(0) + status.slice(1).toLowerCase();
    return <span style={{ ...base, ...style }}>{label}</span>;
};

const MetaStat = ({ label, value, accent = THEME.primary }) => (
    <div style={{
        background: THEME.surface,
        border: `1px solid ${THEME.border}`,
        borderTop: `3px solid ${accent}`,
        borderRadius: '10px',
        padding: '14px 16px',
        minWidth: '140px',
        flex: '1 1 140px',
        boxShadow: '0 1px 3px rgba(0, 0, 0, 0.06)',
    }}>
        <div style={{
            fontSize: '0.75rem',
            color: '#777',
            marginBottom: '6px',
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            fontWeight: 700,
        }}>
            {label}
        </div>
        <div style={{ fontSize: '1.18rem', fontWeight: 800, color: THEME.text, lineHeight: 1.2 }}>
            {value ?? '—'}
        </div>
    </div>
);

// ── Confirmation Modal ────────────────────────────────────────────────────────

const ConfirmModal = ({ show, title, body, onConfirm, onCancel, confirmLabel = 'Confirm', confirmColor = '#C83A2B' }) => {
    if (!show) return null;
    return (
        <div style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.45)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999,
        }}>
            <div style={{
                background: THEME.surface,
                border: `1px solid ${THEME.border}`,
                borderRadius: '12px',
                padding: '28px 32px',
                maxWidth: '440px', width: '90%', boxShadow: '0 8px 32px rgba(0,0,0,0.18)',
            }}>
                <h3 style={{ margin: '0 0 12px', color: THEME.text }}>{title}</h3>
                <p style={{ margin: '0 0 24px', color: '#555', lineHeight: 1.6 }}>{body}</p>
                <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                    <button onClick={onCancel} style={{
                        padding: '8px 20px', borderRadius: '6px',
                        border: '1px solid #ccc', background: '#f5f5f5', cursor: 'pointer', fontWeight: 600,
                    }}>Cancel</button>
                    <button onClick={onConfirm} style={{
                        padding: '8px 20px', borderRadius: '6px',
                        border: 'none', background: confirmColor, color: '#fff',
                        cursor: 'pointer', fontWeight: 600,
                    }}>{confirmLabel}</button>
                </div>
            </div>
        </div>
    );
};

// ── Main Component ────────────────────────────────────────────────────────────

const RetrainCenter = () => {
    const navigate = useNavigate();
    const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000';

    // Model metadata
    const [meta, setMeta] = useState(null);
    const [metaLoading, setMetaLoading] = useState(true);
    const [metaError, setMetaError] = useState('');

    // Approved samples
    const [samples, setSamples] = useState([]);
    const [samplesLoading, setSamplesLoading] = useState(true);
    const [samplesError, setSamplesError] = useState('');

    // Pagination
    const [currentPage, setCurrentPage] = useState(1);

    // UI state
    const [statusMsg, setStatusMsg] = useState('');
    const [statusType, setStatusType] = useState(''); // 'success' | 'error' | 'info'

    // Modals
    const [showRetrainModal, setShowRetrainModal] = useState(false);
    const [showFlushModal, setShowFlushModal] = useState(false);
    const [retrainSampleCount, setRetrainSampleCount] = useState(0);

    const authHeaders = () => {
        const token = localStorage.getItem('access_token');
        return token ? { Authorization: 'Bearer ' + token } : {};
    };

    const fetchMeta = useCallback(async () => {
        setMetaLoading(true);
        setMetaError('');
        try {
            const res = await fetch(`${API_BASE}/api/retrain/model-metadata`, { headers: authHeaders() });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            setMeta(await res.json());
        } catch (err) {
            setMetaError('Could not load model metadata.');
        } finally {
            setMetaLoading(false);
        }
    }, [API_BASE]);

    const fetchSamples = useCallback(async () => {
        setSamplesLoading(true);
        setSamplesError('');
        try {
            const res = await fetch(`${API_BASE}/api/retrain/approved-samples`, { headers: authHeaders() });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            setSamples(data.samples || []);
        } catch (err) {
            setSamplesError('Could not load approved samples.');
        } finally {
            setSamplesLoading(false);
        }
    }, [API_BASE]);

    useEffect(() => {
        fetchMeta();
        fetchSamples();
    }, [fetchMeta, fetchSamples]);

    // ── Retrain trigger ──────────────────────────────────────────────────────

    const handleRetrainClick = () => {
        setRetrainSampleCount(samples.length);
        setShowRetrainModal(true);
    };

    const handleRetrainConfirm = async () => {
        setShowRetrainModal(false);
        setStatusMsg('');
        try {
            const res = await fetch(`${API_BASE}/api/retrain/trigger`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...authHeaders() },
                body: JSON.stringify({ force: true }),
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
            setStatusMsg(`✓ ${data.message}`);
            setStatusType('success');
            // Refresh metadata to show updated version
            setTimeout(fetchMeta, 2000);
        } catch (err) {
            setStatusMsg(`✗ Retraining failed: ${err.message}`);
            setStatusType('error');
        }
    };

    // ── Flush queue ──────────────────────────────────────────────────────────

    const handleFlushConfirm = async () => {
        setShowFlushModal(false);
        setStatusMsg('');
        try {
            const res = await fetch(`${API_BASE}/api/retrain/flush-queue`, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json', ...authHeaders() },
                body: JSON.stringify({}),
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
            setStatusMsg(`✓ ${data.message}`);
            setStatusType('success');
            setSamples([]);
            setCurrentPage(1);
        } catch (err) {
            setStatusMsg(`✗ Flush failed: ${err.message}`);
            setStatusType('error');
        }
    };

    // ── Pagination ───────────────────────────────────────────────────────────

    const totalPages = Math.max(1, Math.ceil(samples.length / ROWS_PER_PAGE));
    const startIdx = (currentPage - 1) * ROWS_PER_PAGE;
    const pageData = samples.slice(startIdx, startIdx + ROWS_PER_PAGE);

    const goToPage = (p) => { if (p >= 1 && p <= totalPages) setCurrentPage(p); };
    const getPageNumbers = () => {
        const pages = [];
        let start = Math.max(1, currentPage - 2);
        let end = Math.min(totalPages, start + 4);
        if (end - start < 4) start = Math.max(1, end - 4);
        for (let i = start; i <= end; i++) pages.push(i);
        return pages;
    };

    // ── Progress bar ─────────────────────────────────────────────────────────

    const progress = Math.min(100, Math.round((samples.length / RETRAINING_THRESHOLD) * 100));
    const progressColor = progress >= 100 ? THEME.success : progress >= 50 ? THEME.warning : THEME.danger;

    // ── Format helpers ────────────────────────────────────────────────────────

    const fmt = (v, digits = 4) => v != null ? (v * 100).toFixed(digits - 2) + '%' : '—';
    const fmtDate = (iso) => {
        if (!iso) return '—';
        const d = new Date(iso);
        return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
    };

    const isMaliciousPrediction = (sample) => {
        const label = (sample?.prediction_label || '').toLowerCase();
        if (label.includes('mal') || label.includes('threat')) return true;
        if (label.includes('clean') || label.includes('benign') || label.includes('safe')) return false;
        return sample?.ml_prediction === 0;
    };

    const getPredictionText = (sample) => {
        return isMaliciousPrediction(sample) ? 'MALICIOUS' : 'CLEAN';
    };

    // ── Render ────────────────────────────────────────────────────────────────

    return (
        <div style={{ background: THEME.pageBg, minHeight: '100vh', padding: '24px 20px' }}>
            <div style={{ fontFamily: 'Inter, Segoe UI, system-ui, sans-serif', color: THEME.text, maxWidth: '1250px', margin: '0 auto' }}>

            {/* Back nav */}
            <div style={{ marginBottom: '20px' }}>
                <button
                    onClick={() => navigate('/admin-dashboard')}
                    style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        background: THEME.surface,
                        border: `1px solid ${THEME.border}`,
                        borderRadius: '6px',
                        cursor: 'pointer',
                        color: THEME.primary,
                        fontSize: '0.92rem',
                        fontWeight: 700,
                        padding: '8px 14px',
                    }}
                >
                    ← Back to Uncertain Samples
                </button>
            </div>

            <h2 style={{ margin: '0 0 24px', color: THEME.text }}>🧠 Retrain Center</h2>

            {/* ── Status toast ── */}
            {statusMsg && (
                <div style={{
                    marginBottom: '20px',
                    padding: '12px 18px',
                    borderRadius: '8px',
                    border: `1px solid ${THEME.border}`,
                    fontWeight: 600,
                    background: statusType === 'success' ? '#d4edda' : statusType === 'error' ? '#f8d7da' : '#d1ecf1',
                    color: statusType === 'success' ? '#155724' : statusType === 'error' ? '#721c24' : '#0c5460',
                }}>
                    {statusMsg}
                    <button onClick={() => setStatusMsg('')} style={{ float: 'right', background: 'none', border: 'none', cursor: 'pointer', fontSize: '1.1rem', lineHeight: 1 }}>×</button>
                </div>
            )}

            {/* ══ Section A: Model Metadata ══════════════════════════════════ */}
            <div style={{
                background: THEME.surfaceAlt,
                border: `1px solid ${THEME.border}`,
                borderRadius: '12px',
                padding: '20px 24px',
                marginBottom: '28px',
                boxShadow: '0 2px 8px rgba(0, 0, 0, 0.08)',
            }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                    <h3 style={{ margin: 0, color: THEME.text }}>Current Model Performance</h3>
                    <button onClick={fetchMeta} disabled={metaLoading} className="export-btn" style={{ opacity: metaLoading ? 0.6 : 1 }}>
                        🔄 Refresh
                    </button>
                </div>

                {metaLoading ? (
                    <div style={{ color: '#888', padding: '20px 0' }}>Loading model metrics…</div>
                ) : metaError ? (
                    <div style={{ color: '#C83A2B' }}>{metaError}</div>
                ) : meta ? (
                    <>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px' }}>
                            <MetaStat label="Version" value={`v${meta.version}`} accent={THEME.primary} />
                            <MetaStat label="Model Type" value={meta.model_type} accent={THEME.primary} />
                            <MetaStat label="Dataset" value={meta.dataset} accent={THEME.primary} />
                            <MetaStat label="Accuracy" value={fmt(meta.accuracy)} accent={THEME.success} />
                            <MetaStat label="Precision" value={fmt(meta.precision)} accent={THEME.success} />
                            <MetaStat label="Recall" value={fmt(meta.recall)} accent={THEME.success} />
                            <MetaStat label="F1 Score" value={fmt(meta.f1_score)} accent={THEME.success} />
                            <MetaStat label="FPR" value={fmt(meta.fpr)} accent={THEME.danger} />
                            <MetaStat label="AUC" value={fmt(meta.auc)} accent={THEME.warning} />
                            <MetaStat label="Features" value={meta.n_features?.toLocaleString()} accent={THEME.primary} />
                            <MetaStat label="Vocab Size" value={meta.vocab_size?.toLocaleString()} accent={THEME.primary} />
                            <MetaStat label="Training Samples" value={meta.total_samples?.toLocaleString()} accent={THEME.warning} />
                        </div>
                        <div style={{ marginTop: '14px', fontSize: '0.82rem', color: '#666' }}>
                            Last trained: <strong>{fmtDate(meta.trained_at)}</strong>
                            {meta.model_path && <> &nbsp;·&nbsp; <code style={{ fontSize: '0.78rem', color: '#555' }}>{meta.model_path}</code></>}
                        </div>
                    </>
                ) : null}
            </div>

            {/* ══ Section B: Approved Samples Table ═════════════════════════ */}
            <div style={{
                background: THEME.surface,
                border: `1px solid ${THEME.border}`,
                borderRadius: '12px',
                padding: '20px 24px',
                marginBottom: '28px',
                boxShadow: '0 2px 8px rgba(0, 0, 0, 0.08)',
            }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <h3 style={{ margin: 0, color: THEME.text }}>
                        Approved Samples
                        {!samplesLoading && (
                            <span style={{ marginLeft: '8px', fontWeight: 400, fontSize: '0.9rem', color: '#888' }}>
                                ({samples.length} approved)
                            </span>
                        )}
                    </h3>
                    <button onClick={fetchSamples} disabled={samplesLoading} className="export-btn" style={{ opacity: samplesLoading ? 0.6 : 1 }}>
                        🔄 Refresh
                    </button>
                </div>

                {/* Progress bar */}
                <div style={{ marginBottom: '16px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', color: THEME.muted, marginBottom: '4px' }}>
                        <span>{samples.length} / {RETRAINING_THRESHOLD} samples ready for retraining</span>
                        <span style={{ color: progressColor, fontWeight: 600 }}>{progress}%</span>
                    </div>
                    <div style={{ background: '#eee', borderRadius: '6px', height: '8px', overflow: 'hidden' }}>
                        <div style={{ width: `${progress}%`, height: '100%', background: progressColor, borderRadius: '6px', transition: 'width 0.4s' }} />
                    </div>
                    {samples.length < RETRAINING_THRESHOLD && (
                        <div style={{ fontSize: '0.78rem', color: '#888', marginTop: '4px' }}>
                            ⚠ {RETRAINING_THRESHOLD - samples.length} more samples recommended before retraining.
                        </div>
                    )}
                </div>

                {samplesLoading ? (
                    <div style={{ color: '#888', padding: '20px 0', textAlign: 'center' }}>Loading approved samples…</div>
                ) : samplesError ? (
                    <div style={{ color: '#C83A2B' }}>{samplesError}</div>
                ) : samples.length === 0 ? (
                    <div style={{ color: '#888', padding: '20px 0', textAlign: 'center' }}>
                        No samples approved yet. Go to <strong>Uncertain Samples</strong> and use "Approve All for Retrain".
                    </div>
                ) : (
                    <>
                        <div className="table-wrapper">
                            <table className="data-table retrain-table" style={{ tableLayout: 'fixed' }}>
                                <colgroup>
                                    <col style={{ width: '5%' }} />
                                    <col style={{ width: '28%' }} />
                                    <col style={{ width: '15%' }} />
                                    <col style={{ width: '10%' }} />
                                    <col style={{ width: '12%' }} />
                                    <col style={{ width: '14%' }} />
                                    <col style={{ width: '16%' }} />
                                </colgroup>
                                <thead>
                                    <tr>
                                        <th>#</th>
                                        <th>File Name</th>
                                        <th>AI Prediction</th>
                                        <th>Confidence</th>
                                        <th>VT Status</th>
                                        <th>Behavioral</th>
                                        <th>Approved On</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {pageData.map((s, idx) => (
                                        <tr key={s.id}>
                                            <td style={{ color: '#888', fontSize: '0.85rem' }}>{startIdx + idx + 1}</td>
                                            <td style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={s.file_name}>
                                                {s.file_name}
                                            </td>
                                            <td>
                                                <span className={`status-badge ${isMaliciousPrediction(s) ? 'status-malware' : 'status-benign'}`}>
                                                    {getPredictionText(s)}
                                                </span>
                                            </td>
                                            <td style={{ fontWeight: 'bold', color: '#FF9500' }}>
                                                {(s.ml_confidence * 100).toFixed(1)}%
                                            </td>
                                            <td><VtBadge status={s.vt_status} /></td>
                                            <td style={{ fontSize: '0.85rem', color: s.behavioral_enriched ? '#155724' : '#888' }}>
                                                {s.behavioral_enriched ? '✓ Enriched' : '—'}
                                            </td>
                                            <td style={{ fontSize: '0.85rem', color: '#555' }}>
                                                {s.admin_decision_date ? fmtDate(s.admin_decision_date) : fmtDate(s.created_at)}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        {totalPages > 1 && (
                            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '6px', marginTop: '14px' }}>
                                <button className="page-btn" onClick={() => goToPage(1)} disabled={currentPage === 1}>«</button>
                                <button className="page-btn" onClick={() => goToPage(currentPage - 1)} disabled={currentPage === 1}>‹</button>
                                {getPageNumbers().map(p => (
                                    <button key={p} className={`page-btn${currentPage === p ? ' page-btn-active' : ''}`} onClick={() => goToPage(p)}>{p}</button>
                                ))}
                                <button className="page-btn" onClick={() => goToPage(currentPage + 1)} disabled={currentPage === totalPages}>›</button>
                                <button className="page-btn" onClick={() => goToPage(totalPages)} disabled={currentPage === totalPages}>»</button>
                                <span style={{ marginLeft: '8px', fontSize: '0.85rem', color: '#888' }}>Page {currentPage} of {totalPages}</span>
                            </div>
                        )}
                    </>
                )}
            </div>

            {/* ══ Section C: Controls ═══════════════════════════════════════ */}
            <div style={{
                background: THEME.surfaceAlt,
                border: `1px solid ${THEME.border}`,
                borderRadius: '12px',
                padding: '20px 24px',
                boxShadow: '0 2px 8px rgba(0, 0, 0, 0.08)',
            }}>
                <h3 style={{ margin: '0 0 16px', color: THEME.text }}>Actions</h3>
                <div style={{ display: 'flex', gap: '14px', flexWrap: 'wrap' }}>
                    <button
                        onClick={handleRetrainClick}
                        disabled={samplesLoading}
                        style={{
                            padding: '10px 24px', borderRadius: '8px', border: 'none',
                            background: THEME.primary, color: '#fff', cursor: 'pointer',
                            fontWeight: 600, fontSize: '0.95rem',
                            boxShadow: '0 1px 2px rgba(0, 0, 0, 0.15)',
                            opacity: samplesLoading ? 0.6 : 1,
                        }}
                    >
                        🔁 Initiate Retraining
                    </button>
                    <button
                        onClick={() => setShowFlushModal(true)}
                        style={{
                            padding: '10px 24px', borderRadius: '8px',
                            border: `1px solid ${THEME.danger}`, background: '#fff',
                            color: THEME.danger, cursor: 'pointer',
                            fontWeight: 600, fontSize: '0.95rem',
                            boxShadow: '0 1px 2px rgba(0, 0, 0, 0.08)',
                        }}
                    >
                        🗑 Flush Queue (Demo Reset)
                    </button>
                </div>
                <div style={{
                    marginTop: '14px',
                    background: THEME.surface,
                    border: `1px solid ${THEME.border}`,
                    borderRadius: '8px',
                    padding: '12px 14px',
                    fontSize: '0.84rem',
                    color: '#444',
                    lineHeight: 1.55,
                }}>
                    <div style={{ fontSize: '0.8rem', color: '#666', fontWeight: 700, marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                        What each action does
                    </div>

                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', marginBottom: '8px' }}>
                        <span style={{
                            background: '#e7f3ff',
                            color: THEME.primary,
                            border: '1px solid #cfe6ff',
                            borderRadius: '5px',
                            fontWeight: 700,
                            fontSize: '0.78rem',
                            padding: '3px 8px',
                            whiteSpace: 'nowrap',
                        }}>
                            Initiate Retraining
                        </span>
                        <span style={{ color: '#404040' }}>
                            Starts a new retraining job using all currently approved samples from the queue.
                        </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
                        <span style={{
                            background: '#ffe8e5',
                            color: THEME.danger,
                            border: '1px solid #ffd3ce',
                            borderRadius: '5px',
                            fontWeight: 700,
                            fontSize: '0.78rem',
                            padding: '3px 8px',
                            whiteSpace: 'nowrap',
                        }}>
                            Flush Queue (Demo Reset)
                        </span>
                        <span style={{ color: '#404040' }}>
                            Clears all uncertain and approved queue entries so files can be scanned and reviewed again from scratch.
                        </span>
                    </div>
                </div>
            </div>

            {/* ── Modals ─────────────────────────────────────────────────── */}

            <ConfirmModal
                show={showRetrainModal}
                title="⚠ Confirm Retraining"
                body={
                    retrainSampleCount < RETRAINING_THRESHOLD
                        ? `Only ${retrainSampleCount} / ${RETRAINING_THRESHOLD} samples are approved. Retraining with fewer samples may reduce model generalization. Proceed anyway?`
                        : `${retrainSampleCount} samples approved — threshold met. Initiate retraining now?`
                }
                confirmLabel="Proceed"
                confirmColor={THEME.primary}
                onConfirm={handleRetrainConfirm}
                onCancel={() => setShowRetrainModal(false)}
            />

            <ConfirmModal
                show={showFlushModal}
                title="🗑 Flush Uncertain Queue"
                body="This will reset the approval status (admin_review) on all queued samples — queue entries are kept intact. Samples will reappear in the Uncertain Samples list for re-review. Continue?"
                confirmLabel="Flush All"
                confirmColor={THEME.danger}
                onConfirm={handleFlushConfirm}
                onCancel={() => setShowFlushModal(false)}
            />
            </div>
        </div>
    );
};

export default RetrainCenter;
