import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000';

function authHeaders() {
    const token = localStorage.getItem('access_token');
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}

/* ─── Confidence ring ─── */
const ConfidenceRing = ({ value, size = 120 }) => {
    const radius = (size - 16) / 2;
    const circumference = 2 * Math.PI * radius;
    const pct = Math.min(Math.max(value * 100, 0), 100);
    const offset = circumference - (pct / 100) * circumference;
    const color = pct >= 90 ? '#C83A2B' : pct >= 70 ? '#FF9500' : '#2B8A2B';

    return (
        <svg width={size} height={size} style={{ display: 'block' }}>
            <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#e8e8e8" strokeWidth="10" />
            <circle
                cx={size / 2} cy={size / 2} r={radius} fill="none"
                stroke={color} strokeWidth="10" strokeLinecap="round"
                strokeDasharray={circumference} strokeDashoffset={offset}
                transform={`rotate(-90 ${size / 2} ${size / 2})`}
                style={{ transition: 'stroke-dashoffset 0.6s ease' }}
            />
            <text x={size / 2} y={size / 2 + 6} textAnchor="middle" fontSize="20" fontWeight="700" fill={color}>
                {pct.toFixed(1)}%
            </text>
        </svg>
    );
};

const UncertainSampleDetail = () => {
    const { detectionId } = useParams();
    const navigate = useNavigate();
    const [detail, setDetail] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [reviewDone, setReviewDone] = useState(false);

    useEffect(() => {
        fetchDetail();
    }, [detectionId]); // eslint-disable-line react-hooks/exhaustive-deps

    const fetchDetail = async () => {
        setLoading(true);
        setError('');
        try {
            const res = await fetch(`${API_BASE}/api/detections/admin/detail/${detectionId}`, {
                headers: authHeaders(),
            });
            if (res.status === 401) { navigate('/login'); return; }
            if (res.status === 403) { setError('Admin access required.'); setLoading(false); return; }
            if (res.status === 404) { setError('Detection not found.'); setLoading(false); return; }
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            setDetail(data);
            setReviewDone(data.admin_review);
        } catch (err) {
            console.error('Failed to fetch detection detail:', err);
            setError('Failed to load detection detail. Make sure the backend is running.');
        } finally {
            setLoading(false);
        }
    };

    const handleReview = async (decision) => {
        try {
            const res = await fetch(`${API_BASE}/api/detections/admin/review/${detectionId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...authHeaders() },
                body: JSON.stringify({ admin_decision: decision }),
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            setReviewDone(true);
            // Refresh data to show updated state
            fetchDetail();
        } catch (err) {
            console.error('Review failed:', err);
            alert('Error submitting review. Please try again.');
        }
    };

    /* ─── style helpers ─── */
    const card = {
        background: '#fff', borderRadius: '10px', padding: '24px',
        boxShadow: '0 2px 10px rgba(0,0,0,0.06)', marginBottom: '24px',
    };
    const label = { fontSize: '0.82rem', color: '#888', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '0.5px' };
    const val = { fontSize: '1rem', fontWeight: 600, color: '#1a1a1a', wordBreak: 'break-all' };
    const row = { display: 'flex', flexWrap: 'wrap', gap: '24px' };
    const cell = { flex: '1 1 200px', minWidth: 0 };

    return (
        <div style={{ background: '#f5f5f5', minHeight: '100vh' }}>
            {/* Header */}
            <header style={{
                background: '#1a1a1a', color: '#fff', padding: '15px 30px',
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                borderBottom: '2px solid #C83A2B',
            }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <h1 style={{ margin: 0, fontSize: '1.4rem', fontFamily: "'Arbutus Slab', serif" }}>
                        <span style={{ color: '#C83A2B' }}>Ran</span>
                        <span style={{ color: '#999' }}>ScanAI</span>
                    </h1>
                    <span style={{ color: '#777', fontSize: '0.95rem' }}>/ Uncertain Sample Detail</span>
                </div>
                <button
                    onClick={() => navigate('/admin-dashboard')}
                    style={{
                        background: '#C83A2B', color: '#fff', border: 'none',
                        padding: '8px 18px', borderRadius: '5px', cursor: 'pointer',
                        fontWeight: 600, fontSize: '0.9rem',
                    }}
                >
                    ← Back to Dashboard
                </button>
            </header>

            <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '30px 20px' }}>
                {loading && (
                    <div style={{ textAlign: 'center', padding: '60px', color: '#888' }}>Loading detection detail…</div>
                )}

                {error && (
                    <div style={{
                        background: '#ffe0e0', color: '#C83A2B', padding: '14px 20px',
                        borderRadius: '8px', marginBottom: '20px', fontWeight: 500,
                    }}>
                        {error}
                        <div style={{ marginTop: 12 }}>
                            <button onClick={() => navigate('/admin-dashboard')} style={{
                                background: '#C83A2B', color: '#fff', border: 'none', padding: '6px 14px',
                                borderRadius: '4px', cursor: 'pointer', fontWeight: 600,
                            }}>← Back to Dashboard</button>
                        </div>
                    </div>
                )}

                {detail && (
                    <>
                        {/* Title card */}
                        <div style={{
                            ...card,
                            display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '24px',
                            borderLeft: `4px solid ${detail.is_malicious ? '#C83A2B' : '#2B8A2B'}`,
                        }}>
                            <div style={{ flex: '1 1 auto' }}>
                                <h2 style={{ margin: '0 0 6px', fontSize: '1.3rem', color: '#1a1a1a' }}>
                                    Detection #{detail.id}
                                </h2>
                                <span style={{
                                    display: 'inline-block', padding: '4px 12px', borderRadius: '4px',
                                    fontWeight: 700, fontSize: '0.9rem',
                                    background: detail.is_malicious ? '#ffcccc' : '#d4edda',
                                    color: detail.is_malicious ? '#C83A2B' : '#155724',
                                }}>
                                    {detail.prediction_label}
                                </span>
                                {detail.admin_review && (
                                    <span style={{
                                        display: 'inline-block', marginLeft: '8px', padding: '4px 10px',
                                        borderRadius: '4px', background: '#e0e0ff', color: '#333',
                                        fontSize: '0.82rem', fontWeight: 600,
                                    }}>
                                        ✓ Admin Reviewed
                                    </span>
                                )}
                            </div>
                            <ConfidenceRing value={detail.confidence} />
                        </div>

                        {/* File information */}
                        <div style={card}>
                            <h3 style={{ margin: '0 0 16px', color: '#333', fontSize: '1.05rem' }}>📄 File Information</h3>
                            <div style={row}>
                                <div style={cell}>
                                    <div style={label}>File Name</div>
                                    <div style={val}>{detail.file_name}</div>
                                </div>
                                <div style={cell}>
                                    <div style={label}>File Size</div>
                                    <div style={val}>{detail.file_size != null ? `${(detail.file_size / 1024).toFixed(1)} KB` : '—'}</div>
                                </div>
                            </div>
                            <div style={{ ...row, marginTop: '16px' }}>
                                <div style={{ flex: '1 1 100%' }}>
                                    <div style={label}>File Path</div>
                                    <div style={{ ...val, fontSize: '0.9rem', color: '#555' }}>{detail.file_path || '—'}</div>
                                </div>
                            </div>
                            <div style={{ ...row, marginTop: '16px' }}>
                                <div style={{ flex: '1 1 100%' }}>
                                    <div style={label}>SHA-256 Hash</div>
                                    <div style={{ ...val, fontSize: '0.85rem', fontFamily: 'monospace', color: '#555' }}>
                                        {detail.file_hash || '—'}
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* Scan results */}
                        <div style={card}>
                            <h3 style={{ margin: '0 0 16px', color: '#333', fontSize: '1.05rem' }}>🔍 Scan Results</h3>
                            <div style={row}>
                                <div style={cell}>
                                    <div style={label}>Classification</div>
                                    <div style={{ ...val, color: detail.is_malicious ? '#C83A2B' : '#2B8A2B' }}>
                                        {detail.prediction_label}
                                    </div>
                                </div>
                                <div style={cell}>
                                    <div style={label}>Confidence</div>
                                    <div style={{ ...val, color: '#FF9500' }}>{(detail.confidence * 100).toFixed(2)}%</div>
                                </div>
                                <div style={cell}>
                                    <div style={label}>Model Type</div>
                                    <div style={val}>{detail.model_type || '—'}</div>
                                </div>
                            </div>
                            <div style={{ ...row, marginTop: '16px' }}>
                                <div style={cell}>
                                    <div style={label}>Scan Time</div>
                                    <div style={val}>{detail.scan_time_ms != null ? `${detail.scan_time_ms.toFixed(1)} ms` : '—'}</div>
                                </div>
                                <div style={cell}>
                                    <div style={label}>Features Analyzed</div>
                                    <div style={val}>{detail.features_analyzed ?? '—'}</div>
                                </div>
                                <div style={cell}>
                                    <div style={label}>Scan Date &amp; Time</div>
                                    <div style={val}>{detail.display_time}</div>
                                </div>
                            </div>
                        </div>

                        {/* User & VirusTotal */}
                        <div style={card}>
                            <h3 style={{ margin: '0 0 16px', color: '#333', fontSize: '1.05rem' }}>👤 User &amp; Enrichment</h3>
                            <div style={row}>
                                <div style={cell}>
                                    <div style={label}>Username</div>
                                    <div style={val}>{detail.username || '—'}</div>
                                </div>
                                <div style={cell}>
                                    <div style={label}>Role</div>
                                    <div style={val}>
                                        <span style={{
                                            padding: '3px 10px', borderRadius: '4px',
                                            background: detail.role === 'admin' ? '#ffcccc' : '#f0f0f0',
                                            color: detail.role === 'admin' ? '#C83A2B' : '#555',
                                            fontSize: '0.88rem', textTransform: 'capitalize',
                                        }}>{detail.role || '—'}</span>
                                    </div>
                                </div>
                                <div style={cell}>
                                    <div style={label}>VirusTotal Detection</div>
                                    <div style={val}>{detail.vt_detection_ratio || 'Not available'}</div>
                                </div>
                            </div>
                        </div>

                        {/* Admin review info */}
                        <div style={card}>
                            <h3 style={{ margin: '0 0 16px', color: '#333', fontSize: '1.05rem' }}>🛡️ Admin Review</h3>
                            <div style={row}>
                                <div style={cell}>
                                    <div style={label}>Review Status</div>
                                    <div style={val}>
                                        {detail.admin_review
                                            ? <span style={{ color: '#2B8A2B' }}>✓ Reviewed</span>
                                            : <span style={{ color: '#FF9500' }}>⏳ Pending Review</span>
                                        }
                                    </div>
                                </div>
                                {detail.admin_decision_date && (
                                    <div style={cell}>
                                        <div style={label}>Decision Date</div>
                                        <div style={val}>{detail.admin_decision_date}</div>
                                    </div>
                                )}
                            </div>

                            {/* Review actions */}
                            {!reviewDone && (
                                <div style={{
                                    marginTop: '20px', padding: '16px', background: '#fffbe6',
                                    borderRadius: '8px', border: '1px solid #ffe58f',
                                }}>
                                    <p style={{ margin: '0 0 12px', fontWeight: 600, color: '#555' }}>
                                        This sample has uncertain confidence. Make a classification decision:
                                    </p>
                                    <div style={{ display: 'flex', gap: '12px' }}>
                                        <button
                                            onClick={() => handleReview('benign')}
                                            style={{
                                                padding: '8px 20px', borderRadius: '6px', border: 'none',
                                                background: '#28a745', color: '#fff', fontWeight: 700,
                                                fontSize: '0.95rem', cursor: 'pointer',
                                            }}
                                        >
                                            ✓ Mark as Safe (Benign)
                                        </button>
                                        <button
                                            onClick={() => handleReview('malware')}
                                            style={{
                                                padding: '8px 20px', borderRadius: '6px', border: 'none',
                                                background: '#C83A2B', color: '#fff', fontWeight: 700,
                                                fontSize: '0.95rem', cursor: 'pointer',
                                            }}
                                        >
                                            ✗ Mark as Malware
                                        </button>
                                    </div>
                                </div>
                            )}

                            {reviewDone && !detail.admin_review && (
                                <div style={{
                                    marginTop: '16px', padding: '12px 16px', background: '#d4edda',
                                    borderRadius: '8px', color: '#155724', fontWeight: 600,
                                }}>
                                    ✓ Review submitted successfully. Refreshing…
                                </div>
                            )}
                        </div>
                    </>
                )}
            </div>
        </div>
    );
};

export default UncertainSampleDetail;
