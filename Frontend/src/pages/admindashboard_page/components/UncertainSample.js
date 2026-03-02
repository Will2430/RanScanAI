import React, { useState, useEffect } from 'react';

const ROWS_PER_PAGE = 10;

const UncertainSample = () => {
    const [samples, setSamples] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [reviewed, setReviewed] = useState(new Set());
    const [currentPage, setCurrentPage] = useState(1);
    const [filenameSearch, setFilenameSearch] = useState('');

    const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000';

    function authHeaders() {
        const token = localStorage.getItem('access_token');
        return token ? { 'Authorization': 'Bearer ' + token } : {};
    }

    useEffect(() => {
        fetchUncertainSamples();
    }, []);

    const fetchUncertainSamples = async () => {
        setLoading(true);
        setError('');
        try {
            const res = await fetch(`${API_BASE}/api/detections/admin/uncertain`, {
                headers: authHeaders()
            });
            if (res.status === 401 || res.status === 403) {
                setError('Unauthorized: Admin access required.');
                setLoading(false);
                return;
            }
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            setSamples(data.detections || []);
            setCurrentPage(1);
        } catch (err) {
            console.error('Failed to fetch uncertain samples:', err);
            setError('Failed to load uncertain samples. Make sure the backend is running.');
        } finally {
            setLoading(false);
        }
    };

    const handleReview = async (sampleId, decision) => {
        try {
            const res = await fetch(`${API_BASE}/api/detections/admin/review/${sampleId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...authHeaders() },
                body: JSON.stringify({ admin_decision: decision })
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            // Fade out then remove
            setReviewed(prev => new Set(prev).add(sampleId));
            setTimeout(() => {
                setSamples(prev => {
                    const next = prev.filter(s => s.id !== sampleId);
                    // If removing the last row on the current page, go back one page
                    const newTotal = next.length;
                    const newMaxPage = Math.max(1, Math.ceil(newTotal / ROWS_PER_PAGE));
                    setCurrentPage(p => Math.min(p, newMaxPage));
                    return next;
                });
                setReviewed(prev => { const s = new Set(prev); s.delete(sampleId); return s; });
            }, 350);
        } catch (err) {
            console.error('Failed to submit review:', err);
            alert('Error submitting review. Please try again.');
        }
    };

    // Filter
    const filtered = samples.filter(s =>
        !filenameSearch || s.file_name.toLowerCase().includes(filenameSearch.toLowerCase())
    );

    const totalPages = Math.max(1, Math.ceil(filtered.length / ROWS_PER_PAGE));
    const startIdx = (currentPage - 1) * ROWS_PER_PAGE;
    const pageData = filtered.slice(startIdx, startIdx + ROWS_PER_PAGE);

    const goToPage = (page) => {
        if (page >= 1 && page <= totalPages) setCurrentPage(page);
    };

    const getPageNumbers = () => {
        const pages = [];
        let start = Math.max(1, currentPage - 2);
        let end = Math.min(totalPages, start + 4);
        if (end - start < 4) start = Math.max(1, end - 4);
        for (let i = start; i <= end; i++) pages.push(i);
        return pages;
    };

    return (
        <div>
            {/* Header row */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <h3 style={{ margin: 0, color: '#333333' }}>
                    Uncertain Samples Review
                    {!loading && (
                        <span style={{ marginLeft: '8px', fontSize: '0.9rem', fontWeight: 400, color: '#888' }}>
                            ({filtered.length} pending)
                        </span>
                    )}
                </h3>
                <button
                    onClick={fetchUncertainSamples}
                    disabled={loading}
                    className="export-btn"
                    style={{ opacity: loading ? 0.6 : 1 }}
                >
                    🔄 Refresh
                </button>
            </div>

            {/* Error */}
            {error && (
                <div style={{
                    background: '#ffe0e0', color: '#C83A2B', padding: '12px 20px',
                    borderRadius: '8px', marginBottom: '16px', fontWeight: 500
                }}>
                    {error}
                </div>
            )}

            {/* Search */}
            {!loading && !error && (
                <div style={{ marginBottom: '14px' }}>
                    <label style={{ display: 'block', fontSize: '0.9rem', marginBottom: '4px', color: '#555' }}>File Name:</label>
                    <input
                        type="text"
                        placeholder="Search file name…"
                        value={filenameSearch}
                        onChange={(e) => { setFilenameSearch(e.target.value); setCurrentPage(1); }}
                        style={{ padding: '6px 8px', borderRadius: '4px', border: '1px solid #ddd', fontSize: '0.9rem', width: '200px' }}
                    />
                </div>
            )}

            {/* Loading */}
            {loading ? (
                <div style={{ textAlign: 'center', padding: '40px', color: '#888' }}>
                    Loading uncertain samples…
                </div>
            ) : !error && filtered.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px', color: '#888' }}>
                    No uncertain samples to review. All detections have clear confidence levels.
                </div>
            ) : !error && (
                <>
                    <div className="table-wrapper">
                        <table className="data-table" style={{ tableLayout: 'fixed' }}>
                            <colgroup>
                                <col style={{ width: '5%' }} />   {/* # */}
                                <col style={{ width: '26%' }} />  {/* File Name */}
                                <col style={{ width: '12%' }} />  {/* User */}
                                <col style={{ width: '8%' }} />   {/* Role */}
                                <col style={{ width: '12%' }} />  {/* AI Prediction */}
                                <col style={{ width: '10%' }} />  {/* Confidence */}
                                <col style={{ width: '18%' }} />  {/* Date */}
                                <col style={{ width: '9%' }} />   {/* Actions */}
                            </colgroup>
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>File Name</th>
                                    <th>User</th>
                                    <th>Role</th>
                                    <th>AI Prediction</th>
                                    <th>Confidence</th>
                                    <th>Date &amp; Time</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {pageData.map((sample, idx) => (
                                    <tr
                                        key={sample.id}
                                        style={{
                                            opacity: reviewed.has(sample.id) ? 0.4 : 1,
                                            transition: 'opacity 0.35s',
                                            backgroundColor: reviewed.has(sample.id) ? '#f9f9f9' : undefined
                                        }}
                                    >
                                        <td style={{ color: '#888', fontSize: '0.85rem' }}>
                                            {startIdx + idx + 1}
                                        </td>
                                        <td style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={sample.file_name}>
                                            {sample.file_name}
                                        </td>
                                        <td>{sample.username || '—'}</td>
                                        <td style={{ textTransform: 'capitalize', color: '#555', fontSize: '0.9rem' }}>
                                            {sample.role || '—'}
                                        </td>
                                        <td>
                                            <span className={`status-badge ${sample.prediction_label === 'MALWARE' ? 'status-malware' : 'status-benign'}`}>
                                                {sample.prediction_label}
                                            </span>
                                        </td>
                                        <td style={{ fontWeight: 'bold', color: '#FF9500' }}>
                                            {(sample.confidence * 100).toFixed(1)}%
                                        </td>
                                        <td style={{ fontSize: '0.88rem', color: '#555' }}>
                                            {sample.date || sample.display_time}
                                        </td>
                                        <td>
                                            <div style={{ display: 'flex', gap: '5px' }}>
                                                <button
                                                    onClick={() => handleReview(sample.id, 'benign')}
                                                    disabled={reviewed.has(sample.id)}
                                                    title="Mark as Safe"
                                                    style={{
                                                        padding: '4px 8px',
                                                        borderRadius: '4px',
                                                        border: 'none',
                                                        backgroundColor: reviewed.has(sample.id) ? '#ddd' : '#28a745',
                                                        color: reviewed.has(sample.id) ? '#999' : '#fff',
                                                        cursor: reviewed.has(sample.id) ? 'not-allowed' : 'pointer',
                                                        fontSize: '0.8rem',
                                                        fontWeight: 600,
                                                        whiteSpace: 'nowrap'
                                                    }}
                                                >
                                                    ✓ Safe
                                                </button>
                                                <button
                                                    onClick={() => handleReview(sample.id, 'malware')}
                                                    disabled={reviewed.has(sample.id)}
                                                    title="Mark as Malware"
                                                    style={{
                                                        padding: '4px 8px',
                                                        borderRadius: '4px',
                                                        border: 'none',
                                                        backgroundColor: reviewed.has(sample.id) ? '#ddd' : '#C83A2B',
                                                        color: reviewed.has(sample.id) ? '#999' : '#fff',
                                                        cursor: reviewed.has(sample.id) ? 'not-allowed' : 'pointer',
                                                        fontSize: '0.8rem',
                                                        fontWeight: 600,
                                                        whiteSpace: 'nowrap'
                                                    }}
                                                >
                                                    ✗ Malware
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    {/* Pagination */}
                    {totalPages > 1 && (
                        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '6px', marginTop: '16px' }}>
                            <button className="page-btn" onClick={() => goToPage(1)} disabled={currentPage === 1}>«</button>
                            <button className="page-btn" onClick={() => goToPage(currentPage - 1)} disabled={currentPage === 1}>‹</button>
                            {getPageNumbers().map(page => (
                                <button
                                    key={page}
                                    className={`page-btn${currentPage === page ? ' page-btn-active' : ''}`}
                                    onClick={() => goToPage(page)}
                                >
                                    {page}
                                </button>
                            ))}
                            <button className="page-btn" onClick={() => goToPage(currentPage + 1)} disabled={currentPage === totalPages}>›</button>
                            <button className="page-btn" onClick={() => goToPage(totalPages)} disabled={currentPage === totalPages}>»</button>
                            <span style={{ marginLeft: '8px', fontSize: '0.85rem', color: '#888' }}>
                                Page {currentPage} of {totalPages}
                            </span>
                        </div>
                    )}
                </>
            )}
        </div>
    );
};

export default UncertainSample;
