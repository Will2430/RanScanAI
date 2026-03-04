import React, { useState, useEffect } from 'react';

const MonthlyUserReport = () => {
    const [monthlyData, setMonthlyData] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [selectedMonth, setSelectedMonth] = useState(getCurrentMonth());
    const [currentPage, setCurrentPage] = useState(1);

    const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000';
    const ROWS_PER_PAGE = 10;

    function authHeaders() {
        const token = localStorage.getItem('access_token');
        return token ? { 'Authorization': 'Bearer ' + token } : {};
    }

    function getCurrentMonth() {
        const today = new Date();
        return `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}`;
    }

    useEffect(() => {
        fetchMonthlyReport();
    }, [selectedMonth]);

    const fetchMonthlyReport = async () => {
        setLoading(true);
        setError('');
        setCurrentPage(1);
        try {
            const res = await fetch(`${API_BASE}/api/detections/admin/monthly-report?month=${selectedMonth}`, {
                headers: authHeaders()
            });

            if (res.status === 401 || res.status === 403) {
                setError('Unauthorized: Admin access required.');
                setLoading(false);
                return;
            }

            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            const data = await res.json();
            setMonthlyData(data.users || []);
        } catch (err) {
            console.error('Failed to fetch monthly report:', err);
            setError('Failed to load monthly report. Make sure the backend is running.');
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return (
            <div className="report-section" style={{ textAlign: 'center', padding: '40px', color: '#888' }}>
                Loading monthly report…
            </div>
        );
    }

    if (error) {
        return (
            <div style={{
                background: '#ffe0e0', color: '#C83A2B', padding: '12px 20px',
                borderRadius: '8px', marginBottom: '20px'
            }}>
                {error}
            </div>
        );
    }

    const totalPages = Math.ceil(monthlyData.length / ROWS_PER_PAGE);
    const startIdx = (currentPage - 1) * ROWS_PER_PAGE;
    const pageData = monthlyData.slice(startIdx, startIdx + ROWS_PER_PAGE);

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

    const getDetectionRate = (row) => {
        if (row.total_scans === 0) return '0%';
        return `${((row.malicious_count / row.total_scans) * 100).toFixed(1)}%`;
    };

    return (
        <div className="report-section">
            <div style={{ marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '16px' }}>
                <h3 style={{ margin: 0 }}>Monthly User Report</h3>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <label style={{ fontSize: '0.9rem', color: '#555', fontWeight: 500 }}>Month:</label>
                    <input 
                        type="month" 
                        value={selectedMonth}
                        onChange={(e) => setSelectedMonth(e.target.value)}
                        style={{ padding: '6px 8px', borderRadius: '4px', border: '1px solid #ddd', fontSize: '0.9rem' }}
                    />
                    <button 
                        onClick={fetchMonthlyReport}
                        style={{ padding: '6px 12px', borderRadius: '4px', border: 'none', backgroundColor: '#f0f0f0', cursor: 'pointer', fontSize: '0.9rem' }}
                    >
                        🔄 Refresh
                    </button>
                </div>
            </div>

            <div className="table-wrapper">
                <table className="data-table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Role</th>
                            <th>Total Scans</th>
                            <th>Threats Found</th>
                            <th>Benign Files</th>
                            <th>Detection Rate</th>
                            <th>Critical (≥90%)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {pageData.length === 0 ? (
                            <tr>
                                <td colSpan="7" style={{ textAlign: 'center', padding: '20px', color: '#888' }}>
                                    No user activity for this month
                                </td>
                            </tr>
                        ) : (
                            pageData.map((row, index) => (
                                <tr key={index}>
                                    <td><strong>{row.username}</strong></td>
                                    <td>
                                        <span style={{
                                            padding: '4px 8px',
                                            borderRadius: '4px',
                                            backgroundColor: row.role === 'admin' ? '#ffcccc' : '#f0f0f0',
                                            color: row.role === 'admin' ? '#C83A2B' : '#555',
                                            fontSize: '0.85rem'
                                        }}>
                                            {row.role}
                                        </span>
                                    </td>
                                    <td style={{ textAlign: 'center' }}>{row.total_scans}</td>
                                    <td style={{ textAlign: 'center' }}>
                                        <span style={{ color: '#C83A2B', fontWeight: 'bold' }}>
                                            {row.malicious_count}
                                        </span>
                                    </td>
                                    <td style={{ textAlign: 'center' }}>
                                        <span style={{ color: '#2B8A2B' }}>
                                            {row.benign_count}
                                        </span>
                                    </td>
                                    <td style={{ textAlign: 'center', fontWeight: 'bold', color: '#FF9500' }}>
                                        {getDetectionRate(row)}
                                    </td>
                                    <td style={{ textAlign: 'center' }}>
                                        <span style={{ padding: '2px 6px', backgroundColor: '#ffcccc', borderRadius: '3px', color: '#C83A2B' }}>
                                            {row.critical_count}
                                        </span>
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
                <div style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '16px 0 4px', fontSize: '0.9rem', color: '#555'
                }}>
                    <span>Showing {pageData.length > 0 ? startIdx + 1 : 0}–{Math.min(startIdx + ROWS_PER_PAGE, monthlyData.length)} of {monthlyData.length} users</span>
                    <div style={{ display: 'flex', gap: '4px' }}>
                        <button onClick={() => goToPage(1)} disabled={currentPage === 1}
                            className="page-btn" title="First page">«</button>
                        <button onClick={() => goToPage(currentPage - 1)} disabled={currentPage === 1}
                            className="page-btn" title="Previous page">‹</button>
                        {getPageNumbers().map(p => (
                            <button key={p} onClick={() => goToPage(p)}
                                className={`page-btn ${p === currentPage ? 'page-btn-active' : ''}`}>{p}</button>
                        ))}
                        <button onClick={() => goToPage(currentPage + 1)} disabled={currentPage === totalPages}
                            className="page-btn" title="Next page">›</button>
                        <button onClick={() => goToPage(totalPages)} disabled={currentPage === totalPages}
                            className="page-btn" title="Last page">»</button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default MonthlyUserReport;
