import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000';

function authHeaders() {
    const token = localStorage.getItem('access_token');
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}

const MonthlySummaryTable = () => {
    const navigate = useNavigate();
    const [months, setMonths] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        fetchAvailableMonths();
    }, []);

    const fetchAvailableMonths = async () => {
        setLoading(true);
        setError('');
        try {
            const res = await fetch(`${API_BASE}/api/detections/admin/available-months`, {
                headers: authHeaders(),
            });

            if (res.status === 401 || res.status === 403) {
                setError('Unauthorized: Admin access required.');
                setLoading(false);
                return;
            }
            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            const data = await res.json();
            setMonths(data.months || []);
        } catch (err) {
            console.error('Failed to fetch available months:', err);
            setError('Failed to load monthly summary data.');
        } finally {
            setLoading(false);
        }
    };

    const handleViewSummary = (month) => {
        navigate(`/admin/summary-report/${month}`);
    };

    /* ─── styles ─── */
    const thStyle = {
        padding: '12px 14px',
        fontWeight: 600,
        borderBottom: '2px solid #ddd',
        whiteSpace: 'nowrap',
        textAlign: 'left',
        fontSize: '0.88rem',
        color: '#333',
    };

    const tdStyle = {
        padding: '10px 14px',
        verticalAlign: 'middle',
        fontSize: '0.88rem',
        color: '#444',
    };

    if (loading) {
        return (
            <div style={{ textAlign: 'center', padding: '30px', color: '#888' }}>
                Loading monthly summaries…
            </div>
        );
    }

    if (error) {
        return (
            <div style={{
                background: '#ffe0e0', color: '#C83A2B', padding: '12px 20px',
                borderRadius: '8px', marginBottom: '20px',
            }}>
                {error}
            </div>
        );
    }

    return (
        <div>
            <div style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                marginBottom: '16px', flexWrap: 'wrap', gap: '12px',
            }}>
                <h3 style={{ margin: 0, fontSize: '1.1rem', color: '#1a1a1a' }}>
                    <span style={{ color: '#C83A2B', fontWeight: 700 }}>📋</span>{' '}
                    Monthly Summary Reports
                </h3>
                <button
                    onClick={fetchAvailableMonths}
                    style={{
                        padding: '6px 12px', borderRadius: '4px', border: 'none',
                        backgroundColor: '#f0f0f0', cursor: 'pointer', fontSize: '0.9rem',
                    }}
                >🔄 Refresh</button>
            </div>

            {months.length === 0 ? (
                <div style={{
                    textAlign: 'center', padding: '40px', color: '#888',
                    background: '#fff', borderRadius: '10px',
                    boxShadow: '0 2px 8px rgba(0,0,0,0.06)',
                }}>
                    No scan data available yet.
                </div>
            ) : (
                <div style={{
                    background: '#fff', borderRadius: '10px',
                    boxShadow: '0 2px 8px rgba(0,0,0,0.06)',
                    overflow: 'hidden',
                }}>
                    <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                            <thead>
                                <tr style={{ background: '#f8f8f8' }}>
                                    <th style={thStyle}>Month</th>
                                    <th style={thStyle}>Total Scans</th>
                                    <th style={thStyle}>Benign</th>
                                    <th style={thStyle}>Malicious</th>
                                    <th style={thStyle}>Detection Rate</th>
                                    <th style={thStyle}>Critical</th>
                                    <th style={thStyle}>Users</th>
                                    <th style={{ ...thStyle, textAlign: 'center' }}>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {months.map((m, i) => (
                                    <tr key={m.month} style={{
                                        borderBottom: '1px solid #eee',
                                        background: i % 2 === 0 ? '#fff' : '#fcfcfc',
                                        transition: 'background 0.15s',
                                    }}
                                        onMouseEnter={(e) => e.currentTarget.style.background = '#f5f5ff'}
                                        onMouseLeave={(e) => e.currentTarget.style.background = i % 2 === 0 ? '#fff' : '#fcfcfc'}
                                    >
                                        <td style={{ ...tdStyle, fontWeight: 600, color: '#1a1a1a' }}>
                                            {m.month_label}
                                        </td>
                                        <td style={tdStyle}>
                                            {m.total_scans.toLocaleString()}
                                        </td>
                                        <td style={tdStyle}>
                                            <span style={{ color: '#2B8A2B', fontWeight: 600 }}>
                                                {m.total_benign.toLocaleString()}
                                            </span>
                                        </td>
                                        <td style={tdStyle}>
                                            <span style={{ color: '#C83A2B', fontWeight: 600 }}>
                                                {m.total_malicious.toLocaleString()}
                                            </span>
                                        </td>
                                        <td style={tdStyle}>
                                            <span style={{
                                                padding: '3px 8px',
                                                borderRadius: '4px',
                                                fontSize: '0.8rem',
                                                fontWeight: 600,
                                                background: m.detection_rate >= 50 ? '#ffcccc'
                                                    : m.detection_rate >= 20 ? '#ffe5cc'
                                                    : '#e0f5e0',
                                                color: m.detection_rate >= 50 ? '#C83A2B'
                                                    : m.detection_rate >= 20 ? '#c45e00'
                                                    : '#2B8A2B',
                                            }}>
                                                {m.detection_rate}%
                                            </span>
                                        </td>
                                        <td style={tdStyle}>
                                            {m.critical_count > 0 ? (
                                                <span style={{
                                                    padding: '3px 8px', borderRadius: '4px',
                                                    fontSize: '0.8rem', fontWeight: 600,
                                                    background: '#ffcccc', color: '#C83A2B',
                                                }}>
                                                    {m.critical_count}
                                                </span>
                                            ) : (
                                                <span style={{ color: '#999' }}>0</span>
                                            )}
                                        </td>
                                        <td style={tdStyle}>
                                            {m.total_users}
                                        </td>
                                        <td style={{ ...tdStyle, textAlign: 'center' }}>
                                            <button
                                                onClick={() => handleViewSummary(m.month)}
                                                style={{
                                                    padding: '6px 16px',
                                                    borderRadius: '6px',
                                                    border: 'none',
                                                    backgroundColor: '#C83A2B',
                                                    color: '#fff',
                                                    cursor: 'pointer',
                                                    fontSize: '0.85rem',
                                                    fontWeight: 600,
                                                    transition: 'background 0.2s, transform 0.1s',
                                                    whiteSpace: 'nowrap',
                                                }}
                                                onMouseEnter={(e) => e.target.style.backgroundColor = '#a83025'}
                                                onMouseLeave={(e) => e.target.style.backgroundColor = '#C83A2B'}
                                            >
                                                📊 View Summary
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
};

export default MonthlySummaryTable;
