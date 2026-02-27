import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './AdminDash.css';
import DashboardHeader from './components/DashboardHeader';
import StatCard from './components/StatCard';
import ChartSection from './components/ChartSection';
import DataTable from './components/DataTable';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000';

function authHeaders() {
    const token = localStorage.getItem('access_token');
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}

const AdminDash = () => {
    const navigate = useNavigate();
    const [timeRange, setTimeRange] = useState('all');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    // Real data state
    const [stats, setStats] = useState([
        { title: 'Total Scans', value: '—', trend: '', color: 'blue' },
        { title: 'Total Threats', value: '—', trend: '', color: 'red' },
        { title: 'Threats Blocked', value: '—', trend: '', color: 'green' },
        { title: 'Critical Issues', value: '—', trend: '', color: 'orange' }
    ]);
    const [tableData, setTableData] = useState([]);
    const [chartData, setChartData] = useState({ detections: [] });

    useEffect(() => {
        // Verify admin is logged in
        const token = localStorage.getItem('access_token');
        if (!token) {
            navigate('/login');
            return;
        }

        fetchAdminData();
    }, []); // eslint-disable-line react-hooks/exhaustive-deps

    const fetchAdminData = async () => {
        setLoading(true);
        setError('');
        try {
            const res = await fetch(`${API_BASE}/api/detections/admin/stats`, {
                headers: authHeaders()
            });

            if (res.status === 401) {
                localStorage.removeItem('access_token');
                localStorage.removeItem('user_data');
                navigate('/login');
                return;
            }
            if (res.status === 403) {
                setError('Admin privileges required.');
                setLoading(false);
                return;
            }
            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            const data = await res.json();

            // Build stat cards from real data
            const threatRate = data.total_scans > 0
                ? Math.round((data.total_threats / data.total_scans) * 100)
                : 0;

            setStats([
                { title: 'Total Scans', value: data.total_scans.toLocaleString(), trend: `${data.total_users} users`, color: 'blue' },
                { title: 'Total Threats', value: data.total_threats.toLocaleString(), trend: `${threatRate}% detection rate`, color: 'red' },
                { title: 'Benign Files', value: data.total_benign.toLocaleString(), trend: `${100 - threatRate}% safe`, color: 'green' },
                { title: 'Critical Issues', value: data.critical_threats.toLocaleString(), trend: 'confidence ≥ 90%', color: 'orange' }
            ]);

            // Build table rows from detections
            const rows = data.detections.map((d) => {
                const severity = d.is_malicious
                    ? (d.confidence >= 0.9 ? 'CRITICAL' : d.confidence >= 0.7 ? 'HIGH' : 'MEDIUM')
                    : 'LOW';
                return {
                    id: `D${String(d.id).padStart(3, '0')}`,
                    file_name: d.file_name,
                    username: d.username || '—',
                    role: d.role || '—',
                    severity,
                    prediction: d.prediction_label,
                    confidence: `${(d.confidence * 100).toFixed(1)}%`,
                    date: d.display_time,
                };
            });
            setTableData(rows);
            setChartData({ detections: data.detections });
        } catch (err) {
            console.error('Admin dashboard fetch error:', err);
            setError('Failed to load dashboard data. Make sure the backend is running.');
        } finally {
            setLoading(false);
        }
    };

    const handleLogout = () => {
        localStorage.removeItem('access_token');
        localStorage.removeItem('user_data');
        navigate('/login');
    };

    return (
        <div className="admin-dash-container">
            <DashboardHeader userType="Admin" onLogout={handleLogout} />

            <div className="dash-content">
                {/* Top Navigation */}
                <div className="dash-nav">
                    <h2>Dashboard Overview</h2>
                    <div className="nav-controls">
                        <button className="export-btn" onClick={fetchAdminData} disabled={loading}>
                            🔄 Refresh
                        </button>
                    </div>
                </div>

                {error && (
                    <div style={{
                        background: '#ffe0e0', color: '#C83A2B', padding: '12px 20px',
                        borderRadius: '8px', marginBottom: '20px', fontWeight: 500
                    }}>
                        {error}
                    </div>
                )}

                {loading ? (
                    <div style={{ textAlign: 'center', padding: '60px 0', color: '#888' }}>
                        Loading dashboard data…
                    </div>
                ) : (
                    <>
                        {/* Statistics Cards */}
                        <div className="stats-grid">
                            {stats.map((stat, index) => (
                                <StatCard key={index} {...stat} />
                            ))}
                        </div>

                        {/* Charts Section */}
                        <div className="charts-section">
                            <ChartSection detections={chartData.detections} />
                        </div>

                        {/* Data Table */}
                        <div className="table-section">
                            <h3>All Detection History</h3>
                            <DataTable data={tableData} />
                        </div>
                    </>
                )}
            </div>
        </div>
    );
};

export default AdminDash;