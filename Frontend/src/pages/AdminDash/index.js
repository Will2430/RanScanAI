import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './AdminDash.css';
import DashboardHeader from './components/DashboardHeader';
import StatCard from './components/StatCard';
import ChartSection from './components/ChartSection';
import DataTable from './components/DataTable';

const AdminDash = () => {
    const navigate = useNavigate();
    const [timeRange, setTimeRange] = useState('7days');

    const stats = [
        { title: 'Total Threats', value: '2,451', trend: '+12%', color: 'red' },
        { title: 'Devices Monitored', value: '1,248', trend: '+8%', color: 'blue' },
        { title: 'Threats Blocked', value: '892', trend: '+15%', color: 'green' },
        { title: 'Critical Issues', value: '23', trend: '+5%', color: 'orange' }
    ];

    const tableData = [
        { id: 'TRE001', threat: 'Ransomware.Win32', severity: 'CRITICAL', status: 'W-BLOCKED', date: '2024-01-15 09:30', devices: 3 },
        { id: 'TRE002', threat: 'Trojan.Generic', severity: 'HIGH', status: 'W-ISOLATED', date: '2024-01-14 14:22', devices: 1 },
        { id: 'TRE003', threat: 'Worm.Email', severity: 'MEDIUM', status: 'QUARANTINE', date: '2024-01-13 11:45', devices: 5 },
        { id: 'TRE004', threat: 'Exploit.Java', severity: 'HIGH', status: 'PATCHED', date: '2024-01-12 16:20', devices: 2 },
        { id: 'TRE005', threat: 'Malware.Crypto', severity: 'CRITICAL', status: 'W-REMOVED', date: '2024-01-11 08:15', devices: 4 },
    ];

    return (
        <div className="admin-dash-container">
            <DashboardHeader userType="Admin" onLogout={() => navigate('/login')} />

            <div className="dash-content">
                {/* Top Navigation */}
                <div className="dash-nav">
                    <h2>Dashboard Overview</h2>
                    <div className="nav-controls">
                        <select value={timeRange} onChange={(e) => setTimeRange(e.target.value)} className="time-select">
                            <option value="24hours">Last 24 Hours</option>
                            <option value="7days">Last 7 Days</option>
                            <option value="30days">Last 30 Days</option>
                            <option value="90days">Last 90 Days</option>
                        </select>
                        <button className="export-btn">📊 Export Report</button>
                    </div>
                </div>

                {/* Statistics Cards */}
                <div className="stats-grid">
                    {stats.map((stat, index) => (
                        <StatCard key={index} {...stat} />
                    ))}
                </div>

                {/* Charts Section */}
                <div className="charts-section">
                    <ChartSection />
                </div>

                {/* Data Table */}
                <div className="table-section">
                    <h3>Recent Threats Detected</h3>
                    <DataTable data={tableData} />
                </div>
            </div>
        </div>
    );
};

export default AdminDash;