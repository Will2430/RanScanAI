import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000';

const DashboardHeader = ({ userType, onLogout }) => {
    const navigate = useNavigate();
    const [cnnStatus, setCnnStatus] = useState(null); // null | 'loading' | 'remote' | 'local' | 'error'

    const reloadCnnService = async () => {
        setCnnStatus('loading');
        try {
            const token = localStorage.getItem('access_token');
            const res = await fetch(`${API_BASE}/reload-cnn-service`, {
                method: 'POST',
                headers: token ? { 'Authorization': 'Bearer ' + token } : {},
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            setCnnStatus(data.status); // 'remote' or 'local'
            setTimeout(() => setCnnStatus(null), 4000);
        } catch (e) {
            setCnnStatus('error');
            setTimeout(() => setCnnStatus(null), 4000);
        }
    };

    // Get admin name from localStorage
    let adminName = 'Admin';
    try {
        const userData = JSON.parse(localStorage.getItem('user_data'));
        if (userData) {
            adminName = (userData.first_name || '') + ' ' + (userData.last_name || '');
            if (adminName.trim() === '') adminName = userData.username || 'Admin';
        }
    } catch (e) { /* ignore */ }

    return (
        <header className="dash-header">
            <div className="header-left">
                <h1 className="dash-title">
                    <span className="dash-red">Ran</span><span className="dash-grey">ScanAI</span>
                </h1>
                <button
                    className="register-user-btn"
                    onClick={() => navigate('/admin-register-user')}
                    title="Register new user"
                >
                    + Register User
                </button>
                <button
                    className="manage-users-btn"
                    onClick={() => navigate('/admin-manage-users')}
                    title="Manage users"
                >
                    Manage Users
                </button>
                <button
                    className="manage-users-btn"
                    onClick={reloadCnnService}
                    disabled={cnnStatus === 'loading'}
                    title="Re-probe model_service and switch to remote if reachable"
                >
                    {cnnStatus === 'loading' && 'Probing...'}
                    {cnnStatus === 'remote'  && '✓ Remote CNN'}
                    {cnnStatus === 'local'   && '⚠ Local mode'}
                    {cnnStatus === 'error'   && '✗ Failed'}
                    {cnnStatus === null      && 'Reload CNN'}
                </button>
            </div>
            <div className="header-right">
                <span className="user-info">{adminName} — {userType}</span>
                <button onClick={onLogout} className="logout-btn">Logout</button>
            </div>
        </header>
    );
};

export default DashboardHeader;