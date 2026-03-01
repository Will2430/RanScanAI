import React from 'react';
import { useNavigate } from 'react-router-dom';

const DashboardHeader = ({ userType, onLogout }) => {
    const navigate = useNavigate();

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
            </div>
            <div className="header-right">
                <span className="user-info">{adminName} — {userType}</span>
                <button onClick={onLogout} className="logout-btn">Logout</button>
            </div>
        </header>
    );
};

export default DashboardHeader;