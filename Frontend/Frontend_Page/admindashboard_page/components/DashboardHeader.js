import React from 'react';

const DashboardHeader = ({ userType, onLogout }) => {
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
            </div>
            <div className="header-right">
                <span className="user-info">{adminName} — {userType}</span>
                <button onClick={onLogout} className="logout-btn">Logout</button>
            </div>
        </header>
    );
};

export default DashboardHeader;