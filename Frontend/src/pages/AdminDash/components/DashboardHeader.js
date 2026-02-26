import React from 'react';

const DashboardHeader = ({ userType, onLogout }) => {
    return (
        <header className="dash-header">
            <div className="header-left">
                <h1 className="dash-title">
                    <span className="dash-red">Ran</span><span className="dash-grey">ScanAI</span>
                </h1>
                <nav className="header-nav">
                    <a href="#dashboard" className="nav-link active">Dashboard</a>
                    <a href="#devices" className="nav-link">Devices</a>
                    <a href="#threats" className="nav-link">Threats</a>
                    <a href="#reports" className="nav-link">Reports</a>
                    <a href="#settings" className="nav-link">Settings</a>
                </nav>
            </div>
            <div className="header-right">
                <span className="user-info">{userType} Dashboard</span>
                <button onClick={onLogout} className="logout-btn">Logout</button>
            </div>
        </header>
    );
};

export default DashboardHeader;