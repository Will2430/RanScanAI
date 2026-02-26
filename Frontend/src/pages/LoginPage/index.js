import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './LoginPage.css';
import '../../styles/webpage.css';
import '../../App.css';

const LoginPage = () => {
    const navigate = useNavigate();
    const [userType, setUserType] = useState('user');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [showPrivileges, setShowPrivileges] = useState(true);
    const [isLoading, setIsLoading] = useState(false);
    const RanScanLogo = '/assets/images/RanScanLogo.png';
    const DbLockImage = '/assets/images/DbLockImage.png';

    const privilegeInfo = {
        user: {
            title: '👤 User Privileges',
            privileges: [
                'Monitor their own devices',
                'Gain real-time identification of ransomware',
                'Generate personal reports',
                'Access log files of all users',
                'View all identified detections'
            ]
        },
        admin: {
            title: '👨‍💼 Administrator Privileges',
            privileges: [
                'Monitor User Devices',
                'User Management & Permissions',
                'System Configuration & Strategies',
                'View Monthly Reports',
                'Perform Uncertain sample review'
            ]
        }
    };

    const handleUserTypeChange = (type) => {
        // Don't allow changing user type while loading
        if (isLoading) return;
        
        setShowPrivileges(false);
        setUserType(type);
        setTimeout(() => setShowPrivileges(true), 100);
    };

    const handleSignIn = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        
        setTimeout(() => {
            console.log('Signing in as:', userType, username);
            setIsLoading(false);
            // Navigate to admin dashboard
            navigate('/admin-dashboard');
        }, 2000);
    };

    return (
        <div className="login-container">
            {/* Home Icon */}
            <button 
                className="home-icon-btn"
                onClick={() => navigate('/')}
                title="Back to Home"
                disabled={isLoading}
            >
                🏠
            </button>

            <div className="login-content">
                {/* Left Section */}
                <div className="login-left">
                    <div className="logo-section">
                        <img src={RanScanLogo} alt="RanScanLogo" className="logo-icon" />
                        <h1>
                            <span className="title-red">Ran</span><span className="title-grey">ScanAI</span>
                        </h1>
                    </div>

                    <h2>Welcome Back</h2>

                    {/* User Type Buttons */}
                    <div className="user-type-buttons">
                        <button 
                            className={`user-type-btn ${userType === 'admin' ? 'active' : ''}`}
                            onClick={() => handleUserTypeChange('admin')}
                            disabled={isLoading}
                        >
                            Admin
                        </button>
                        <button 
                            className={`user-type-btn ${userType === 'user' ? 'active' : ''}`}
                            onClick={() => handleUserTypeChange('user')}
                            disabled={isLoading}
                        >
                            User
                        </button>
                    </div>

                    {/* Privileges Information Pane */}
                    {showPrivileges && (
                        <div className="privileges-pane">
                            <h3>{privilegeInfo[userType].title}</h3>
                            <ul className="privileges-list">
                                {privilegeInfo[userType].privileges.map((privilege, index) => (
                                    <li key={index}>{privilege}</li>
                                ))}
                            </ul>
                        </div>
                    )}

                    {/* Login Form */}
                    <form onSubmit={handleSignIn}>
                        <input
                            type="text"
                            placeholder="Username"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            className="login-input"
                            disabled={isLoading}
                            required
                        />
                        <input
                            type="password"
                            placeholder="Password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            className="login-input"
                            disabled={isLoading}
                            required
                        />
                        <button 
                            type="submit" 
                            className="sign-in-btn"
                            disabled={isLoading}
                        >
                            {isLoading ? 'Signing In...' : 'Sign In'}
                        </button>
                    </form>
                </div>

                {/* Right Section - Lock Image */}
                <div className="login-right">
                    <img src={DbLockImage} alt="Security Lock" className="lock-image" />
                </div>
            </div>
        </div>
    );
};

export default LoginPage;