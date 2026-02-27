import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './LoginPage.css';
import '../../styles/webpage.css';
import '../../App.css';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000';

const LoginPage = () => {
    const navigate = useNavigate();
    const [userType, setUserType] = useState('user');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [showPrivileges, setShowPrivileges] = useState(true);
    const [isLoading, setIsLoading] = useState(false);
    const [errorMessage, setErrorMessage] = useState('');
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
        setUsername('');
        setPassword('');
        setShowPassword(false);
        setErrorMessage('');
        setTimeout(() => setShowPrivileges(true), 100);
    };

    const handleSignIn = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setErrorMessage('');

        try {
            // Call real backend API: POST /api/auth/login
            const response = await fetch(`${API_BASE}/api/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                if (response.status === 401) {
                    setErrorMessage('Invalid username or password');
                } else if (response.status === 403) {
                    setErrorMessage(errorData.detail || 'Account is inactive. Please contact administrator.');
                } else {
                    setErrorMessage(errorData.detail || 'Login failed. Please try again.');
                }
                setPassword('');
                setIsLoading(false);
                return;
            }

            const data = await response.json();
            // data = { access_token, token_type, user: { user_id, username, email, first_name, last_name, phone_number, role, is_active, created_at, last_login } }

            // Store token and user data in localStorage for cross-page access
            localStorage.setItem('access_token', data.access_token);
            localStorage.setItem('user_data', JSON.stringify(data.user));

            console.log('Login successful:', data.user.username, '(role:', data.user.role + ')');

            // Route based on the user's actual role from the database
            if (data.user.role === 'admin') {
                navigate('/admin-dashboard');
            } else {
                // User → redirect to standalone user dashboard HTML page
                window.location.href = '/userdashboard_page/RSA_userdashboard.html';
            }
        } catch (error) {
            console.error('Login error:', error);
            setErrorMessage('Cannot connect to server. Please check if the backend is running.');
            setIsLoading(false);
        }
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

                    {/* Error Message */}
                    {errorMessage && (
                        <div className="login-error-message">
                            ⚠️ {errorMessage}
                        </div>
                    )}

                    {/* Login Form */}
                    <form onSubmit={handleSignIn}>
                        <input
                            type="text"
                            placeholder="Username"
                            value={username}
                            onChange={(e) => { setUsername(e.target.value); setErrorMessage(''); }}
                            className="login-input"
                            disabled={isLoading}
                            required
                        />
                        <div className="password-wrapper">
                            <input
                                type={showPassword ? 'text' : 'password'}
                                placeholder="Password"
                                value={password}
                                onChange={(e) => { setPassword(e.target.value); setErrorMessage(''); }}
                                className="login-input password-input"
                                disabled={isLoading}
                                required
                            />
                            <button
                                type="button"
                                className="eye-toggle-btn"
                                onClick={() => setShowPassword(!showPassword)}
                                disabled={isLoading}
                                tabIndex={-1}
                                title={showPassword ? 'Hide password' : 'Show password'}
                            >
                                {showPassword ? '🙈' : '👁️'}
                            </button>
                        </div>
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