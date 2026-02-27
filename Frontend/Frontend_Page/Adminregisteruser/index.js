import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './registration_styles.css';

const API_BASE_URL = process.env.REACT_APP_API_BASE || 'http://localhost:8000';

const COUNTRIES = [
    { flag: '🇲🇾', name: 'Malaysia',             code: '+60'  },
    { flag: '🇸🇬', name: 'Singapore',            code: '+65'  },
    { flag: '🇺🇸', name: 'United States',        code: '+1'   },
    { flag: '🇬🇧', name: 'United Kingdom',       code: '+44'  },
    { flag: '🇦🇺', name: 'Australia',            code: '+61'  },
    { flag: '🇯🇵', name: 'Japan',                code: '+81'  },
    { flag: '🇰🇷', name: 'South Korea',          code: '+82'  },
    { flag: '🇨🇳', name: 'China',               code: '+86'  },
    { flag: '🇮🇳', name: 'India',               code: '+91'  },
    { flag: '🇮🇩', name: 'Indonesia',           code: '+62'  },
    { flag: '🇹🇭', name: 'Thailand',            code: '+66'  },
    { flag: '🇵🇭', name: 'Philippines',         code: '+63'  },
    { flag: '🇻🇳', name: 'Vietnam',             code: '+84'  },
    { flag: '🇭🇰', name: 'Hong Kong',           code: '+852' },
    { flag: '🇹🇼', name: 'Taiwan',              code: '+886' },
    { flag: '🇫🇷', name: 'France',              code: '+33'  },
    { flag: '🇩🇪', name: 'Germany',             code: '+49'  },
    { flag: '🇦🇪', name: 'United Arab Emirates', code: '+971' },
    { flag: '🇸🇦', name: 'Saudi Arabia',        code: '+966' },
    { flag: '🇧🇷', name: 'Brazil',              code: '+55'  },
    { flag: '🇨🇦', name: 'Canada',             code: '+1'   },
    { flag: '🇳🇿', name: 'New Zealand',         code: '+64'  },
    { flag: '🇵🇰', name: 'Pakistan',            code: '+92'  },
    { flag: '🇧🇩', name: 'Bangladesh',          code: '+880' },
    { flag: '🇱🇰', name: 'Sri Lanka',           code: '+94'  },
    { flag: '🇲🇲', name: 'Myanmar',             code: '+95'  },
    { flag: '🇰🇭', name: 'Cambodia',            code: '+855' },
    { flag: '🇱🇦', name: 'Laos',               code: '+856' },
    { flag: '🇧🇳', name: 'Brunei',             code: '+673' },
    { flag: '🇲🇴', name: 'Macau',              code: '+853' },
];

function calcPasswordStrength(password) {
    if (!password) return { level: 0, label: '', cls: '' };
    let strength = 0;
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) strength++;

    if (strength >= 5) return { level: 4, label: 'Strong',  cls: 'strong' };
    if (strength >= 4) return { level: 3, label: 'Good',    cls: 'good'   };
    if (strength >= 3) return { level: 2, label: 'Fair',    cls: 'fair'   };
    return                   { level: 1, label: 'Weak',    cls: 'weak'   };
}

const AdminRegisterUser = () => {
    const navigate = useNavigate();
    const [step, setStep] = useState(1);
    const TOTAL_STEPS = 2;

    const [form, setFormData] = useState({
        firstName: '', lastName: '', email: '', phone: '',
        username: '', password: '', confirmPassword: '',
    });
    const [countryCode, setCountryCode] = useState('+60');
    const [countryDisplay, setCountryDisplay] = useState('🇲🇾 +60');
    const [countrySearch, setCountrySearch] = useState('');
    const [dropdownOpen, setDropdownOpen] = useState(false);
    const [errors, setErrors] = useState({});
    const [showPw, setShowPw] = useState(false);
    const [showConfirmPw, setShowConfirmPw] = useState(false);
    const [loading, setLoading] = useState(false);
    const [successMsg, setSuccessMsg] = useState(null);
    const [errorMsg, setErrorMsg] = useState(null);

    const pickerRef = useRef(null);
    const btnRef = useRef(null);
    const [dropdownPos, setDropdownPos] = useState({ top: 0, left: 0 });

    // Apply light-theme scrollbar while on this page
    useEffect(() => {
        document.body.classList.add('reg-page-active');
        return () => document.body.classList.remove('reg-page-active');
    }, []);

    // Close dropdown on outside click or any scroll
    useEffect(() => {
        const handleClick = (e) => {
            if (pickerRef.current && !pickerRef.current.contains(e.target)) {
                setDropdownOpen(false);
            }
        };
        const handleScroll = () => setDropdownOpen(false);
        document.addEventListener('mousedown', handleClick);
        window.addEventListener('scroll', handleScroll, true); // capture phase catches all scroll containers
        return () => {
            document.removeEventListener('mousedown', handleClick);
            window.removeEventListener('scroll', handleScroll, true);
        };
    }, []);

    // Auth check
    useEffect(() => {
        const token = localStorage.getItem('access_token');
        if (!token) navigate('/login');
    }, [navigate]);

    const filteredCountries = COUNTRIES.filter(c =>
        c.name.toLowerCase().includes(countrySearch.toLowerCase()) ||
        c.code.includes(countrySearch)
    );

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({ ...prev, [name]: value }));
        setErrors(prev => ({ ...prev, [name]: '' }));
    };

    /* ---- Validation ---- */
    function validateStep1() {
        const errs = {};
        if (!form.firstName.trim()) errs.firstName = 'First name is required';
        else if (form.firstName.trim().length < 2) errs.firstName = 'Min 2 characters';

        if (!form.lastName.trim()) errs.lastName = 'Last name is required';
        else if (form.lastName.trim().length < 2) errs.lastName = 'Min 2 characters';

        if (!form.email.trim()) errs.email = 'Email is required';
        else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) errs.email = 'Invalid email address';

        if (form.phone.trim()) {
            const digits = form.phone.replace(/\D/g, '');
            if (digits.length < 7 || digits.length > 15) errs.phone = 'Invalid phone number';
        }
        return errs;
    }

    function validateStep2() {
        const errs = {};
        if (!form.username.trim()) errs.username = 'Username is required';
        else if (form.username.length < 3 || form.username.length > 20) errs.username = '3-20 characters required';
        else if (!/^[a-zA-Z0-9_]+$/.test(form.username)) errs.username = 'Only letters, numbers, underscores';

        if (!form.password) errs.password = 'Password is required';
        else if (form.password.length < 8) errs.password = 'Min 8 characters';
        else if (!/[A-Z]/.test(form.password)) errs.password = 'Must contain uppercase letter';
        else if (!/[a-z]/.test(form.password)) errs.password = 'Must contain lowercase letter';
        else if (!/[0-9]/.test(form.password)) errs.password = 'Must contain number';
        else if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(form.password)) errs.password = 'Must contain special character';

        if (!form.confirmPassword) errs.confirmPassword = 'Please confirm your password';
        else if (form.password !== form.confirmPassword) errs.confirmPassword = 'Passwords do not match';

        return errs;
    }

    const nextStep = () => {
        const errs = validateStep1();
        if (Object.keys(errs).length > 0) { setErrors(errs); return; }
        setStep(2);
    };

    const prevStep = () => setStep(1);

    const progressPct = (step / TOTAL_STEPS) * 100;

    /* ---- Submit ---- */
    const handleSubmit = async (e) => {
        e.preventDefault();
        const errs = validateStep2();
        if (Object.keys(errs).length > 0) { setErrors(errs); return; }

        setLoading(true);
        setSuccessMsg(null);
        setErrorMsg(null);

        const phoneRaw = form.phone.trim();
        const fullPhone = phoneRaw ? countryCode + phoneRaw.replace(/^0+/, '') : null;
        const token = localStorage.getItem('access_token');

        try {
            const response = await fetch(`${API_BASE_URL}/api/auth/admin/create-user`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`,
                },
                body: JSON.stringify({
                    first_name: form.firstName.trim(),
                    last_name: form.lastName.trim(),
                    email: form.email.trim().toLowerCase(),
                    username: form.username.trim(),
                    password: form.password,
                    phone_number: fullPhone,
                    role: 'user',
                }),
            });

            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || 'Registration failed');

            // Navigate back to admin dashboard with success message
            navigate('/admin-dashboard', {
                state: { successMsg: `User "${form.username.trim()}" has been created successfully!` }
            });
        } catch (err) {
            setErrorMsg(err.message || 'Registration failed. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const pwStrength = calcPasswordStrength(form.password);

    return (
        <>
        <div className="main-wrapper">
            {/* Left Panel */}
            <div className="branding-panel">
                <div className="branding-content">
                    <div className="logo-section">
                        <div className="logo-icon">🔐</div>
                        <h1>RanScanAI</h1>
                    </div>
                    <p className="tagline">Advanced Malware Detection &amp; Analysis</p>
                    <div className="features-list">
                        {['Real-time Detection','ML-Based Analysis','Comprehensive Reports','24/7 Monitoring'].map(f => (
                            <div className="feature-item" key={f}>
                                <span className="feature-icon">✓</span>
                                <span>{f}</span>
                            </div>
                        ))}
                    </div>
                    <button
                        className="btn btn-secondary"
                        style={{ marginTop: '32px', width: '100%' }}
                        onClick={() => navigate('/admin-dashboard')}
                    >
                        ← Back to Dashboard
                    </button>
                </div>
            </div>

            {/* Right Panel */}
            <div className="form-panel">
                <div className="form-header">
                    <div className="header-title">
                        <h2>User Registration</h2>
                        <p>System Provider Portal - Create new user account</p>
                    </div>
                    <div className="form-progress">
                        <span className="progress-label">Step <span id="currentStep">{step}</span> of {TOTAL_STEPS}</span>
                        <div className="progress-bar">
                            <div className="progress-fill" style={{ width: `${progressPct}%` }}></div>
                        </div>
                    </div>
                </div>

                <div className="form-container">
                    <form className="registration-form" onSubmit={handleSubmit} noValidate>

                        {/* Step 1 */}
                        <div className={`form-step${step === 1 ? ' active' : ''}`} data-step="1">
                            <div className="step-header">
                                <h3>Personal Information</h3>
                                <p>Enter user's basic details</p>
                            </div>

                            <div className="form-row">
                                <div className="form-group">
                                    <label htmlFor="firstName">First Name <span className="required">*</span></label>
                                    <input
                                        type="text" id="firstName" name="firstName"
                                        placeholder="John" value={form.firstName}
                                        onChange={handleChange}
                                        className={errors.firstName ? 'error' : ''}
                                    />
                                    {errors.firstName && <span className="error-message show">{errors.firstName}</span>}
                                </div>
                                <div className="form-group">
                                    <label htmlFor="lastName">Last Name <span className="required">*</span></label>
                                    <input
                                        type="text" id="lastName" name="lastName"
                                        placeholder="Doe" value={form.lastName}
                                        onChange={handleChange}
                                        className={errors.lastName ? 'error' : ''}
                                    />
                                    {errors.lastName && <span className="error-message show">{errors.lastName}</span>}
                                </div>
                            </div>

                            <div className="form-group">
                                <label htmlFor="email">Email Address <span className="required">*</span></label>
                                <input
                                    type="email" id="email" name="email"
                                    placeholder="john.doe@example.com" value={form.email}
                                    onChange={handleChange}
                                    className={errors.email ? 'error' : ''}
                                />
                                {errors.email && <span className="error-message show">{errors.email}</span>}
                            </div>

                            <div className="form-group">
                                <label htmlFor="phone">Phone Number</label>
                                <div className="phone-input-wrapper">
                                    <div className="country-picker" ref={pickerRef}>
                                        <button
                                            type="button"
                                            className="country-picker-btn"
                                            ref={btnRef}
                                            onClick={() => {
                                                if (!dropdownOpen && btnRef.current) {
                                                    const rect = btnRef.current.getBoundingClientRect();
                                                    setDropdownPos({ top: rect.bottom + 4, left: rect.left });
                                                }
                                                setDropdownOpen(o => !o);
                                            }}
                                        >
                                            <span>{countryDisplay}</span>
                                            <span className="country-picker-arrow">&#9662;</span>
                                        </button>
                                        {dropdownOpen && (
                                            <div className="country-picker-dropdown open" style={{ position: 'fixed', top: dropdownPos.top, left: dropdownPos.left, zIndex: 9999 }}>
                                                <div className="country-search-wrap">
                                                    <input
                                                        type="text"
                                                        className="country-search-input"
                                                        placeholder="🔍 Search country..."
                                                        value={countrySearch}
                                                        onChange={e => setCountrySearch(e.target.value)}
                                                        autoFocus
                                                    />
                                                </div>
                                                <ul className="country-picker-list">
                                                    {filteredCountries.length === 0 ? (
                                                        <li className="no-results">No countries found</li>
                                                    ) : filteredCountries.map(c => (
                                                        <li
                                                            key={c.name}
                                                            className={c.code === countryCode ? 'active' : ''}
                                                            onClick={() => {
                                                                setCountryCode(c.code);
                                                                setCountryDisplay(`${c.flag} ${c.code}`);
                                                                setDropdownOpen(false);
                                                                setCountrySearch('');
                                                            }}
                                                        >
                                                            <span>{c.flag}</span>
                                                            <span>{c.name}</span>
                                                            <span className="dial-code">{c.code}</span>
                                                        </li>
                                                    ))}
                                                </ul>
                                            </div>
                                        )}
                                    </div>
                                    <input
                                        type="tel" id="phone" name="phone"
                                        placeholder="12 345 6789"
                                        className={`phone-number-input${errors.phone ? ' error' : ''}`}
                                        value={form.phone} onChange={handleChange}
                                    />
                                </div>
                                {errors.phone && <span className="error-message show">{errors.phone}</span>}
                            </div>
                        </div>

                        {/* Step 2 */}
                        <div className={`form-step${step === 2 ? ' active' : ''}`} data-step="2">
                            <div className="step-header">
                                <h3>Account Setup</h3>
                                <p>Create secure credentials</p>
                            </div>

                            <div className="form-group">
                                <label htmlFor="username">Username <span className="required">*</span></label>
                                <input
                                    type="text" id="username" name="username"
                                    placeholder="john_doe_123" value={form.username}
                                    onChange={handleChange}
                                    className={errors.username ? 'error' : ''}
                                />
                                <span className="help-text">3-20 characters, alphanumeric and underscores</span>
                                {errors.username && <span className="error-message show">{errors.username}</span>}
                            </div>

                            <div className="form-group">
                                <label htmlFor="password">Password <span className="required">*</span></label>
                                <div className="password-input-wrapper">
                                    <input
                                        type={showPw ? 'text' : 'password'}
                                        id="password" name="password"
                                        placeholder="••••••••" value={form.password}
                                        onChange={handleChange}
                                        className={errors.password ? 'error' : ''}
                                    />
                                    <button type="button" className="toggle-password" onClick={() => setShowPw(v => !v)}>
                                        <span className="eye-icon">👁️</span>
                                    </button>
                                </div>
                                <span className="help-text">Min 8 characters: uppercase, lowercase, number &amp; special char</span>
                                {form.password && (
                                    <div className="password-strength" id="passwordStrength">
                                        <div className={`password-strength-text`}>{pwStrength.label}</div>
                                        <div className={`password-strength ${pwStrength.cls}`}>
                                            {[0,1,2,3].map(i => (
                                                <div key={i} className="password-strength-bar"></div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                {errors.password && <span className="error-message show">{errors.password}</span>}
                            </div>

                            <div className="form-group">
                                <label htmlFor="confirmPassword">Confirm Password <span className="required">*</span></label>
                                <div className="password-input-wrapper">
                                    <input
                                        type={showConfirmPw ? 'text' : 'password'}
                                        id="confirmPassword" name="confirmPassword"
                                        placeholder="••••••••" value={form.confirmPassword}
                                        onChange={handleChange}
                                        className={errors.confirmPassword ? 'error' : ''}
                                    />
                                    <button type="button" className="toggle-password" onClick={() => setShowConfirmPw(v => !v)}>
                                        <span className="eye-icon">👁️</span>
                                    </button>
                                </div>
                                {errors.confirmPassword && <span className="error-message show">{errors.confirmPassword}</span>}
                            </div>
                        </div>

                        {/* Actions */}
                        <div className="form-actions">
                            {step > 1 && (
                                <button type="button" className="btn btn-secondary" onClick={prevStep}>
                                    ← Previous
                                </button>
                            )}
                            {step < TOTAL_STEPS && (
                                <button type="button" className="btn btn-primary" onClick={nextStep}>
                                    Next →
                                </button>
                            )}
                            {step === TOTAL_STEPS && (
                                <button type="submit" className="btn btn-success" disabled={loading}>
                                    {loading ? 'Creating…' : 'Create User Account'}
                                </button>
                            )}
                        </div>
                    </form>
                </div>



                {/* Error Message */}
                {errorMsg && (
                    <div className="message-container">
                        <div className="alert alert-error">
                            <div className="alert-header">
                                <span className="alert-icon">✕</span>
                                <strong>Registration Error</strong>
                            </div>
                            <p>{errorMsg}</p>
                            <button type="button" className="btn-small btn-close" onClick={() => setErrorMsg(null)}>Dismiss</button>
                        </div>
                    </div>
                )}

                {/* Loading Overlay */}
                {loading && (
                    <div className="loading-overlay" style={{ display: 'flex' }}>
                        <div className="loader"></div>
                        <p>Processing registration...</p>
                    </div>
                )}
            </div>
        </div>

        {/* Footer */}
        <footer className="footer">
            <p>&copy; 2026 RanScanAI Security Platform. All rights reserved.</p>
        </footer>
        </>
    );
};

export default AdminRegisterUser;
