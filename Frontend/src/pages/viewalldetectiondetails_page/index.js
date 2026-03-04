import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import './ViewAllDetectionDetails.css';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000';

function authHeaders() {
    const token = localStorage.getItem('access_token');
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}

function formatFileSize(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
}

function padId(id) {
    return 'D' + String(id).padStart(3, '0');
}

/* ─── SVG Icons ─── */
const ArrowLeftIcon = () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <line x1="19" y1="12" x2="5" y2="12" /><polyline points="12 19 5 12 12 5" />
    </svg>
);

const BellIcon = () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.73 21a2 2 0 0 1-3.46 0" />
    </svg>
);

const UserIcon = () => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" />
    </svg>
);

const ShieldIcon = () => (
    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
);

const WarningIcon = () => (
    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
        <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
);

const ErrorCircleIcon = () => (
    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#5B6380" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
);

const ViewAllDetectionDetails = () => {
    const { detectionId } = useParams();
    const navigate = useNavigate();
    const [detection, setDetection] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        const token = localStorage.getItem('access_token');
        if (!token) {
            navigate('/login');
            return;
        }

        if (!detectionId) {
            setError('No detection ID specified');
            setLoading(false);
            return;
        }

        fetchDetection();
    }, [detectionId]); // eslint-disable-line react-hooks/exhaustive-deps

    const fetchDetection = async () => {
        setLoading(true);
        setError('');
        try {
            const res = await fetch(`${API_BASE}/api/detections/${detectionId}`, {
                headers: authHeaders(),
            });

            if (res.status === 401) {
                localStorage.removeItem('access_token');
                localStorage.removeItem('user_data');
                navigate('/login');
                return;
            }

            if (!res.ok) {
                throw new Error(res.status === 404 ? 'Detection not found' : 'Failed to fetch detection');
            }

            const data = await res.json();
            setDetection(data);
        } catch (err) {
            console.error('Failed to fetch detection:', err);
            setError(err.message || 'Detection not found');
        } finally {
            setLoading(false);
        }
    };

    /* ─── Derived values ─── */
    const getSeverity = (d) => {
        const confidence = d.confidence || 0;
        if (!d.is_malicious) return { text: 'SAFE', className: 'severity-safe' };
        if (confidence >= 0.9) return { text: 'CRITICAL', className: 'severity-critical' };
        if (confidence >= 0.7) return { text: 'HIGH', className: 'severity-high' };
        return { text: 'MEDIUM', className: 'severity-medium' };
    };

    const getThreatType = (d) => {
        if (d.is_malicious) {
            return d.prediction_label === 'MALWARE' ? 'Malware Detected' : d.prediction_label;
        }
        return 'No Threat Detected';
    };

    const parseDateTime = (d) => {
        let date = '—', time = '—';
        if (d.display_time) {
            const parts = d.display_time.split(' ');
            if (parts.length >= 4) {
                date = `${parts[0]} ${parts[1]} ${parts[2]}`;
                time = parts[3];
            } else {
                date = d.display_time;
            }
        } else if (d.timestamp) {
            const dt = new Date(d.timestamp);
            date = dt.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
            time = dt.toLocaleTimeString('en-GB');
        }
        return { date, time };
    };

    const handleBack = () => {
        window.location.href = '/viewalldetection_page/RSA_viewalldetection.html';
    };

    return (
        <div className="vad-page">
            {/* Header */}
            <header className="vad-header">
                <div className="vad-header-left">
                    <a className="vad-logo" href="/userdashboard_page/RSA_userdashboard.html" aria-label="Go to dashboard">
                        <img src="/userdashboard_page/RSA_logo.png" alt="RanScanAI logo" className="vad-logo-img" />
                        <span className="vad-logo-text">
                            <span className="vad-logo-ran">Ran</span>
                            <span className="vad-logo-scan">Scan</span>
                            <span className="vad-logo-ai">AI</span>
                        </span>
                    </a>
                    <span className="vad-header-divider"></span>
                    <span className="vad-header-page-title">Incident Details</span>
                </div>
                <div className="vad-header-right">
                    <button className="vad-icon-btn vad-bell-btn" aria-label="Notifications">
                        <BellIcon />
                        <span className="vad-notif-dot"></span>
                    </button>
                    <a className="vad-icon-btn" href="/userprofile_page/RSA_userprofile.html" aria-label="User profile">
                        <UserIcon />
                    </a>
                </div>
            </header>

            <main className="vad-page-wrap">
                {/* Page Title */}
                <div className="vad-page-title">
                    <button className="vad-back-link" onClick={handleBack} aria-label="Back to all detections">
                        <ArrowLeftIcon />
                        <span>Back to All Detections</span>
                    </button>
                    <h1>Incident Details</h1>
                </div>

                {/* Loading State */}
                {loading && (
                    <div className="vad-details-grid">
                        <section className="vad-details-card vad-summary-card">
                            <div className="vad-card-header"><h2>Loading...</h2></div>
                            <div className="vad-summary-content">
                                <p style={{ color: '#5B6380' }}>Fetching detection data...</p>
                            </div>
                        </section>
                    </div>
                )}

                {/* Error State */}
                {!loading && error && (
                    <div className="vad-details-grid">
                        <section className="vad-details-card vad-summary-card">
                            <div className="vad-card-header"><h2>No Detection Found</h2></div>
                            <div className="vad-summary-content">
                                <div className="vad-summary-icon" style={{ background: 'var(--vad-bg-hover)' }}>
                                    <ErrorCircleIcon />
                                </div>
                                <div className="vad-summary-info">
                                    <h3 className="vad-threat-name">{error}</h3>
                                    <p className="vad-threat-type">The requested detection could not be loaded.</p>
                                </div>
                            </div>
                        </section>
                    </div>
                )}

                {/* Detection Content */}
                {!loading && !error && detection && (() => {
                    const severity = getSeverity(detection);
                    const confidence = detection.confidence || 0;
                    const threatType = getThreatType(detection);
                    const { date, time } = parseDateTime(detection);

                    return (
                        <div className="vad-details-grid">
                            {/* Summary Card */}
                            <section className="vad-details-card vad-summary-card">
                                <div className="vad-card-header">
                                    <h2>Threat Summary</h2>
                                    <span className={`vad-severity-badge ${severity.className}`}>
                                        {severity.text}
                                    </span>
                                </div>
                                <div className="vad-summary-content">
                                    <div
                                        className="vad-summary-icon"
                                        style={{
                                            background: detection.is_malicious
                                                ? 'var(--vad-color-danger-bg)'
                                                : 'var(--vad-color-success-bg)',
                                        }}
                                    >
                                        <div style={{
                                            color: detection.is_malicious
                                                ? 'var(--vad-color-danger)'
                                                : 'var(--vad-color-success)',
                                        }}>
                                            {detection.is_malicious ? <WarningIcon /> : <ShieldIcon />}
                                        </div>
                                    </div>
                                    <div className="vad-summary-info">
                                        <h3 className="vad-threat-name">{detection.file_name || '—'}</h3>
                                        <p className="vad-threat-type">
                                            {threatType} ({(confidence * 100).toFixed(1)}% confidence)
                                        </p>
                                    </div>
                                </div>
                            </section>

                            {/* Info Card */}
                            <section className="vad-details-card vad-info-card">
                                <h2>Detection Information</h2>
                                <div className="vad-info-list">
                                    <div className="vad-info-row">
                                        <span className="vad-info-label">Detection ID</span>
                                        <span className="vad-info-value">{padId(detection.id)}</span>
                                    </div>
                                    <div className="vad-info-row">
                                        <span className="vad-info-label">Date</span>
                                        <span className="vad-info-value">{date}</span>
                                    </div>
                                    <div className="vad-info-row">
                                        <span className="vad-info-label">Time</span>
                                        <span className="vad-info-value">{time}</span>
                                    </div>
                                    <div className="vad-info-row">
                                        <span className="vad-info-label">Model</span>
                                        <span className="vad-info-value">{detection.model_type || '—'}</span>
                                    </div>
                                    <div className="vad-info-row">
                                        <span className="vad-info-label">Features Analyzed</span>
                                        <span className="vad-info-value">
                                            {detection.features_analyzed != null
                                                ? detection.features_analyzed.toLocaleString()
                                                : '—'}
                                        </span>
                                    </div>
                                </div>
                            </section>

                            {/* File Details Card */}
                            <section className="vad-details-card vad-file-card">
                                <h2>File Details</h2>
                                <div className="vad-info-list">
                                    <div className="vad-info-row">
                                        <span className="vad-info-label">File Path</span>
                                        <span className="vad-info-value vad-file-path">
                                            {detection.file_path || '—'}
                                        </span>
                                    </div>
                                    <div className="vad-info-row">
                                        <span className="vad-info-label">File Size</span>
                                        <span className="vad-info-value">
                                            {detection.file_size ? formatFileSize(detection.file_size) : '—'}
                                        </span>
                                    </div>
                                    {detection.is_malicious && detection.file_hash && (
                                        <div className="vad-info-row">
                                            <span className="vad-info-label">SHA-256</span>
                                            <span className="vad-info-value vad-hash-value">
                                                {detection.file_hash}
                                            </span>
                                        </div>
                                    )}
                                    <div className="vad-info-row">
                                        <span className="vad-info-label">Status</span>
                                        <span className={`vad-info-value ${
                                            detection.is_malicious ? 'vad-status-quarantined' : 'vad-status-clean'
                                        }`}>
                                            {detection.is_malicious ? 'Quarantined' : 'Clean'}
                                        </span>
                                    </div>
                                </div>
                            </section>

                            {/* Action Card */}
                            <section className="vad-details-card vad-action-card">
                                <h2>Recommended Actions</h2>
                                <p className="vad-action-desc">
                                    {detection.is_malicious
                                        ? 'The threat has been isolated. Please review the file details and choose an action.'
                                        : 'This file has been scanned and no threats were detected. No action is required.'}
                                </p>
                                {detection.is_malicious && (
                                    <div className="vad-action-buttons">
                                        <button className="vad-btn vad-btn-danger">Delete File</button>
                                        <button className="vad-btn vad-btn-secondary">Restore (Not Recommended)</button>
                                    </div>
                                )}
                            </section>
                        </div>
                    );
                })()}
            </main>
        </div>
    );
};

export default ViewAllDetectionDetails;
