import React, { useState, useEffect, useRef } from 'react';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://127.0.0.1:8000';

function authHeaders() {
    const token = localStorage.getItem('access_token');
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}

/* ─── tiny SVG gauge (0-100) ─── */
const Gauge = ({ value, size = 160, color = '#C83A2B', label }) => {
    const radius = (size - 20) / 2;
    const circumference = Math.PI * radius; // half-circle
    const pct = Math.min(Math.max(value, 0), 100);
    const offset = circumference - (pct / 100) * circumference;

    return (
        <div style={{ textAlign: 'center' }}>
            <svg width={size} height={size / 2 + 30} viewBox={`0 0 ${size} ${size / 2 + 30}`}>
                {/* background arc */}
                <path
                    d={`M ${10} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 10} ${size / 2}`}
                    fill="none" stroke="#e0e0e0" strokeWidth="14" strokeLinecap="round"
                />
                {/* value arc */}
                <path
                    d={`M ${10} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 10} ${size / 2}`}
                    fill="none" stroke={color} strokeWidth="14" strokeLinecap="round"
                    strokeDasharray={circumference}
                    strokeDashoffset={offset}
                    style={{ transition: 'stroke-dashoffset 0.8s ease' }}
                />
                <text x={size / 2} y={size / 2 - 6} textAnchor="middle" fontSize="28" fontWeight="700" fill="#1a1a1a">
                    {pct.toFixed(1)}%
                </text>
                {label && (
                    <text x={size / 2} y={size / 2 + 18} textAnchor="middle" fontSize="11" fill="#777">{label}</text>
                )}
            </svg>
        </div>
    );
};

/* ─── circular score (0-100) ─── */
const ScoreCircle = ({ value, size = 140 }) => {
    const radius = (size - 20) / 2;
    const circumference = 2 * Math.PI * radius;
    const pct = Math.min(Math.max(value, 0), 100);
    const offset = circumference - (pct / 100) * circumference;
    const color = pct >= 80 ? '#2B8A2B' : pct >= 50 ? '#FF9500' : '#C83A2B';

    return (
        <div style={{ textAlign: 'center' }}>
            <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
                <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#e0e0e0" strokeWidth="12" />
                <circle
                    cx={size / 2} cy={size / 2} r={radius} fill="none"
                    stroke={color} strokeWidth="12" strokeLinecap="round"
                    strokeDasharray={circumference} strokeDashoffset={offset}
                    transform={`rotate(-90 ${size / 2} ${size / 2})`}
                    style={{ transition: 'stroke-dashoffset 0.8s ease' }}
                />
                <text x={size / 2} y={size / 2 + 8} textAnchor="middle" fontSize="32" fontWeight="700" fill={color}>
                    {Math.round(pct)}%
                </text>
            </svg>
        </div>
    );
};

/* ─── simple bar chart ─── */
const BarChart = ({ data }) => {
    if (!data || data.length === 0) return <div style={{ color: '#888', padding: 20 }}>No user activity data</div>;
    const maxVal = Math.max(...data.map(d => d.legitimate + d.malicious), 1);
    const barWidth = Math.max(24, Math.min(60, 500 / data.length));

    return (
        <div style={{ overflowX: 'auto' }}>
            <svg width={Math.max(data.length * (barWidth + 16) + 40, 300)} height={220} style={{ display: 'block', margin: '0 auto' }}>
                {data.map((d, i) => {
                    const x = 30 + i * (barWidth + 16);
                    const legH = (d.legitimate / maxVal) * 150;
                    const malH = (d.malicious / maxVal) * 150;
                    return (
                        <g key={i}>
                            {/* legitimate bar */}
                            <rect x={x} y={180 - legH - malH} width={barWidth / 2 - 2} height={legH} fill="#2B8A2B" rx="3" />
                            {/* malicious bar */}
                            <rect x={x + barWidth / 2 + 2} y={180 - malH} width={barWidth / 2 - 2} height={malH} fill="#C83A2B" rx="3" />
                            {/* label */}
                            <text x={x + barWidth / 2} y={198} textAnchor="middle" fontSize="9" fill="#555">
                                {d.username.length > 8 ? d.username.slice(0, 7) + '…' : d.username}
                            </text>
                        </g>
                    );
                })}
                {/* legend */}
                <rect x={30} y={210} width={10} height={10} fill="#2B8A2B" rx="2" />
                <text x={44} y={219} fontSize="10" fill="#555">Legitimate</text>
                <rect x={110} y={210} width={10} height={10} fill="#C83A2B" rx="2" />
                <text x={124} y={219} fontSize="10" fill="#555">Malicious</text>
            </svg>
        </div>
    );
};

/* ─── simple line chart ─── */
const LineChart = ({ data }) => {
    if (!data || data.length === 0) return <div style={{ color: '#888', padding: 20 }}>No trend data</div>;
    const maxVal = Math.max(...data.map(d => Math.max(d.malicious, d.benign)), 1);
    const w = Math.max(data.length * 80, 300);
    const h = 180;
    const px = 40, py = 20;

    const points = (key, color) => {
        const pts = data.map((d, i) => {
            const x = px + (i / Math.max(data.length - 1, 1)) * (w - px * 2);
            const y = py + (1 - d[key] / maxVal) * (h - py * 2);
            return `${x},${y}`;
        }).join(' ');
        return <polyline points={pts} fill="none" stroke={color} strokeWidth="2.5" strokeLinejoin="round" />;
    };

    const dots = (key, color) =>
        data.map((d, i) => {
            const x = px + (i / Math.max(data.length - 1, 1)) * (w - px * 2);
            const y = py + (1 - d[key] / maxVal) * (h - py * 2);
            return <circle key={i} cx={x} cy={y} r="4" fill={color} />;
        });

    return (
        <div style={{ overflowX: 'auto' }}>
            <svg width={w} height={h + 30} style={{ display: 'block', margin: '0 auto' }}>
                {/* grid lines */}
                {[0, 0.25, 0.5, 0.75, 1].map((f, i) => {
                    const y = py + (1 - f) * (h - py * 2);
                    return (
                        <g key={i}>
                            <line x1={px} y1={y} x2={w - px} y2={y} stroke="#eee" strokeWidth="1" />
                            <text x={px - 6} y={y + 4} textAnchor="end" fontSize="9" fill="#999">{Math.round(maxVal * f)}</text>
                        </g>
                    );
                })}
                {points('benign', '#2B8A2B')}
                {points('malicious', '#C83A2B')}
                {dots('benign', '#2B8A2B')}
                {dots('malicious', '#C83A2B')}
                {/* x labels */}
                {data.map((d, i) => {
                    const x = px + (i / Math.max(data.length - 1, 1)) * (w - px * 2);
                    return <text key={i} x={x} y={h + 4} textAnchor="middle" fontSize="9" fill="#555">{d.label}</text>;
                })}
                {/* legend */}
                <rect x={px} y={h + 14} width={10} height={10} fill="#2B8A2B" rx="2" />
                <text x={px + 14} y={h + 23} fontSize="10" fill="#555">Benign</text>
                <rect x={px + 80} y={h + 14} width={10} height={10} fill="#C83A2B" rx="2" />
                <text x={px + 94} y={h + 23} fontSize="10" fill="#555">Malicious</text>
            </svg>
        </div>
    );
};


/* ═══════════════════════════════════════════════════════
   MAIN COMPONENT
   ═══════════════════════════════════════════════════════ */
const SummaryReport = () => {
    const [report, setReport] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const reportRef = useRef(null);

    useEffect(() => {
        fetchSummaryReport();
    }, []);

    const fetchSummaryReport = async () => {
        setLoading(true);
        setError('');
        try {
            const res = await fetch(`${API_BASE}/api/detections/admin/summary-report`, {
                headers: authHeaders(),
            });

            if (res.status === 401 || res.status === 403) {
                setError('Unauthorized: Admin access required.');
                setLoading(false);
                return;
            }
            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            const data = await res.json();
            setReport(data);
        } catch (err) {
            console.error('Failed to fetch summary report:', err);
            setError('Failed to load summary report. Make sure the backend is running.');
        } finally {
            setLoading(false);
        }
    };

    const handlePrint = () => {
        window.print();
    };

    /* ─── render states ─── */
    if (loading) {
        return (
            <div style={{ textAlign: 'center', padding: '40px', color: '#888' }}>
                Loading summary report…
            </div>
        );
    }

    if (error) {
        return (
            <div style={{
                background: '#ffe0e0', color: '#C83A2B', padding: '12px 20px',
                borderRadius: '8px', marginBottom: '20px',
            }}>
                {error}
            </div>
        );
    }

    if (!report) return null;

    /* ─── styles (inline to keep self-contained) ─── */
    const sectionBox = {
        background: '#fff',
        borderRadius: '10px',
        padding: '24px',
        marginBottom: '24px',
        boxShadow: '0 2px 8px rgba(0,0,0,0.06)',
    };

    const sectionTitle = (icon, text) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <span style={{
                background: '#C83A2B', color: '#fff', borderRadius: '50%',
                width: 32, height: 32, display: 'flex', alignItems: 'center',
                justifyContent: 'center', fontSize: '16px', flexShrink: 0,
            }}>{icon}</span>
            <h3 style={{ margin: 0, fontSize: '1.1rem', color: '#1a1a1a' }}>{text}</h3>
        </div>
    );

    return (
        <div ref={reportRef}>
            {/* Header bar */}
            <div style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                marginBottom: '16px', flexWrap: 'wrap', gap: '12px',
            }}>
                <h3 style={{ margin: 0 }}>
                    <span style={{ color: '#C83A2B', fontWeight: 700 }}>Ran</span>
                    <span style={{ color: '#555' }}>ScanAI</span>
                    {' '}Summary Report
                </h3>
                <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                        onClick={fetchSummaryReport}
                        style={{
                            padding: '6px 12px', borderRadius: '4px', border: 'none',
                            backgroundColor: '#f0f0f0', cursor: 'pointer', fontSize: '0.9rem',
                        }}
                    >🔄 Refresh</button>
                    <button
                        onClick={handlePrint}
                        style={{
                            padding: '6px 14px', borderRadius: '4px', border: 'none',
                            backgroundColor: '#C83A2B', color: '#fff', cursor: 'pointer',
                            fontSize: '0.9rem', fontWeight: 600,
                        }}
                    >🖨️ Print Report</button>
                </div>
            </div>

            {/* Report title banner */}
            <div style={{
                background: '#1a1a1a', color: '#fff', padding: '18px 24px',
                borderRadius: '10px 10px 0 0', borderBottom: '3px solid #C83A2B',
            }}>
                <h2 style={{ margin: 0, fontSize: '1.3rem' }}>{report.report_title}</h2>
                <small style={{ color: '#aaa' }}>Generated on {report.generated_date}</small>
            </div>

            <div style={{ background: '#fafafa', borderRadius: '0 0 10px 10px', padding: '24px' }}>

                {/* ─── 1. Activity Detection Rate ─── */}
                <div style={sectionBox}>
                    {sectionTitle('📊', 'Activity Detection Rate')}
                    <p style={{ color: '#666', fontSize: '0.9rem', marginBottom: '12px' }}>
                        Percentage of legitimate and malicious activities detected over all user scans.
                    </p>
                    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '40px' }}>
                        <Gauge value={report.detection_rate} color="#C83A2B" label="Malicious Rate" />
                        <div style={{ flex: 1, minWidth: 200, fontSize: '0.92rem', lineHeight: 1.8, color: '#444' }}>
                            <p>
                                Across all users, an average of <strong style={{ color: '#C83A2B' }}>{report.detection_rate}%</strong> of
                                scans were flagged as malicious.
                            </p>
                            <p>
                                <strong>{report.total_scans.toLocaleString()}</strong> total scans performed by{' '}
                                <strong>{report.total_users}</strong> user{report.total_users !== 1 ? 's' : ''}.{' '}
                                <strong style={{ color: '#2B8A2B' }}>{report.total_benign.toLocaleString()}</strong> benign,{' '}
                                <strong style={{ color: '#C83A2B' }}>{report.total_malicious.toLocaleString()}</strong> malicious.
                            </p>
                        </div>
                    </div>
                </div>

                {/* ─── 2. Threat Snapshot ─── */}
                <div style={sectionBox}>
                    {sectionTitle('🛡️', 'Threat Snapshot')}
                    <p style={{ color: '#666', fontSize: '0.9rem', marginBottom: '12px' }}>
                        Summary of all detected malicious activity across users, sorted by most recent.
                    </p>
                    <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.88rem' }}>
                            <thead>
                                <tr style={{ background: '#f5f5f5', textAlign: 'left' }}>
                                    <th style={thStyle}>File</th>
                                    <th style={thStyle}>User</th>
                                    <th style={thStyle}>Severity</th>
                                    <th style={thStyle}>Confidence</th>
                                    <th style={thStyle}>Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                {report.threat_snapshot.length === 0 ? (
                                    <tr><td colSpan="5" style={{ textAlign: 'center', padding: 16, color: '#888' }}>No threats detected</td></tr>
                                ) : (
                                    report.threat_snapshot.slice(0, 20).map((t, i) => (
                                        <tr key={i} style={{ borderBottom: '1px solid #eee' }}>
                                            <td style={tdStyle}>{t.file_name}</td>
                                            <td style={tdStyle}>{t.username}</td>
                                            <td style={tdStyle}>
                                                <span style={{
                                                    padding: '3px 8px', borderRadius: '4px', fontSize: '0.8rem', fontWeight: 600,
                                                    background: t.severity === 'CRITICAL' ? '#ffcccc' : t.severity === 'HIGH' ? '#ffe5cc' : '#fff5cc',
                                                    color: t.severity === 'CRITICAL' ? '#C83A2B' : t.severity === 'HIGH' ? '#c45e00' : '#8a7000',
                                                }}>{t.severity}</span>
                                            </td>
                                            <td style={tdStyle}>{(t.confidence * 100).toFixed(1)}%</td>
                                            <td style={tdStyle}>{t.date}</td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* ─── 3. User Activity Classification ─── */}
                <div style={sectionBox}>
                    {sectionTitle('👥', 'User Activity Classification')}
                    <p style={{ color: '#666', fontSize: '0.9rem', marginBottom: '12px' }}>
                        Number of scanned activities from all users, classified as Legitimate or Malicious.
                    </p>
                    <BarChart data={report.user_activity} />
                </div>

                {/* ─── 4. Ransomware Trends ─── */}
                <div style={sectionBox}>
                    {sectionTitle('📈', 'Ransomware Trends')}
                    <p style={{ color: '#666', fontSize: '0.9rem', marginBottom: '12px' }}>
                        Monthly trend of malicious vs. benign detections across all users.
                    </p>
                    <LineChart data={report.trends} />
                </div>

                {/* ─── 5. System Summary & Score ─── */}
                <div style={sectionBox}>
                    {sectionTitle('💻', 'Overall System Summary')}

                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '30px', alignItems: 'flex-start' }}>
                        <div>
                            <p style={{ fontWeight: 600, color: '#555', marginBottom: 4 }}>
                                # USERS: <span style={{ color: '#1a1a1a' }}>{report.total_users}</span>
                            </p>
                            <p style={{ fontWeight: 600, color: '#555', marginBottom: 12 }}>
                                System Score:
                            </p>
                            <ScoreCircle value={report.system_score} />
                        </div>

                        <div style={{ flex: 1, minWidth: 250, fontSize: '0.92rem', lineHeight: 1.8, color: '#444' }}>
                            <p>
                                During the reporting period, the RanScanAI system scanned 
                                <strong> {report.total_scans.toLocaleString()}</strong> files across{' '}
                                <strong>{report.total_users}</strong> user account{report.total_users !== 1 ? 's' : ''}.
                                A total of <strong style={{ color: '#C83A2B' }}>{report.wannacry_count}</strong>{' '}
                                high-confidence ransomware detection{report.wannacry_count !== 1 ? 's were' : ' was'} identified,
                                with <strong>{report.ai_reclassified_count}</strong> sample{report.ai_reclassified_count !== 1 ? 's' : ''}{' '}
                                reclassified after admin review.
                            </p>
                            <p>
                                {report.no_damage_found
                                    ? 'No data encryption or ransomware damage was found. This shows the system\'s effectiveness in mitigating early-stage ransomware before encryption occurs.'
                                    : 'Critical ransomware activity was detected. Immediate mitigation steps are recommended below.'}
                            </p>

                            <div style={{
                                marginTop: 16, background: '#f9f9f9', border: '1px solid #e0e0e0',
                                borderRadius: '8px', padding: '16px',
                            }}>
                                <h4 style={{ margin: '0 0 8px', color: '#C83A2B', fontSize: '0.95rem' }}>
                                    Suggested Mitigation
                                </h4>
                                <p style={{ margin: 0, color: '#555', fontSize: '0.9rem', lineHeight: 1.7 }}>
                                    {report.suggested_mitigation}
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

/* ─── table cell helpers ─── */
const thStyle = { padding: '10px 12px', fontWeight: 600, borderBottom: '2px solid #ddd', whiteSpace: 'nowrap' };
const tdStyle = { padding: '8px 12px', verticalAlign: 'middle' };

export default SummaryReport;
