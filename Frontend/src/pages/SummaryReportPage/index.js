import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import SummaryReport from '../admindashboard_page/components/SummaryReport';

const SummaryReportPage = () => {
    const { month } = useParams();
    const navigate = useNavigate();

    // Format month label for display (e.g. "2026-03" → "March 2026")
    const monthNames = [
        'January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December',
    ];
    let monthLabel = 'Summary Report';
    if (month) {
        const parts = month.split('-');
        if (parts.length === 2) {
            const yr = parts[0];
            const mo = parseInt(parts[1], 10);
            if (mo >= 1 && mo <= 12) {
                monthLabel = `${monthNames[mo - 1]} ${yr} Summary Report`;
            }
        }
    }

    return (
        <div style={{
            background: '#f5f5f5',
            minHeight: '100vh',
            fontFamily: "'Inter', 'Segoe UI', system-ui, sans-serif",
        }}>
            {/* Top bar */}
            <div style={{
                background: '#1a1a1a',
                color: '#fff',
                padding: '14px 30px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                borderBottom: '2px solid #C83A2B',
                boxShadow: '0 2px 10px rgba(0,0,0,0.3)',
            }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <button
                        onClick={() => navigate('/admin-dashboard')}
                        style={{
                            background: 'transparent',
                            border: '1.5px solid #C83A2B',
                            color: '#C83A2B',
                            borderRadius: '6px',
                            padding: '7px 16px',
                            fontSize: '0.92rem',
                            fontWeight: 700,
                            cursor: 'pointer',
                            transition: 'background 0.2s, color 0.2s',
                        }}
                        onMouseEnter={(e) => { e.target.style.background = '#C83A2B'; e.target.style.color = '#fff'; }}
                        onMouseLeave={(e) => { e.target.style.background = 'transparent'; e.target.style.color = '#C83A2B'; }}
                    >
                        ← Back to Dashboard
                    </button>
                    <h2 style={{ margin: 0, fontSize: '1.15rem' }}>
                        <span style={{ color: '#C83A2B', fontWeight: 700 }}>Ran</span>
                        <span style={{ color: '#fff' }}>ScanAI</span>
                    </h2>
                </div>
                <span style={{ color: '#aaa', fontSize: '0.9rem' }}>{monthLabel}</span>
            </div>

            {/* Report content */}
            <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '30px 24px' }}>
                <SummaryReport month={month} />
            </div>
        </div>
    );
};

export default SummaryReportPage;
