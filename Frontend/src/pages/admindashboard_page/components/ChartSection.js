import React, { useMemo } from 'react';

const MONTHS_SHORT = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

const ChartSection = ({ detections = [] }) => {
    // Build monthly breakdown from real detection data
    const { monthlyData, verdictBreakdown } = useMemo(() => {
        const monthly = new Array(12).fill(0);
        let malicious = 0;
        let suspicious = 0;
        let benign = 0;
        const currentYear = new Date().getFullYear();

        detections.forEach(d => {
            if (!d.timestamp) return;
            const dt = new Date(d.timestamp);
            if (dt.getFullYear() === currentYear) {
                monthly[dt.getMonth()]++;
            }
            if (d.is_malicious) {
                if (d.confidence >= 0.8) malicious++;
                else suspicious++;
            } else {
                benign++;
            }
        });

        return {
            monthlyData: monthly,
            verdictBreakdown: { malicious, suspicious, benign }
        };
    }, [detections]);

    const maxMonthly = Math.max(...monthlyData, 1);
    const total = verdictBreakdown.malicious + verdictBreakdown.suspicious + verdictBreakdown.benign;

    // Build conic gradient for pie chart
    const pieGradient = useMemo(() => {
        if (total === 0) return '#e0e0e0';
        const malDeg = (verdictBreakdown.malicious / total) * 360;
        const susDeg = malDeg + (verdictBreakdown.suspicious / total) * 360;
        return `conic-gradient(#DC2626 0deg ${malDeg}deg, #F97316 ${malDeg}deg ${susDeg}deg, #16A34A ${susDeg}deg 360deg)`;
    }, [verdictBreakdown, total]);

    return (
        <div className="chart-grid">
            {/* Bar chart — Detections per month */}
            <div className="chart-box">
                <h3>Detections Over Time ({new Date().getFullYear()})</h3>
                <div className="chart-placeholder" style={{ alignItems: 'flex-end', gap: '6px', padding: '20px 16px 10px' }}>
                    {monthlyData.map((val, i) => (
                        <div key={i} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flex: 1 }}>
                            <span style={{ fontSize: '0.7rem', color: '#666', marginBottom: '4px' }}>{val || ''}</span>
                            <div style={{
                                width: '100%',
                                maxWidth: '28px',
                                height: `${Math.max(4, (val / maxMonthly) * 200)}px`,
                                background: val > 0 ? '#3B51C4' : '#e0e0e0',
                                borderRadius: '4px 4px 0 0',
                                transition: 'height 0.5s ease',
                            }} />
                            <span style={{ fontSize: '0.65rem', color: '#888', marginTop: '4px' }}>{MONTHS_SHORT[i]}</span>
                        </div>
                    ))}
                </div>
            </div>

            {/* Pie chart — Verdict Distribution */}
            <div className="chart-box">
                <h3>Verdict Distribution</h3>
                <div className="chart-placeholder pie-chart" style={{ flexDirection: 'column', gap: '16px' }}>
                    {total > 0 ? (
                        <>
                            <div className="pie" style={{ background: pieGradient, width: '140px', height: '140px', borderRadius: '50%' }} />
                            <div style={{ display: 'flex', gap: '16px', fontSize: '0.82rem', color: '#111' }}>
                                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#111' }}>
                                    <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#DC2626', display: 'inline-block' }} />
                                    Malware ({verdictBreakdown.malicious})
                                </span>
                                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#111' }}>
                                    <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#F97316', display: 'inline-block' }} />
                                    Suspicious ({verdictBreakdown.suspicious})
                                </span>
                                <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#111' }}>
                                    <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#16A34A', display: 'inline-block' }} />
                                    Benign ({verdictBreakdown.benign})
                                </span>
                            </div>
                        </>
                    ) : (
                        <span style={{ color: '#888' }}>No scan data available</span>
                    )}
                </div>
            </div>
        </div>
    );
};

export default ChartSection;