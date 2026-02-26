import React from 'react';

const ChartSection = () => {
    return (
        <div className="chart-grid">
            <div className="chart-box">
                <h3>Threats Over Time</h3>
                <div className="chart-placeholder">
                    <svg viewBox="0 0 400 200" className="line-chart">
                        <polyline points="10,180 50,150 90,160 130,100 170,120 210,80 250,110 290,90 330,140 370,100" />
                    </svg>
                </div>
            </div>
            <div className="chart-box">
                <h3>Threat Distribution</h3>
                <div className="chart-placeholder pie-chart">
                    <div className="pie" style={{background: 'conic-gradient(#FF6B35 0deg 108deg, #004E89 108deg 180deg, #F77F00 180deg 270deg, #FCBF49 270deg)'}}></div>
                </div>
            </div>
        </div>
    );
};

export default ChartSection;