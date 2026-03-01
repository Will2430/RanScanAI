import React from 'react';

const StatCard = ({ title, value, trend, color }) => {
    return (
        <div className={`stat-card stat-${color}`}>
            <h3>{title}</h3>
            <div className="stat-value">{value}</div>
            <div className="stat-trend">
                <span className="trend-icon">↑</span>
                <span className="trend-text">{trend} from last period</span>
            </div>
        </div>
    );
};

export default StatCard;