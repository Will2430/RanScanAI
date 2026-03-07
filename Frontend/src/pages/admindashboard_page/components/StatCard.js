import React, { useState, useEffect, useRef } from 'react';

function parseNumeric(val) {
    if (!val || val === '—') return null;
    const n = parseInt(String(val).replace(/,/g, ''), 10);
    return isNaN(n) ? null : n;
}

const StatCard = ({ title, value, trend, color }) => {
    const [displayed, setDisplayed] = useState(value);
    const rafRef = useRef(null);
    const prevNumRef = useRef(parseNumeric(value));

    useEffect(() => {
        const target = parseNumeric(value);

        // Non-numeric value (e.g. '—') — just set directly
        if (target === null) {
            setDisplayed(value);
            prevNumRef.current = null;
            return;
        }

        const from = prevNumRef.current ?? 0;
        prevNumRef.current = target;

        if (rafRef.current) cancelAnimationFrame(rafRef.current);

        const duration = 800;
        const startTime = performance.now();

        function step(now) {
            const elapsed = now - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const ease = 1 - Math.pow(1 - progress, 3);
            const current = Math.round(from + (target - from) * ease);
            setDisplayed(current.toLocaleString());
            if (progress < 1) {
                rafRef.current = requestAnimationFrame(step);
            }
        }

        rafRef.current = requestAnimationFrame(step);
        return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); };
    }, [value]);

    return (
        <div className={`stat-card stat-${color}`}>
            <h3>{title}</h3>
            <div className="stat-value">{displayed}</div>
            <div className="stat-trend">
                <span className="trend-icon">↑</span>
                <span className="trend-text">{trend} from last period</span>
            </div>
        </div>
    );
};

export default StatCard;