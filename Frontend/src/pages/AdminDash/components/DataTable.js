import React from 'react';

const DataTable = ({ data }) => {
    const getSeverityColor = (severity) => {
        switch(severity) {
            case 'CRITICAL': return 'critical';
            case 'HIGH': return 'high';
            case 'MEDIUM': return 'medium';
            default: return 'low';
        }
    };

    return (
        <div className="table-wrapper">
            <table className="data-table">
                <thead>
                    <tr>
                        <th>Threat ID</th>
                        <th>Threat Name</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Detection Date</th>
                        <th>Devices Affected</th>
                    </tr>
                </thead>
                <tbody>
                    {data.map((row, index) => (
                        <tr key={index}>
                            <td>{row.id}</td>
                            <td>{row.threat}</td>
                            <td><span className={`severity-badge ${getSeverityColor(row.severity)}`}>{row.severity}</span></td>
                            <td><span className="status-badge">{row.status}</span></td>
                            <td>{row.date}</td>
                            <td>{row.devices}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default DataTable;