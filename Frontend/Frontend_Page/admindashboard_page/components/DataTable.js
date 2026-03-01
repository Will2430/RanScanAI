import React, { useState } from 'react';

const ROWS_PER_PAGE = 10;

const DataTable = ({ data }) => {
    const [currentPage, setCurrentPage] = useState(1);

    const getSeverityColor = (severity) => {
        switch(severity) {
            case 'CRITICAL': return 'critical';
            case 'HIGH': return 'high';
            case 'MEDIUM': return 'medium';
            default: return 'low';
        }
    };

    if (!data || data.length === 0) {
        return (
            <div className="table-wrapper" style={{ textAlign: 'center', padding: '40px', color: '#888' }}>
                No detection records found.
            </div>
        );
    }

    const totalPages = Math.ceil(data.length / ROWS_PER_PAGE);
    const startIdx = (currentPage - 1) * ROWS_PER_PAGE;
    const pageData = data.slice(startIdx, startIdx + ROWS_PER_PAGE);

    const goToPage = (page) => {
        if (page >= 1 && page <= totalPages) setCurrentPage(page);
    };

    // Generate visible page numbers (max 5 around current)
    const getPageNumbers = () => {
        const pages = [];
        let start = Math.max(1, currentPage - 2);
        let end = Math.min(totalPages, start + 4);
        if (end - start < 4) start = Math.max(1, end - 4);
        for (let i = start; i <= end; i++) pages.push(i);
        return pages;
    };

    return (
        <div>
            <div className="table-wrapper">
                <table className="data-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>File Name</th>
                            <th>Username</th>
                            <th>Role</th>
                            <th>Severity</th>
                            <th>Prediction</th>
                            <th>Confidence</th>
                            <th>Date &amp; Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        {pageData.map((row, index) => (
                            <tr key={index}>
                                <td>{row.id}</td>
                                <td title={row.file_name}>{row.file_name}</td>
                                <td title={row.username}>{row.username}</td>
                                <td><span className={`severity-badge ${row.role === 'admin' ? 'high' : 'low'}`}>{row.role}</span></td>
                                <td><span className={`severity-badge ${getSeverityColor(row.severity)}`}>{row.severity}</span></td>
                                <td><span className={`status-badge ${row.prediction === 'MALWARE' ? 'status-malware' : 'status-benign'}`}>{row.prediction}</span></td>
                                <td>{row.confidence}</td>
                                <td title={row.date}>{row.date}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
                <div style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '16px 0 4px', fontSize: '0.9rem', color: '#555'
                }}>
                    <span>Showing {startIdx + 1}–{Math.min(startIdx + ROWS_PER_PAGE, data.length)} of {data.length} records</span>
                    <div style={{ display: 'flex', gap: '4px' }}>
                        <button onClick={() => goToPage(1)} disabled={currentPage === 1}
                            className="page-btn" title="First page">«</button>
                        <button onClick={() => goToPage(currentPage - 1)} disabled={currentPage === 1}
                            className="page-btn" title="Previous page">‹</button>
                        {getPageNumbers().map(p => (
                            <button key={p} onClick={() => goToPage(p)}
                                className={`page-btn ${p === currentPage ? 'page-btn-active' : ''}`}>{p}</button>
                        ))}
                        <button onClick={() => goToPage(currentPage + 1)} disabled={currentPage === totalPages}
                            className="page-btn" title="Next page">›</button>
                        <button onClick={() => goToPage(totalPages)} disabled={currentPage === totalPages}
                            className="page-btn" title="Last page">»</button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default DataTable;