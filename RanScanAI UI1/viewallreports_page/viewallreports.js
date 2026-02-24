// view all reports page

const api = {
    getReports: () => Promise.resolve({ count: 10 })
};

const reportMonths = [
    { year: 2026, month: 'February' },
    { year: 2026, month: 'January' },
    { year: 2025, month: 'December' },
    { year: 2025, month: 'November' },
    { year: 2025, month: 'October' },
    { year: 2025, month: 'September' },
    { year: 2025, month: 'August' },
    { year: 2025, month: 'July' },
    { year: 2025, month: 'June' },
    { year: 2025, month: 'May' }
];

function formatReportName(entry) {
    return `${entry.year} ${entry.month} Detailed Report`;
}

function reportId(index) {
    const value = String(index).padStart(2, '0');
    return `R${value}`;
}

async function populateReports() {
    const { count } = await api.getReports();
    const tbody = document.getElementById('reports-tbody');
    tbody.innerHTML = '';

    for (let i = 0; i < count; i += 1) {
        const rowIndex = count - i;
        const report = reportMonths[i % reportMonths.length];
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${reportId(rowIndex)}</td>
            <td>
                <span class="report-cell">
                    <span>${formatReportName(report)}</span>
                    <span class="report-icons">
                        <span class="eye-icon" title="View">&#128065;</span>
                        <span class="download-icon" title="Download">&#128190;</span>
                    </span>
                </span>
            </td>
        `;
        tbody.appendChild(tr);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    populateReports();
});
