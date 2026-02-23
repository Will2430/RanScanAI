// view all detections page

const api = {
    getDetectionsCount: () => Promise.resolve({ count: 14 })
};

const detectionNames = [
    'ransomransom.exe',
    'encryptor.dll',
    'shadowcopy.bat',
    'lockscreen.bin',
    'payload.ps1',
    'dropper.tmp',
    'vaultkey.dat'
];

function padId(value) {
    return `D${String(value).padStart(3, '0')}`;
}

function formatDateTime(date) {
    const months = [
        'January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December'
    ];
    const day = String(date.getDate()).padStart(2, '0');
    const month = months[date.getMonth()];
    const year = String(date.getFullYear());
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');

    return `${day} ${month} ${year} ${hours}:${minutes}:${seconds}`;
}

function randomDateTime() {
    const now = new Date();
    const past = new Date();
    past.setDate(now.getDate() - Math.floor(Math.random() * 30));
    past.setHours(Math.floor(Math.random() * 24));
    past.setMinutes(Math.floor(Math.random() * 60));
    past.setSeconds(Math.floor(Math.random() * 60));

    return {
        date: past,
        display: formatDateTime(past)
    };
}

function buildDetectionRows(count) {
    const rows = [];
    for (let i = 1; i <= count; i += 1) {
        const detection = detectionNames[Math.floor(Math.random() * detectionNames.length)];
        const dateInfo = randomDateTime();
        rows.push({
            id: padId(i),
            detection,
            date: dateInfo.date,
            display: dateInfo.display
        });
    }
    return rows;
}

function renderDetectionRows(rows) {
    const tbody = document.getElementById('detections-tbody');
    tbody.innerHTML = '';
    rows.forEach(row => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${row.id}</td>
            <td>${row.detection}</td>
            <td>${row.display}</td>
        `;
        tbody.appendChild(tr);
    });
}

async function populateDetections() {
    const detections = await api.getDetectionsCount();
    const countEl = document.getElementById('detections-count');
    countEl.innerHTML =
        `<span class="detections-count">${detections.count}</span>` +
        `<span class="detections-sub">New Detections</span>`;

    const allRows = buildDetectionRows(detections.count);
    renderDetectionRows(allRows);
}

document.addEventListener('DOMContentLoaded', () => {
    populateDetections();
});
