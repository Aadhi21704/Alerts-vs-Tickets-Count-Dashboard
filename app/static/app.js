let dashboardData = null;

async function loadData() {

    const response = await fetch('/api/data');
    dashboardData = await response.json();

    const data = dashboardData[0];

    document.getElementById('sentinel-count').innerText =
        data.sentinel_count;

    document.getElementById('jira-count').innerText =
        data.jira_count;

    const statusElement =
    document.getElementById('status');

    statusElement.innerText = data.status;

    if (data.status === 'Equal') {
        statusElement.style.color = '#22c55e';
    }
    else {
        statusElement.style.color = '#dc2626';
    }

    document.getElementById('timestamp').innerText =
        data.timestamp;

    document.getElementById('table-sentinel').innerText =
        data.sentinel_count;

    document.getElementById('table-jira').innerText =
        data.jira_count;

    document.getElementById('table-status').innerText =
        data.status;
}

loadData();

setInterval(loadData, 30000);

const modal = document.getElementById('modal');

document.getElementById('close-modal').onclick = () => {
    modal.style.display = 'none';
};

document.getElementById('sentinel-count').onclick = () => {

    const data = dashboardData[0];

    document.getElementById('modal-title').innerText =
        'SentinelOne Alerts';

    document.getElementById('modal-body').innerHTML = `

        <table class="detail-table">

            <thead>
                <tr>
                    <th>Alert ID</th>
                </tr>
            </thead>

            <tbody>

                ${data.sentinel_alerts.map(alert => `

                    <tr>
                        <td>${alert.id}</td>
                    </tr>

                `).join('')}

            </tbody>

        </table>

    `;

    modal.style.display = 'block';
};

document.getElementById('jira-count').onclick = () => {

    const data = dashboardData[0];

    document.getElementById('modal-title').innerText =
        'Jira Tickets';

    document.getElementById('modal-body').innerHTML = `

        <table class="detail-table">

            <thead>
                <tr>
                    <th>Key</th>
                    <th>Summary</th>
                    <th>Created</th>
                </tr>
            </thead>

            <tbody>

                ${data.jira_tickets.map(ticket => `

                    <tr>

                        <td>
                            <a
                                href="https://nopalcyber.atlassian.net/browse/${ticket.key}"
                                target="_blank"
                                class="jira-link"
                            >
                                ${ticket.key}
                            </a>
                        </td>

                        <td>${ticket.summary}</td>

                        <td>${ticket.created}</td>

                    </tr>

                `).join('')}

            </tbody>

        </table>

    `;

    modal.style.display = 'block';
};