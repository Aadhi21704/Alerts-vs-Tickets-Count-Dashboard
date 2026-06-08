let dashboardData = null;

async function loadData() {

    const response = await fetch('/api/data');
    dashboardData = await response.json();

    const data = dashboardData[0];
    const clients = data.clients || [];

    const mismatchClients =
        clients.filter(
            c => c.status !== 'Equal'
        ).length;


    document.getElementById('sentinel-count').innerText =
        data.total_sentinel_count;

    document.getElementById('jira-count').innerText =
        data.total_jira_count;

    document.getElementById('mismatch-clients').innerText =
        mismatchClients;

    const statusElement =
    document.getElementById('status');

    statusElement.innerText =
        data.clients.every(c => c.status === 'Equal')
            ? 'Equal'
            : 'Mismatch';

    if (
        data.clients.every(
            c => c.status === 'Equal'
        )
    ) {
        statusElement.style.color = '#22c55e';
    }
    else {
        statusElement.style.color = '#dc2626';
    }

    const clientCards =
        document.getElementById('client-cards');

    clientCards.innerHTML = clients.map(client => `

    <div class="client-card ${client.status === 'Equal' ? 'equal-card' : 'mismatch-card'}">

        <div class="client-header"
            onclick="toggleClient('${client.client}')">

            <span>▼ ${client.client}</span>

            <span>
                S1: ${client.sentinel_count}
                |
                Jira: ${client.jira_count}
                |
                ${client.status}
            </span>

        </div>

        <div
            id="client-${client.client}"
            class="client-details"
        >

            <h4>SentinelOne Alerts</h4>

            <ul>
                ${client.sentinel_alerts
                    .map(alert => `
                        <li>${alert.id}</li>
                    `)
                    .join('')}
            </ul>

            <h4>Jira Tickets</h4>

            <ul>
                ${client.jira_tickets
                    .map(ticket => `
                        <li>
                            <a
                                href="https://nopalcyber.atlassian.net/browse/${ticket.key}"
                                target="_blank"
                                class="jira-link"
                            >
                                ${ticket.key}
                            </a>
                        </li>
                    `)
                    .join('')}
            </ul>

        </div>

    </div>

    `).join('');
}


loadData();

setInterval(loadData, 30000);



function toggleClient(clientName) {

    const element =
        document.getElementById(
            `client-${clientName}`
        );

    if (
        element.style.display === 'none'
        ||
        element.style.display === ''
    ) {
        element.style.display = 'block';
    }
    else {
        element.style.display = 'none';
    }
}