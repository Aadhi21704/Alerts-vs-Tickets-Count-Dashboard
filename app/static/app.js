let dashboardData = null;

async function loadData() {

    const response = await fetch('/api/data');
    dashboardData = await response.json();

    const data = dashboardData[0];
    const clients = data.clients || [];

    document.getElementById('sentinel-count').innerText =
        data.total_sentinel_count;

    document.getElementById('jira-count').innerText =
        data.total_jira_count;

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

    document.getElementById('timestamp').innerText =
        data.timestamp;

    document.getElementById('table-sentinel').innerText =
        data.total_sentinel_count;

    document.getElementById('table-jira').innerText =
        data.total_jira_count;

    document.getElementById('table-status').innerText =
        data.clients.every(c => c.status === 'Equal')
            ? 'Equal'
            : 'Mismatch';


    const clientsBody =
    document.getElementById('clients-body');

    clientsBody.innerHTML = clients.map(client => `

    <tr class="client-row"
        onclick="showClientDetails('${client.client}')">

        <td>${client.client}</td>

        <td>${client.sentinel_count}</td>

        <td>${client.jira_count}</td>

        <td>${client.status}</td>

    </tr>

    `).join('');
}

loadData();

setInterval(loadData, 30000);

const modal = document.getElementById('modal');

document.getElementById('close-modal').onclick = () => {
    modal.style.display = 'none';
};

// document.getElementById('sentinel-count').onclick = () => {

//     const data = dashboardData[0];

//     document.getElementById('modal-title').innerText =
//         'SentinelOne Alerts';

//     document.getElementById('modal-body').innerHTML = `

//         <table class="detail-table">

//             <thead>
//                 <tr>
//                     <th>Alert ID</th>
//                 </tr>
//             </thead>

//             <tbody>

//                 ${data.sentinel_alerts.map(alert => `

//                     <tr>
//                         <td>${alert.id}</td>
//                     </tr>

//                 `).join('')}

//             </tbody>

//         </table>

//     `;

//     modal.style.display = 'block';
// };

// document.getElementById('jira-count').onclick = () => {

//     const data = dashboardData[0];

//     document.getElementById('modal-title').innerText =
//         'Jira Tickets';

//     document.getElementById('modal-body').innerHTML = `

//         <table class="detail-table">

//             <thead>
//                 <tr>
//                     <th>Key</th>
//                     <th>Summary</th>
//                     <th>Created</th>
//                 </tr>
//             </thead>

//             <tbody>

//                 ${data.jira_tickets.map(ticket => `

//                     <tr>

//                         <td>
//                             <a
//                                 href="https://nopalcyber.atlassian.net/browse/${ticket.key}"
//                                 target="_blank"
//                                 class="jira-link"
//                             >
//                                 ${ticket.key}
//                             </a>
//                         </td>

//                         <td>${ticket.summary}</td>

//                         <td>${ticket.created}</td>

//                     </tr>

//                 `).join('')}

//             </tbody>

//         </table>

//     `;

//     modal.style.display = 'block';
// };

function showClientDetails(clientName) {

    const client =
        dashboardData[0].clients.find(
            c => c.client === clientName
        );

    if (!client) return;

    document.getElementById('modal-title').innerText =
        clientName;

    document.getElementById('modal-body').innerHTML = `

        <h3>SentinelOne Alerts</h3>

        <ul>
            ${client.sentinel_alerts
                .map(a => `<li>${a.id}</li>`)
                .join('')}
        </ul>

        <h3>Jira Tickets</h3>

        <ul>
            ${client.jira_tickets
                .map(t => `
                    <li>
                        <a
                            href="https://nopalcyber.atlassian.net/browse/${t.key}"
                            target="_blank"
                            class="jira-link"
                        >
                            ${t.key}
                        </a>
                    </li>
                `)
                .join('')}
        </ul>
    `;

    modal.style.display = 'block';
}