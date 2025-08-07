document.addEventListener('DOMContentLoaded', () => {
    const clientsTableBody = document.getElementById('clientsTable').querySelector('tbody');
    const connectionsTableBody = document.getElementById('connectionsTable').querySelector('tbody');
    const addForwardForm = document.getElementById('addForwardForm');
    const addClientIdSelect = document.getElementById('addClientId');

    async function fetchData() {
        try {
            const clientsResponse = await fetch('/api/admin/clients');
            const clients = await clientsResponse.json();
            renderClients(clients);
            populateClientIdSelect(clients);

            const connectionsResponse = await fetch('/api/admin/connections');
            const connections = await connectionsResponse.json();
            renderConnections(connections);
        } catch (error) {
            console.error('Error fetching data:', error);
        }
    }

    function populateClientIdSelect(clients) {
        addClientIdSelect.innerHTML = '<option value="">Select Client ID</option>'; // Clear existing options
        clients.forEach(client => {
            const option = document.createElement('option');
            option.value = client.id;
            option.textContent = `${client.id} (${client.remote_addr})`;
            addClientIdSelect.appendChild(option);
        });
    }

    function renderClients(clients) {
        clientsTableBody.innerHTML = '';
        clients.forEach(client => {
            const row = clientsTableBody.insertRow();
            row.insertCell().textContent = client.id;
            row.insertCell().textContent = client.remote_addr;
            row.insertCell().textContent = new Date(client.connected_at).toLocaleString();

            const forwardsCell = row.insertCell();
            if (client.forwards) {
                for (const remotePort in client.forwards) {
                    const localAddr = client.forwards[remotePort];
                    const forwardText = `${remotePort} -> ${localAddr}`;
                    const forwardDiv = document.createElement('div');
                    forwardDiv.textContent = forwardText;

                    const deleteButton = document.createElement('button');
                    deleteButton.textContent = 'Del';
                    deleteButton.className = 'delete-button';
                    deleteButton.onclick = () => deleteForward(client.id, remotePort);
                    forwardDiv.appendChild(deleteButton);

                    forwardsCell.appendChild(forwardDiv);
                }
            }

            const actionsCell = row.insertCell();
            const disconnectButton = document.createElement('button');
            disconnectButton.textContent = 'Disconnect';
            disconnectButton.className = 'delete-button'; // Reusing style
            disconnectButton.onclick = () => disconnectClient(client.id);
            actionsCell.appendChild(disconnectButton);
        });
    }

    function renderConnections(connections) {
        connectionsTableBody.innerHTML = '';
        connections.forEach(conn => {
            const row = connectionsTableBody.insertRow();
            row.insertCell().textContent = conn.id;
            row.insertCell().textContent = conn.tunnel_id;
            row.insertCell().textContent = conn.client_id;
            row.insertCell().textContent = conn.client_addr;
            row.insertCell().textContent = conn.server_addr;
            row.insertCell().textContent = new Date(conn.connected_at).toLocaleString();
        });
    }

    addForwardForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const clientId = addClientIdSelect.value;
        const remotePort = parseInt(document.getElementById('addRemotePort').value);
        const localAddr = document.getElementById('addLocalAddr').value;

        try {
            const response = await fetch('/api/admin/forwards', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ client_id: clientId, remote_port: remotePort, local_addr: localAddr }),
            });
            const result = await response.json();
            if (result.success) {
                alert('Forward added successfully!');
                addForwardForm.reset();
                fetchData(); // Refresh data
            } else {
                alert(`Failed to add forward: ${result.message}`);
            }
        } catch (error) {
            console.error('Error adding forward:', error);
            alert('Error adding forward.');
        }
    });

    async function disconnectClient(clientId) {
        if (!confirm(`Are you sure you want to disconnect client ${clientId}?`)) {
            return;
        }
        try {
            const response = await fetch('/api/admin/disconnect', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ client_id: clientId }),
            });
            const result = await response.json();
            if (result.success) {
                alert('Client disconnected successfully!');
                fetchData(); // Refresh data
            } else {
                alert(`Failed to disconnect client: ${result.message}`);
            }
        } catch (error) {
            console.error('Error disconnecting client:', error);
            alert('Error disconnecting client.');
        }
    }

    async function deleteForward(clientId, remotePort) {
        if (!confirm(`Are you sure you want to delete forward for client ${clientId} on remote port ${remotePort}?`)) {
            return;
        }
        try {
            const response = await fetch('/api/admin/delete_forward', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ client_id: clientId, remote_port: parseInt(remotePort) }),
            });
            const result = await response.json();
            if (result.success) {
                alert('Forward deleted successfully!');
                fetchData(); // Refresh data
            } else {
                alert(`Failed to delete forward: ${result.message}`);
            }
        } catch (error) {
            console.error('Error deleting forward:', error);
            alert('Error deleting forward.');
        }
    }

    // Initial fetch and set interval for refreshing data
    fetchData();
    setInterval(fetchData, 5000); // Refresh every 5 seconds
});