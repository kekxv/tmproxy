document.addEventListener('DOMContentLoaded', () => {
    const clientsTableBody = document.getElementById('clientsTable').querySelector('tbody');
    const connectionsTableBody = document.getElementById('connectionsTable').querySelector('tbody');

    // Custom Modal Elements
    const customModal = document.getElementById('customModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalMessage = document.getElementById('modalMessage');
    const modalInput = document.getElementById('modalInput');
    const modalRemotePortInput = document.getElementById('modalRemotePortInput');
    const modalLocalAddrInput = document.getElementById('modalLocalAddrInput');
    const modalConfirmBtn = document.getElementById('modalConfirmBtn');
    const modalCancelBtn = document.getElementById('modalCancelBtn');
    const modalAlertBtn = document.getElementById('modalAlertBtn');
    const closeButton = document.querySelector('.close-button');

    let resolveModalPromise;

    function showModal(title, message, type, defaultValue = '') {
        return new Promise(resolve => {
            modalTitle.textContent = title;
            modalMessage.textContent = message;
            modalInput.value = defaultValue;

            // Hide all specific input/button types initially
            modalConfirmBtn.style.display = 'none';
            modalCancelBtn.style.display = 'none';
            modalAlertBtn.style.display = 'none';
            modalInput.style.display = 'none';
            modalRemotePortInput.style.display = 'none';
            modalLocalAddrInput.style.display = 'none';

            if (type === 'alert') {
                modalAlertBtn.style.display = 'inline-block';
            } else if (type === 'confirm') {
                modalConfirmBtn.style.display = 'inline-block';
                modalCancelBtn.style.display = 'inline-block';
            } else if (type === 'prompt') {
                modalInput.style.display = 'block';
                modalConfirmBtn.style.display = 'inline-block';
                modalCancelBtn.style.display = 'inline-block';
            } else if (type === 'addForwardPrompt') {
                modalRemotePortInput.value = ''; // Clear previous values
                modalLocalAddrInput.value = '';
                modalRemotePortInput.style.display = 'block';
                modalLocalAddrInput.style.display = 'block';
                modalConfirmBtn.style.display = 'inline-block';
                modalCancelBtn.style.display = 'inline-block';
            }

            customModal.style.display = 'block';
            resolveModalPromise = resolve;
        });
    }

    closeButton.onclick = () => {
        customModal.style.display = 'none';
        resolveModalPromise(null); // Resolve with null if closed without action
    };

    window.onclick = (event) => {
        if (event.target === customModal) {
            customModal.style.display = 'none';
            resolveModalPromise(null); // Resolve with null if clicked outside
        }
    };

    modalAlertBtn.onclick = () => {
        customModal.style.display = 'none';
        resolveModalPromise(true);
    };

    modalConfirmBtn.onclick = () => {
        customModal.style.display = 'none';
        if (modalInput.style.display === 'block') {
            resolveModalPromise(modalInput.value);
        } else if (modalRemotePortInput.style.display === 'block') {
            resolveModalPromise({
                remotePort: parseInt(modalRemotePortInput.value),
                localAddr: modalLocalAddrInput.value
            });
        } else {
            resolveModalPromise(true);
        }
    };

    modalCancelBtn.onclick = () => {
        customModal.style.display = 'none';
        resolveModalPromise(false);
    };

    async function fetchData() {
        try {
            const clientsResponse = await fetch('/api/admin/clients');
            const clients = await clientsResponse.json();
            renderClients(clients);

            const connectionsResponse = await fetch('/api/admin/connections');
            const connections = await connectionsResponse.json();
            renderConnections(connections);
        } catch (error) {
            console.error('Error fetching data:', error);
            await showModal('Error', 'Error fetching data: ' + error.message, 'alert');
        }
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
                    deleteButton.onclick = async () => {
                        const confirmed = await showModal('Confirm Delete', `Are you sure you want to delete forward for client ${client.id} on remote port ${remotePort}?`, 'confirm');
                        if (confirmed) {
                            deleteForward(client.id, remotePort);
                        }
                    };
                    forwardDiv.appendChild(deleteButton);

                    forwardsCell.appendChild(forwardDiv);
                }
            }

            const actionsCell = row.insertCell();

            // Add Forward button
            const addForwardButton = document.createElement('button');
            addForwardButton.textContent = 'Add Forward';
            addForwardButton.className = 'add-forward-button';
            addForwardButton.onclick = async () => {
                const result = await showModal('Add New Forward', 'Please enter the remote port and local address:', 'addForwardPrompt');
                if (result) {
                    const { remotePort, localAddr } = result;
                    if (isNaN(remotePort) || remotePort <= 0 || !localAddr) {
                        await showModal('Input Error', 'Please enter a valid remote port and local address.', 'alert');
                        return;
                    }
                    addForward(client.id, remotePort, localAddr);
                }
            };
            actionsCell.appendChild(addForwardButton);

            const disconnectButton = document.createElement('button');
            disconnectButton.textContent = 'Disconnect';
            disconnectButton.className = 'delete-button';
            disconnectButton.onclick = async () => {
                const confirmed = await showModal('Confirm Disconnect', `Are you sure you want to disconnect client ${client.id}?`, 'confirm');
                if (confirmed) {
                    disconnectClient(client.id);
                }
            };
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

            const actionsCell = row.insertCell();
            const disconnectButton = document.createElement('button');
            disconnectButton.textContent = 'Disconnect';
            disconnectButton.className = 'delete-button';
            disconnectButton.onclick = async () => {
                const confirmed = await showModal('Confirm Disconnect', `Are you sure you want to disconnect TCP connection ${conn.id} (Tunnel ID: ${conn.tunnel_id})?`, 'confirm');
                if (confirmed) {
                    disconnectConnection(conn.tunnel_id);
                }
            };
            actionsCell.appendChild(disconnectButton);
        });
    }

    async function disconnectConnection(tunnelId) {
        try {
            const response = await fetch('/api/admin/disconnect', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ connection_id: tunnelId }),
            });
            const result = await response.json();
            if (result.success) {
                await showModal('Success', 'TCP connection disconnected successfully!', 'alert');
                fetchData(); // Refresh data
            } else {
                await showModal('Error', `Failed to disconnect TCP connection: ${result.message}`, 'alert');
            }
        } catch (error) {
            console.error('Error disconnecting TCP connection:', error);
            await showModal('Error', 'Error disconnecting TCP connection.', 'alert');
        }
    }

    async function addForward(clientId, remotePort, localAddr) {
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
                await showModal('Success', 'Forward added successfully!', 'alert');
                fetchData(); // Refresh data
            } else {
                await showModal('Error', `Failed to add forward: ${result.message}`, 'alert');
            }
        } catch (error) {
            console.error('Error adding forward:', error);
            await showModal('Error', 'Error adding forward.', 'alert');
        }
    }

    async function disconnectClient(clientId) {
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
                await showModal('Success', 'Client disconnected successfully!', 'alert');
                fetchData(); // Refresh data
            } else {
                await showModal('Error', `Failed to disconnect client: ${result.message}`, 'alert');
            }
        } catch (error) {
            console.error('Error disconnecting client:', error);
            await showModal('Error', 'Error disconnecting client.', 'alert');
        }
    }

    async function deleteForward(clientId, remotePort) {
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
                await showModal('Success', 'Forward deleted successfully!', 'alert');
                fetchData(); // Refresh data
            } else {
                await showModal('Error', `Failed to delete forward: ${result.message}`, 'alert');
            }
        } catch (error) {
            console.error('Error deleting forward:', error);
            await showModal('Error', 'Error deleting forward.', 'alert');
        }
    }

    // Initial fetch and set interval for refreshing data
    fetchData();
    setInterval(fetchData, 5000); // Refresh every 5 seconds
});