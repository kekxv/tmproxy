document.addEventListener('DOMContentLoaded', () => {
    const totpCodeElement = document.getElementById('totpCode');
    const totpContainer = document.getElementById('totp-floating-container');

    async function fetchTotp() {
        try {
            const response = await fetch('/api/admin/totp');
            if (response.ok) {
                const data = await response.json();
                totpCodeElement.textContent = data.totp;
            } else {
                const errorData = await response.json();
                totpCodeElement.textContent = `Error: ${errorData.message || response.statusText}`;
            }
        } catch (error) {
            console.error('Error fetching TOTP:', error);
            totpCodeElement.textContent = 'Error fetching TOTP.';
        }
    }

    // Fetch TOTP immediately on page load
    fetchTotp();

    // Refresh TOTP every 30 seconds
    setInterval(fetchTotp, 30000);

    // Add click to copy functionality
    if (totpContainer) {
        totpContainer.addEventListener('click', async () => {
            if (totpContainer.classList.contains('copied')) {
                return; // Prevent clicking when already in 'copied' state
            }
            const totpText = totpCodeElement.textContent;
            try {
                await navigator.clipboard.writeText(totpText);
                totpContainer.classList.add('copied');
                const originalText = totpCodeElement.textContent;
                totpCodeElement.textContent = 'Copied!';
                setTimeout(() => {
                    totpCodeElement.textContent = originalText;
                    totpContainer.classList.remove('copied');
                }, 1000);
            } catch (err) {
                console.error('Failed to copy TOTP: ', err);
            }
        });
    }

    // Existing admin dashboard logic (if any) would go here
    // For now, I'll just add placeholders for fetching clients and connections
    async function fetchClients() {
        // Implement fetching clients logic
        // const response = await fetch('/api/admin/clients');
        // const data = await response.json();
        // Update clientsTable
    }

    async function fetchConnections() {
        // Implement fetching connections logic
        // const response = await fetch('/api/admin/connections');
        // const data = await response.json();
        // Update connectionsTable
    }

    // Initial fetch for clients and connections
    fetchClients();
    fetchConnections();
    // Set intervals for clients and connections if needed
});