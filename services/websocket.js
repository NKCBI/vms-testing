const WebSocket = require('ws');
const url = require('url');
const jwt = require('jsonwebtoken');

let alertWss;

function initializeWebSocket(server) {
    alertWss = new WebSocket.Server({ noServer: true });

    alertWss.on('connection', (ws, req, user) => {
        ws.dispatchGroupId = user.dispatchGroupId ? user.dispatchGroupId.toString() : 'general';
        console.log(`[Alerts] Client connected to group: ${ws.dispatchGroupId}`);
        ws.on('close', () => console.log('[Alerts] Client disconnected.'));
    });

    server.on('upgrade', (request, socket, head) => {
        const origin = request.headers.origin;
        console.log(`[WebSocket Upgrade] Received upgrade request from Origin: ${origin}`);

        const parameters = new URLSearchParams(url.parse(request.url).search);
        const token = parameters.get('token');

        if (!token) {
            socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
            socket.destroy();
            return;
        }

        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                console.error("[Alerts] Upgrade Rejected: Invalid Token.", err.message);
                socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
                socket.destroy();
                return;
            }
            
            alertWss.handleUpgrade(request, socket, head, (ws) => {
                alertWss.emit('connection', ws, request, user);
            });
        });
    });

    console.log("✅ WebSocket service initialized for Alerts.");
    
    return { broadcastToGroup };
}

function broadcastToGroup(dispatchGroupId, data) {
    if (!alertWss) {
        console.warn("[Alerts] Cannot broadcast: WebSocket server not initialized.");
        return;
    }
    const groupId = dispatchGroupId ? dispatchGroupId.toString() : 'general';
    const message = JSON.stringify(data);

    // --- LOGGING ADDED ---
    console.log(`[BROADCAST] Starting broadcast for group: ${groupId}. Total connected clients: ${alertWss.clients.size}`);
    
    let clientsFoundForGroup = 0;
    alertWss.clients.forEach((client, index) => {
        const clientIdentifier = `Client #${index + 1}`;
        if (client.readyState === WebSocket.OPEN) {
            if (client.dispatchGroupId === groupId) {
                console.log(`[BROADCAST]   - ${clientIdentifier} (Group: ${client.dispatchGroupId}): MATCH FOUND. SENDING message.`);
                client.send(message);
                clientsFoundForGroup++;
            } else {
                console.log(`[BROADCAST]   - ${clientIdentifier} (Group: ${client.dispatchGroupId}): SKIPPING (group mismatch).`);
            }
        } else {
            console.log(`[BROADCAST]   - ${clientIdentifier}: SKIPPING (connection not open).`);
        }
    });

    console.log(`[BROADCAST] Broadcast complete. Sent message to ${clientsFoundForGroup} client(s).`);
}

module.exports = {
    initializeWebSocket,
    broadcastToGroup,
};