const WebSocket = require('ws');
const url = require('url');
const jwt = require('jsonwebtoken');

let alertWss;

function initializeWebSocket(server) {
    alertWss = new WebSocket.Server({ noServer: true });

    // --- Real-time Alert Logic ---
    alertWss.on('connection', (ws, req, user) => {
        ws.dispatchGroupId = user.dispatchGroupId ? user.dispatchGroupId.toString() : 'general';
        console.log(`[Alerts] Client connected to group: ${ws.dispatchGroupId}`);
        ws.on('close', () => console.log('[Alerts] Client disconnected.'));
    });

    // --- WebSocket Authentication Handler ---
    // This now only handles authentication for the alert service.
    server.on('upgrade', (request, socket, head) => {
        const parameters = new URLSearchParams(url.parse(request.url).search);
        const token = parameters.get('token');

        // The video stream connection is an unauthenticated API call, 
        // so we can ignore any request that doesn't have a token.
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
            
            // If the token is valid, complete the WebSocket upgrade for the alerts server.
            alertWss.handleUpgrade(request, socket, head, (ws) => {
                alertWss.emit('connection', ws, request, user);
            });
        });
    });

    console.log("✅ WebSocket service initialized for Alerts.");
    
    // Return the broadcast function so server.js can use it.
    return { broadcastToGroup };
}

function broadcastToGroup(dispatchGroupId, data) {
    if (!alertWss) {
        console.warn("[Alerts] Cannot broadcast: WebSocket server not initialized.");
        return;
    }
    const groupId = dispatchGroupId ? dispatchGroupId.toString() : 'general';
    const message = JSON.stringify(data);
    alertWss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN && client.dispatchGroupId === groupId) {
            client.send(message);
        }
    });
}

module.exports = {
    initializeWebSocket,
    broadcastToGroup,
};

