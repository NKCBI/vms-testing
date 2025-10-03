require('dotenv').config();
const express = require('express');
const http = require('http');
const cors = require('cors');
const { connectToDb } = require('./database');
const { initializeWebSocket } = require('./services/websocket');
const { startSync } = require('./services/turingSync');
const { loadSystemSettings } = require('./services/settings');
const apiRoutes = require('./api'); 

const PORT = process.env.PORT || 3001;
const app = express();

app.use(cors());
// app.use(express.json()); // <-- THIS LINE HAS BEEN REMOVED. The JSON parser in api/index.js will handle it.

const server = http.createServer(app);

// We need a reference to broadcastToGroup for the API routes.
let broadcastToGroup;

async function startServer() {
    await connectToDb();
    await loadSystemSettings();
    
    // Initialize the simplified websocket service and get the broadcast function.
    const services = initializeWebSocket(server);
    broadcastToGroup = services.broadcastToGroup;
    
    // Make the broadcast function available to all API routes via the request object.
    app.use((req, res, next) => {
        req.broadcastToGroup = broadcastToGroup;
        next();
    });

    // --- API Routes ---
    // This must be registered *after* the middleware that adds broadcastToGroup.
    app.use('/api', apiRoutes);

    startSync();

    server.listen(PORT, () => {
        console.log(`✅ Backend server is running on http://localhost:${PORT}`);
    });
}

startServer();
