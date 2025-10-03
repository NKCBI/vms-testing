const express = require('express');
const router = express.Router();

// Middleware to capture the raw body of the request, regardless of content type.
router.use(express.raw({ type: '*/*', limit: '10mb' }));

// A single, universal endpoint to catch ALL requests (GET, POST, etc.) to any path under /api/
router.all('/*', (req, res) => {
    console.log('--- RENDER LISTENER CATCH-ALL ---');
    console.log(`Timestamp: ${new Date().toISOString()}`);
    console.log(`Method: ${req.method}`);
    console.log(`Path: ${req.originalUrl}`); // This will show the full path, e.g., /api/webhook
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
    
    // The body will be a Buffer, so we convert it to a string to log it.
    const bodyString = req.body && req.body.length > 0 ? req.body.toString() : '(empty body)';
    console.log('Body:', bodyString);

    console.log('--- END OF REQUEST ---');
    
    res.status(200).send('Request successfully received and logged by the simplified listener.');
});

module.exports = router;

