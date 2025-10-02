const express = require('express');
const axios = require('axios');
const authenticateToken = require('../middleware/auth');
const { getSystemSettings } = require('../services/settings');

const router = express.Router();

// The 'authenticateToken' middleware is removed from the individual routes below
// because it is already applied by the parent router in /api/index.js

router.post('/rtsp-url', async (req, res) => {
    const { camera_id, resolution } = req.body;
    console.log(`[RTSP] Received request for RTSP URL for camera_id: ${camera_id}`);
    if (!camera_id) {
        return res.status(400).json({ message: 'camera_id is required.' });
    }

    const settings = getSystemSettings();
    const turingApiUrl = settings.turingApiUrl || 'https://app.turingvideo.com/openapi';
    const turingAccessToken = settings.turingApiToken;

    if (!turingAccessToken) {
        console.error('[RTSP] Turing API token is not configured.');
        return res.status(500).json({ message: 'Server is not configured for the video API.' });
    }

    try {
        console.log(`[RTSP] Calling Turing API for camera: ${camera_id}`);
        const turingApiResponse = await axios.post(`${turingApiUrl}/nest/live/rtsp`, 
            { camera_id, resolution: resolution || 'sub' },
            { headers: { 'Authorization': `Bearer ${turingAccessToken}`, 'Content-Type': 'application/json' } }
        );

        if (turingApiResponse.data && turingApiResponse.data.ret && turingApiResponse.data.ret.play_url) {
            const originalUrl = turingApiResponse.data.ret.play_url;
            console.log(`[RTSP] Successfully retrieved original URL: ${originalUrl}`);
            const authenticatedUrl = originalUrl.replace('rtsp://', `rtsp://token:${turingAccessToken}@`);
            
            console.log(`[API] Successfully authenticated and retrieved stream for camera ${camera_id}.`);
            
            turingApiResponse.data.ret.play_url = authenticatedUrl;
            res.json(turingApiResponse.data);
        } else {
            console.error(`[API] Turing API did not return a play_url for camera ${camera_id}. This is likely a token permission issue. Full response:`, JSON.stringify(turingApiResponse.data, null, 2));
            res.status(403).json({ message: `Access to video stream denied by API. Please check token permissions.` });
        }

    } catch (error) {
        // More robust error logging to catch network errors or non-response errors
        console.error('[API] Error calling Turing API:', error.response ? error.response.data : error.message);
        res.status(500).json({ message: 'An error occurred while contacting the Turing API.' });
    }
});

// --- MediaMTX Control Endpoints ---
router.post('/start-stream', async (req, res) => {
    const { pathName, rtspUrl } = req.body;
    console.log(`[MediaMTX] Start-stream request for path: ${pathName} with URL: ${rtspUrl}`);
    const settings = getSystemSettings();
    const mediaMtxApiUrl = settings.mediaMtxApiUrl || `http://localhost:9997/v3`;

    try {
        let pathExists = false;
        console.log(`[MediaMTX] Checking if path '${pathName}' exists...`);
        try {
            // First, try to get the path to see if it exists.
            await axios.get(`${mediaMtxApiUrl}/config/paths/get/${pathName}`);
            pathExists = true;
            console.log(`[MediaMTX] Path '${pathName}' found.`);
        } catch (error) {
            // A 404 error is expected if the path doesn't exist yet. Any other error is a problem.
            if (error.response && error.response.status === 404) {
                console.log(`[MediaMTX] Path '${pathName}' does not exist yet.`);
            } else {
                console.error(`[MediaMTX] Error checking for path '${pathName}':`, error.response ? error.response.data : error.message);
                throw error; // Re-throw unexpected errors.
            }
        }

        if (pathExists) {
            // If the path exists, patch it with the new source URL to hotswap.
            console.log(`[MediaMTX] Path ${pathName} exists. Patching source for hotswap...`);
            const payload = { source: rtspUrl };
            console.log(`[MediaMTX] PATCH payload for '${pathName}':`, JSON.stringify(payload));
            await axios.patch(`${mediaMtxApiUrl}/config/paths/patch/${pathName}`, payload);
            console.log(`[MediaMTX] Successfully patched source for '${pathName}'.`);
            res.json({ success: true, message: `MediaMTX path ${pathName} source updated.` });
        } else {
            // If the path does not exist, create it.
            console.log(`[MediaMTX] Path ${pathName} does not exist. Creating...`);
            const payload = {
                source: rtspUrl,
                sourceOnDemand: true,
                sourceOnDemandCloseAfter: '20s',
                rtspTransport: 'tcp'
            };
            console.log(`[MediaMTX] POST payload for '${pathName}':`, JSON.stringify(payload));
            await axios.post(`${mediaMtxApiUrl}/config/paths/add/${pathName}`, payload);
            console.log(`[MediaMTX] Successfully created path '${pathName}'.`);
            res.json({ success: true, message: `MediaMTX path ${pathName} configured.` });
        }
    } catch (error) {
        console.error(`[MediaMTX] Error in start-stream for path ${pathName}:`, error.response ? error.response.data : error.message);
        res.status(500).json({ message: 'Failed to configure MediaMTX path.' });
    }
});


router.patch('/stream', async (req, res) => {
    const { pathName, rtspUrl } = req.body;
    const settings = getSystemSettings();
    const mediaMtxApiUrl = settings.mediaMtxApiUrl || `http://localhost:9997/v3`;

    try {
        // Correct logic: hotswap requires only patching the 'source' parameter.
        const payload = {
            source: rtspUrl
        };

        console.log(`[MediaMTX] Attempting to patch path ${pathName} with new source:`, rtspUrl);
        
        const response = await axios.patch(`${mediaMtxApiUrl}/config/paths/patch/${pathName}`, payload);
        
        console.log(`[MediaMTX] Successfully received response for path patch:`, response.status, response.data);
        res.json({ success: true, message: `MediaMTX path ${pathName} source updated.` });
    } catch (error) {
        // Log the full error response from MediaMTX to help diagnose the issue.
        const errorResponse = error.response ? JSON.stringify(error.response.data, null, 2) : error.message;
        console.error(`[MediaMTX] Error hotswapping path ${pathName}:`, errorResponse);
        res.status(500).json({ message: 'Failed to hotswap MediaMTX path source.' });
    }
});

module.exports = router;

