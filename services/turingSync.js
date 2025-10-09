const fetch = require('node-fetch');
const { getDb } = require('../database');
const { getSystemSettings } = require('./settings');

const TURING_API_BASE_URL = 'https://app.turingvideo.com/openapi';

/**
 * Performs the main synchronization logic with the Turing API for multiple accounts.
 */
async function syncWithTuringAPI() {
    const systemSettings = getSystemSettings();
    // --- CHANGE 1: Check for the new `turingApiTokens` array instead of the single token ---
    if (!Array.isArray(systemSettings.turingApiTokens) || systemSettings.turingApiTokens.length === 0) {
        console.log('[SYNC] Aborted: No Turing API tokens are set in settings.');
        return;
    }
    const TURING_ACCESS_TOKENS = systemSettings.turingApiTokens;
    console.log(`[SYNC] Starting synchronization with Turing API for ${TURING_ACCESS_TOKENS.length} account(s)...`);
    
    const db = getDb();
    const devicesCollection = db.collection('devices');
    const allSitesFromAllAccounts = {};

    // --- CHANGE 2: Loop through each token and fetch data for each account ---
    for (const token of TURING_ACCESS_TOKENS) {
        console.log('[SYNC] Fetching data for a new token...');
        
        // Helper to recursively get site names from the tree structure
        const flattenSites = (sites, flatMap) => {
            for (const site of sites) {
                flatMap.set(site.id, site.name);
                if (site.children && site.children.length > 0) {
                    flattenSites(site.children, flatMap);
                }
            }
        };

        let siteNameMap = new Map();
        try {
            const sitesResponse = await fetch(`${TURING_API_BASE_URL}/bw/v2/site/sites/tree`, { headers: { 'Authorization': `Bearer ${token}` } });
            if (sitesResponse.ok) {
                const sitesData = await sitesResponse.json();
                flattenSites(sitesData.ret.sites || [], siteNameMap);
            }
        } catch (error) { console.error("[SYNC] Could not fetch site list for a token.", error); }

        // Fetch all cameras with pagination for the current token
        let allCamerasFromAPI = [];
        let hasMore = true;
        let offset = 0;
        while (hasMore) {
            try {
                const response = await fetch(`${TURING_API_BASE_URL}/nest/camera/cameras?limit=50&offset=${offset}`, { headers: { 'Authorization': `Bearer ${token}` } });
                if (response.ok) {
                    const data = await response.json();
                    const cameras = data.ret.cameras || [];
                    allCamerasFromAPI.push(...cameras);
                    hasMore = cameras.length === 50;
                    offset += 50;
                } else { hasMore = false; }
            } catch (error) { console.error("[SYNC] Failed to fetch cameras for a token.", error); hasMore = false; }
        }
        
        // Process cameras and sites for the current token
        for (const camera of allCamerasFromAPI) {
            if (!allSitesFromAllAccounts[camera.site_id]) {
                allSitesFromAllAccounts[camera.site_id] = { 
                    _id: camera.site_id, 
                    name: siteNameMap.get(camera.site_id) || `Unknown Site (${camera.site_id})`, 
                    cameras: [] 
                };
            }
            // --- CHANGE 3: Store the token used to fetch this camera directly on the camera object ---
            allSitesFromAllAccounts[camera.site_id].cameras.push({ 
                id: camera.id, 
                name: camera.name, 
                isMonitored: false,
                turingApiToken: token // Store the token
            });
        }
        console.log(`[SYNC] Found ${allCamerasFromAPI.length} cameras for this token.`);
    }

    // --- CHANGE 4: The rest of the logic now uses the aggregated data from all accounts ---
    const existingDevices = await devicesCollection.find({}).toArray();
    const existingDevicesMap = new Map(existingDevices.map(d => [d._id, d]));
    const bulkOps = [];

    for (const siteIdStr in allSitesFromAllAccounts) {
        const siteId = parseInt(siteIdStr);
        const siteFromAPI = allSitesFromAllAccounts[siteId];
        const existingSite = existingDevicesMap.get(siteId);

        let profileData = existingSite ? {
            account_number: existingSite.account_number,
            district: existingSite.district,
            pertinent_info: existingSite.pertinent_info,
        } : {};

        const updatedCameras = siteFromAPI.cameras.map(cameraFromAPI => {
            const existingCamera = existingSite?.cameras.find(c => c.id === cameraFromAPI.id);
            // Preserve monitoring status but update name and ensure token is present
            return { 
                id: cameraFromAPI.id, 
                name: cameraFromAPI.name, 
                isMonitored: existingCamera ? existingCamera.isMonitored : false,
                turingApiToken: cameraFromAPI.turingApiToken 
            };
        });

        bulkOps.push({
            updateOne: {
                filter: { _id: siteId },
                update: { 
                    $set: { name: siteFromAPI.name, cameras: updatedCameras, ...profileData },
                    $setOnInsert: { isConfigured: false }
                },
                upsert: true
            }
        });
    }

    if (bulkOps.length > 0) await devicesCollection.bulkWrite(bulkOps);
    console.log(`[SYNC] Synchronization with Turing API complete for all accounts.`);
}

/**
 * Initializes the synchronization process on server start and schedules it to run periodically.
 */
function startSync() {
    console.log("✅ Turing API synchronization service started.");
    
    // Run initial sync on startup
    syncWithTuringAPI();
    
    // Schedule sync every hour
    setInterval(syncWithTuringAPI, 60 * 60 * 1000);
}

module.exports = {
    startSync,
};