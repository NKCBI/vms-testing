const fetch = require('node-fetch');
const { getDb } = require('../database');
const { getSystemSettings } = require('./settings');

const TURING_API_BASE_URL = 'https://app.turingvideo.com/openapi';

/**
 * Performs the main synchronization logic with the Turing API.
 */
async function syncWithTuringAPI() {
    const systemSettings = getSystemSettings();
    if (!systemSettings.turingApiToken) {
        console.log('[SYNC] Aborted: Turing API token not set.');
        return;
    }
    const TURING_ACCESS_TOKEN = systemSettings.turingApiToken;
    console.log('[SYNC] Starting synchronization with Turing API...');
    
    const db = getDb();
    const devicesCollection = db.collection('devices');

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
        const sitesResponse = await fetch(`${TURING_API_BASE_URL}/bw/v2/site/sites/tree`, { headers: { 'Authorization': `Bearer ${TURING_ACCESS_TOKEN}` } });
        if (sitesResponse.ok) {
            const sitesData = await sitesResponse.json();
            flattenSites(sitesData.ret.sites || [], siteNameMap);
        }
    } catch (error) { console.error("[SYNC] Could not fetch site list.", error); }

    // Fetch all cameras with pagination
    let allCamerasFromAPI = [];
    let hasMore = true;
    let offset = 0;
    while (hasMore) {
        try {
            const response = await fetch(`${TURING_API_BASE_URL}/nest/camera/cameras?limit=50&offset=${offset}`, { headers: { 'Authorization': `Bearer ${TURING_ACCESS_TOKEN}` } });
            if (response.ok) {
                const data = await response.json();
                const cameras = data.ret.cameras || [];
                allCamerasFromAPI.push(...cameras);
                hasMore = cameras.length === 50;
                offset += 50;
            } else { hasMore = false; }
        } catch (error) { console.error("[SYNC] Failed to fetch cameras.", error); hasMore = false; }
    }
    
    const sitesFromAPI = {};
    for (const camera of allCamerasFromAPI) {
        if (!sitesFromAPI[camera.site_id]) {
            sitesFromAPI[camera.site_id] = { 
                _id: camera.site_id, 
                name: siteNameMap.get(camera.site_id) || `Unknown Site (${camera.site_id})`, 
                cameras: [] 
            };
        }
        sitesFromAPI[camera.site_id].cameras.push({ id: camera.id, name: camera.name, isMonitored: false });
    }

    const existingDevices = await devicesCollection.find({}).toArray();
    const existingDevicesMap = new Map(existingDevices.map(d => [d._id, d]));
    const bulkOps = [];

    for (const siteIdStr in sitesFromAPI) {
        const siteId = parseInt(siteIdStr);
        const siteFromAPI = sitesFromAPI[siteId];
        const existingSite = existingDevicesMap.get(siteId);

        let profileData = existingSite ? {
            account_number: existingSite.account_number,
            district: existingSite.district,
            pertinent_info: existingSite.pertinent_info,
        } : {};

        const updatedCameras = siteFromAPI.cameras.map(cameraFromAPI => {
            const existingCamera = existingSite?.cameras.find(c => c.id === cameraFromAPI.id);
            return { id: cameraFromAPI.id, name: cameraFromAPI.name, isMonitored: existingCamera ? existingCamera.isMonitored : false };
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
    console.log(`[SYNC] Synchronization with Turing API complete.`);
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
