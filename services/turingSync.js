const fetch = require('node-fetch');
const { getDb } = require('../database');
const { getSystemSettings } = require('./settings');

const TURING_API_BASE_URL = 'https://app.turingvideo.com/openapi';

/**
 * Performs the main synchronization logic with the Turing API.
 */
async function syncWithTuringAPI() {
    const systemSettings = getSystemSettings();
    if (!Array.isArray(systemSettings.turingApiTokens) || systemSettings.turingApiTokens.length === 0) {
        console.log('[SYNC] Aborted: No Turing API tokens are set in settings.');
        return;
    }
    const TURING_ACCESS_TOKENS = systemSettings.turingApiTokens;
    console.log(`[SYNC] Starting synchronization with Turing API for ${TURING_ACCESS_TOKENS.length} account(s)...`);
    
    const db = getDb();
    const devicesCollection = db.collection('devices');
    const allSitesFromAllAccounts = {};

    for (const token of TURING_ACCESS_TOKENS) {
        console.log('[SYNC] Fetching data for a new token...');
        
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
        
        for (const camera of allCamerasFromAPI) {
            if (!allSitesFromAllAccounts[camera.site_id]) {
                allSitesFromAllAccounts[camera.site_id] = { 
                    _id: camera.site_id, 
                    name: siteNameMap.get(camera.site_id) || `Unknown Site (${camera.site_id})`, 
                    cameras: [] 
                };
            }
            allSitesFromAllAccounts[camera.site_id].cameras.push({ 
                id: camera.id, 
                name: camera.name, 
                turingApiToken: token
            });
        }
        console.log(`[SYNC] Found ${allCamerasFromAPI.length} cameras for this token.`);
    }

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

        // --- Preserve per-camera settings, surviving removal/re-add cycles ---
        // cameraSettings is a persistent map keyed by camera ID. It outlives the cameras
        // array, so if a camera is temporarily removed from Turing Vision and re-added
        // (same ID), its isMonitored state is restored instead of resetting to false.
        const persistedSettings = existingSite?.cameraSettings || {};

        const updatedCameras = siteFromAPI.cameras.map(cameraFromAPI => {
            // First check the live cameras array, then fall back to the persisted map.
            const existingCamera = existingSite?.cameras.find(c => c.id === cameraFromAPI.id);
            const savedSettings = persistedSettings[cameraFromAPI.id];
            const source = existingCamera || savedSettings;
            return {
                id: cameraFromAPI.id,
                name: cameraFromAPI.name,
                turingApiToken: cameraFromAPI.turingApiToken,
                isMonitored: source ? source.isMonitored : false,
                isSleeping: source ? source.isSleeping : false,
                sleepExpiresAt: source ? source.sleepExpiresAt : null,
            };
        });

        // Rebuild the persisted settings map so it always reflects the latest state.
        // We keep ALL previously seen cameras (not just current ones) so re-added cameras
        // can restore their settings.
        const updatedCameraSettings = { ...persistedSettings };
        for (const camera of updatedCameras) {
            updatedCameraSettings[camera.id] = {
                isMonitored: camera.isMonitored,
                isSleeping: camera.isSleeping,
                sleepExpiresAt: camera.sleepExpiresAt,
            };
        }

        bulkOps.push({
            updateOne: {
                filter: { _id: siteId },
                update: {
                    $set: {
                        name: siteFromAPI.name,
                        cameras: updatedCameras,
                        cameraSettings: updatedCameraSettings,
                        ...profileData
                    },
                    $setOnInsert: { isConfigured: false }
                },
                upsert: true
            }
        });
    }

    if (bulkOps.length > 0) await devicesCollection.bulkWrite(bulkOps);

    // Remove sites that no longer exist in Turing
    const activeSiteIds = Object.keys(allSitesFromAllAccounts).map(id => parseInt(id));
    const deleteResult = await devicesCollection.deleteMany({ _id: { $nin: activeSiteIds } });
    if (deleteResult.deletedCount > 0) {
        console.log(`[SYNC] Removed ${deleteResult.deletedCount} stale site(s) no longer present in Turing.`);
    }

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
    syncWithTuringAPI
};