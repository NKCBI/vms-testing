// VMS_Project/backend/services/settings.js
const { getDb } = require('../database');

// This object will act as a fast, in-memory cache for our settings.
let systemSettings = {
    turingApiToken: null,
    webhookSecret: null,
};

/**
 * Loads the global settings from the database and updates the in-memory cache.
 * This should be called on server startup and after any settings are updated.
 */
async function loadSystemSettings() {
    try {
        const db = getDb();
        if (!db) {
            console.warn("[Settings] Database not available yet. Skipping settings load.");
            return;
        }
        const settingsCollection = db.collection('settings');
        const settings = await settingsCollection.findOne({ _id: 'global_settings' });
        
        if (settings) {
            // Merge the loaded settings into our cache
            systemSettings = { ...systemSettings, ...settings };
            console.log("✅ System settings loaded successfully.");
        } else {
            console.warn("⚠️ No system settings found in database. Using defaults.");
        }
    } catch (error) {
        console.error("❌ Failed to load system settings:", error);
    }
}

/**
 * A simple getter function to securely access the cached settings from anywhere in the app.
 * @returns {object} The currently cached system settings.
 */
function getSystemSettings() {
    return systemSettings;
}

module.exports = {
    loadSystemSettings,
    getSystemSettings,
};
