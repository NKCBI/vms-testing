const express = require('express');
const { ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { getDb } = require('../database');
// const authenticateToken = require('../middleware/auth'); // Kept commented out for now
const { loadSystemSettings, getSystemSettings } = require('../services/settings');

// Import the new video router
const videoRoutes = require('./video'); 

const router = express.Router();
router.use(express.json());


// --- Server Status Endpoint (Public GET) ---
// You can visit this in a browser to confirm the server is running.
router.get('/status', (req, res) => {
    console.log(`[Status] GET request received at ${new Date().toISOString()}`);
    res.status(200).json({ status: 'ok', message: 'Server is running.' });
});

// --- Auth (Public Route) ---
router.post('/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const db = getDb();
        const usersCollection = db.collection('users');
        const user = await usersCollection.findOne({ username });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const tokenPayload = { 
            userId: user._id, 
            username: user.username, 
            role: user.role, 
            dispatchGroupId: user.dispatchGroupId 
        };

        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '8h' });
        res.json({ token, user: { username: user.username, role: user.role, dispatchGroupId: user.dispatchGroupId } });

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: 'An internal server error occurred.' });
    }
});

// --- Webhook (Public Route) ---
// This middleware is crucial for signature validation as it provides the raw, unparsed request body.
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    console.log(`[Webhook] Received a request at ${new Date().toISOString()}`);

    const systemSettings = getSystemSettings();
    if (systemSettings.WEBHOOK_SECRET) { // Using the correct env var name
        const signature = req.headers['x-turingvideo-signature'];
        if (!signature) {
            console.log('[Webhook] Request rejected: Signature missing.');
            return res.status(401).send('Signature missing');
        }

        const expectedSignature = crypto.createHmac('md5', systemSettings.WEBHOOK_SECRET).update(req.body).digest('hex');
        if (signature !== expectedSignature) {
            console.log(`[Webhook] Request rejected: Invalid signature. Expected: ${expectedSignature}, Got: ${signature}`);
            return res.status(403).send('Invalid signature');
        }
        console.log('[Webhook] Signature validated successfully.');
    }

    try {
        // We now need to parse the raw body buffer into a JSON object.
        const alertData = JSON.parse(req.body.toString());
        const cameraId = alertData.camera?.id;
        if (!cameraId) {
            console.log('[Webhook] Request rejected: Missing camera ID in parsed body.');
            return res.status(400).send('Webhook data missing camera ID.');
        }

        const db = getDb();
        const alertsCollection = db.collection('alerts');
        const devicesCollection = db.collection('devices');
        const dispatchGroupsCollection = db.collection('dispatchGroups');

        const device = await devicesCollection.findOne({ "cameras.id": cameraId, "cameras.isMonitored": true });
        if (!device) {
            console.log(`[Webhook] Alert ignored for camera ${cameraId}: not monitored.`);
            return res.status(200).send('Alert ignored: camera not monitored.');
        }

        const group = await dispatchGroupsCollection.findOne({ siteIds: device._id });
        const targetGroupId = group ? group._id : 'general';

        const newAlertDocument = { 
            status: 'New', 
            createdAt: new Date(), 
            originalData: alertData, 
            siteProfile: device, 
            notes: [] 
        };

        const result = await alertsCollection.insertOne(newAlertDocument);
        
        if (req.broadcastToGroup) {
            req.broadcastToGroup(targetGroupId, { type: 'new_alert', alert: { _id: result.insertedId, ...newAlertDocument } });
        } else {
            console.warn('[Webhook] broadcastToGroup function not available on request object.');
        }
        
        console.log(`[Webhook] Successfully processed and stored alert ${result.insertedId}.`);
        res.status(200).send('Webhook processed successfully.');
    } catch (error) {
        console.error('Error processing webhook:', error);
        res.status(500).send('Error processing webhook.');
    }
});


// --- All routes below this line would be protected in production ---
// router.use(authenticateToken); 


// --- Monitored Devices Route ---
router.get('/monitored-devices', async (req, res) => {
    try {
        const db = getDb();
        const devicesCollection = db.collection('devices');
        
        const monitoredSites = await devicesCollection.aggregate([
            { $unwind: "$cameras" }, 
            { $match: { "cameras.isMonitored": true } }, 
            { $group: { _id: "$_id", name: { $first: "$name" }, cameras: { $push: "$cameras" } } },
            { $sort: { name: 1 } }
        ]).toArray();
        res.json(monitoredSites);
    } catch(error) { 
        console.error("Error fetching monitored devices:", error);
        res.status(500).json([]); 
    }
});


// --- Video Routes ---
router.use('/video', videoRoutes);


// --- Devices (Master Roster) ---
router.get('/devices', async (req, res) => {
    const devicesCollection = getDb().collection('devices');
    res.json(await devicesCollection.find().sort({ name: 1 }).toArray());
});

router.put('/cameras/:id/monitor', async (req, res) => {
    const devicesCollection = getDb().collection('devices');
    await devicesCollection.updateOne({ "cameras.id": parseInt(req.params.id) }, { $set: { "cameras.$.isMonitored": req.body.isMonitored } });
    res.json({ success: true });
});

router.put('/sites/:siteId/monitor-all', async (req, res) => {
    const devicesCollection = getDb().collection('devices');
    await devicesCollection.updateOne({ _id: parseInt(req.params.siteId) }, { $set: { "cameras.$[].isMonitored": req.body.isMonitored } });
    res.json({ success: true });
});

router.put('/devices/:id/profile', async (req, res) => {
    const devicesCollection = getDb().collection('devices');
    const { _id, name, cameras, ...profileData } = req.body;
    await devicesCollection.updateOne({ _id: parseInt(req.params.id) }, { $set: { ...profileData, isConfigured: true } });
    res.json({ success: true });
});


// --- Alerts ---
router.get('/alerts/history', async (req, res) => {
    const alertsCollection = getDb().collection('alerts');
    const { startDate, endDate, siteId } = req.query;
    let filter = {};
    if (startDate && endDate) filter.createdAt = { $gte: new Date(startDate), $lte: new Date(endDate) };
    if (siteId) filter['siteProfile._id'] = parseInt(siteId);
    res.json(await alertsCollection.find(filter).sort({ createdAt: -1 }).limit(500).toArray());
});

router.post('/alerts/:id/status', async (req, res) => {
    const alertsCollection = getDb().collection('alerts');
    const dispatchGroupsCollection = getDb().collection('dispatchGroups');
    const { id } = req.params;
    const { status } = req.body;
    const objectId = new ObjectId(id);
    await alertsCollection.updateOne({ _id: objectId }, { $set: { status, updatedAt: new Date() } });
    const updatedAlert = await alertsCollection.findOne({ _id: objectId });
    const group = await dispatchGroupsCollection.findOne({ siteIds: updatedAlert.siteProfile._id });
    const targetGroupId = group ? group._id : 'general';
    if (req.broadcastToGroup) {
       req.broadcastToGroup(targetGroupId, { type: 'update_alert', alert: updatedAlert });
    }
    res.json({ success: true, alert: updatedAlert });
});

router.post('/alerts/:id/notes', async (req, res) => {
    const alertsCollection = getDb().collection('alerts');
    const dispatchGroupsCollection = getDb().collection('dispatchGroups');
    const { id } = req.params;
    const { noteText } = req.body;
    const note = { username: 'System', text: noteText, timestamp: new Date() };
    const objectId = new ObjectId(id);
    await alertsCollection.updateOne({ _id: objectId }, { $push: { notes: note } });
    const updatedAlert = await alertsCollection.findOne({ _id: objectId });
    const group = await dispatchGroupsCollection.findOne({ siteIds: updatedAlert.siteProfile._id });
    const targetGroupId = group ? group._id : 'general';
    if (req.broadcastToGroup) {
        req.broadcastToGroup(targetGroupId, { type: 'update_alert', alert: updatedAlert });
    }
    res.json({ success: true, alert: updatedAlert });
});

// --- Schedules ---
router.get('/schedules', async (req, res) => {
    const schedulesCollection = getDb().collection('schedules');
    res.json(await schedulesCollection.find().toArray());
});

router.post('/schedules', async (req, res) => {
    const schedulesCollection = getDb().collection('schedules');
    const { name, days } = req.body;
    const result = await schedulesCollection.insertOne({ name, days });
    res.status(201).json({ success: true, schedule: { _id: result.insertedId, name, days } });
});

router.put('/schedules/:id', async (req, res) => {
    const schedulesCollection = getDb().collection('schedules');
    const { id } = req.params;
    const scheduleData = req.body;
    delete scheduleData._id;
    await schedulesCollection.updateOne({ _id: new ObjectId(id) }, { $set: scheduleData });
    res.json({ success: true });
});

router.delete('/schedules/:id', async (req, res) => {
    const schedulesCollection = getDb().collection('schedules');
    await schedulesCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ success: true });
});

// --- Schedule Assignments ---
router.get('/schedule-assignments', async (req, res) => {
    const settingsCollection = getDb().collection('settings');
    res.json(await settingsCollection.findOne({ name: 'scheduleAssignments' }) || { assignments: {} });
});

router.post('/schedule-assignments', async (req, res) => {
    const settingsCollection = getDb().collection('settings');
    await settingsCollection.updateOne({ name: 'scheduleAssignments' }, { $set: req.body }, { upsert: true });
    res.json({ success: true });
});

// --- System Settings ---
router.get('/settings', async (req, res) => {
    const settingsCollection = getDb().collection('settings');
    res.json(await settingsCollection.findOne({ _id: 'global_settings' }) || {});
});

router.put('/settings', async (req, res) => {
    const settingsCollection = getDb().collection('settings');
    await settingsCollection.updateOne({ _id: 'global_settings' }, { $set: req.body }, { upsert: true });
    await loadSystemSettings();
    res.json({ success: true });
});

// --- User Management ---
router.get('/users', async (req, res) => {
    const usersCollection = getDb().collection('users');
    res.json(await usersCollection.find({}, { projection: { password: 0 } }).toArray());
});

router.post('/users', async (req, res) => {
    const usersCollection = getDb().collection('users');
    const { username, password, role, dispatchGroupId } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { username, password: hashedPassword, role, createdAt: new Date() };
    if (role === 'Dispatcher' && dispatchGroupId) newUser.dispatchGroupId = new ObjectId(dispatchGroupId);
    const result = await usersCollection.insertOne(newUser);
    res.status(201).json({ success: true, user: { _id: result.insertedId, username, role } });
});

router.put('/users/:userId', async (req, res) => {
    const usersCollection = getDb().collection('users');
    const { userId } = req.params;
    const { username, password, role, dispatchGroupId } = req.body;
    const updateData = { username, role };
    if (password) updateData.password = await bcrypt.hash(password, 10);
    if (role === 'Dispatcher' && dispatchGroupId) {
        updateData.dispatchGroupId = new ObjectId(dispatchGroupId);
    } else {
        await usersCollection.updateOne({ _id: new ObjectId(userId) }, { $unset: { dispatchGroupId: "" } });
    }
    await usersCollection.updateOne({ _id: new ObjectId(userId) }, { $set: updateData });
    res.json({ success: true });
});

router.delete('/users/:userId', async (req, res) => {
    const usersCollection = getDb().collection('users');
    await usersCollection.deleteOne({ _id: new ObjectId(req.params.userId) });
    res.json({ success: true });
});

// --- Dispatch Groups ---
router.get('/dispatch-groups', async (req, res) => {
    const dispatchGroupsCollection = getDb().collection('dispatchGroups');
    res.json(await dispatchGroupsCollection.find().sort({ name: 1 }).toArray());
});

router.post('/dispatch-groups', async (req, res) => {
    const dispatchGroupsCollection = getDb().collection('dispatchGroups');
    const { name, siteIds } = req.body;
    const result = await dispatchGroupsCollection.insertOne({ name, siteIds: siteIds.map(id => new ObjectId(id)) });
    res.status(201).json({ success: true, group: { _id: result.insertedId, name, siteIds } });
});

router.put('/dispatch-groups/:id', async (req, res) => {
    const dispatchGroupsCollection = getDb().collection('dispatchGroups');
    const { id } = req.params;
    const { name, siteIds } = req.body;
    await dispatchGroupsCollection.updateOne({ _id: new ObjectId(id) }, { $set: { name, siteIds: siteIds.map(id => new ObjectId(id)) } });
    res.json({ success: true });
});

router.delete('/dispatch-groups/:id', async (req, res) => {
    const dispatchGroupsCollection = getDb().collection('dispatchGroups');
    const usersCollection = getDb().collection('users');
    const { id } = req.params;
    await dispatchGroupsCollection.deleteOne({ _id: new ObjectId(id) });
    await usersCollection.updateMany({ dispatchGroupId: new ObjectId(id) }, { $unset: { dispatchGroupId: "" } });
    res.json({ success: true });
});

module.exports = router;

