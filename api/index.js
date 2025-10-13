const express = require('express');
const { ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { getDb } = require('../database');
const authenticateToken = require('../middleware/auth');
const { loadSystemSettings, getSystemSettings } = require('../services/settings');
const videoRoutes = require('./video'); 

const router = express.Router();

const processedAlertIds = new Set();
const DAYS_OF_WEEK = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

// --- PUBLIC ROUTES (No Authentication Required) ---

// Webhook endpoint uses a raw body parser
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    console.log(`[Webhook] Received a request at ${new Date().toISOString()}`);

    const systemSettings = getSystemSettings();
    if (systemSettings.WEBHOOK_SECRET) {
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
        const alertData = JSON.parse(req.body.toString());

        const alertId = alertData.event_id; 
        if (!alertId) {
            console.warn('[Webhook] Alert data is missing the `event_id` field. Cannot perform idempotency check.');
        } else if (processedAlertIds.has(alertId)) {
            console.log(`[Webhook] Duplicate event_id received: ${alertId}. Ignoring.`);
            return res.status(200).send('Duplicate alert ignored.');
        } else {
            processedAlertIds.add(alertId);
            setTimeout(() => {
                processedAlertIds.delete(alertId);
            }, 60000); // Remove after 1 minute
        }

        const cameraId = alertData.camera?.id;
        if (!cameraId) {
            console.log('[Webhook] Request rejected: Missing camera ID in parsed body.');
            return res.status(400).send('Webhook data missing camera ID.');
        }

        const db = getDb();
        const devicesCollection = db.collection('devices');

        const device = await devicesCollection.findOne({ "cameras.id": cameraId });
        
        if (!device) {
             console.log(`[Webhook] Alert ignored for camera ${cameraId}: site not found.`);
            return res.status(200).send('Alert ignored: site not found.');
        }

        const camera = device.cameras.find(c => c.id === cameraId);

        if (camera && camera.isSleeping && camera.sleepExpiresAt && new Date() < new Date(camera.sleepExpiresAt)) {
            console.log(`[Webhook] Alert ignored for camera ${cameraId}: camera is in sleep mode.`);
            return res.status(200).send('Alert ignored: camera is sleeping.');
        }

        if (!camera || !camera.isMonitored) {
             console.log(`[Webhook] Alert ignored for camera ${cameraId}: not monitored.`);
            return res.status(200).send('Alert ignored: camera not monitored.');
        }

        const schedulesCollection = db.collection('schedules');
        const settingsCollection = db.collection('settings');
        const assignmentsDoc = await settingsCollection.findOne({ name: 'scheduleAssignments' });
        const scheduleId = assignmentsDoc?.assignments?.[cameraId];
        
        let isWithinSchedule = false;
        if (scheduleId) {
            const schedule = await schedulesCollection.findOne({ _id: new ObjectId(scheduleId) });
            if (schedule) {
                const { timezone } = getSystemSettings();
                const now = new Date();
                const formatter = new Intl.DateTimeFormat('en-US', {
                    timeZone: timezone || 'UTC', weekday: 'long', hour: '2-digit', minute: '2-digit', hour12: false,
                });
                const parts = formatter.formatToParts(now);
                const dayString = parts.find(p => p.type === 'weekday').value;
                const dayOfWeek = DAYS_OF_WEEK.indexOf(dayString);
                const currentTime = `${parts.find(p => p.type === 'hour').value}:${parts.find(p => p.type === 'minute').value}`;
                const todaySchedule = schedule.days[dayOfWeek];
                if (todaySchedule && todaySchedule.length > 0) {
                    for (const block of todaySchedule) {
                        if (currentTime >= block.startTime && currentTime <= block.endTime) {
                            isWithinSchedule = true;
                            break;
                        }
                    }
                }
            }
        }

        if (!isWithinSchedule) {
            console.log(`[Webhook] Alert for camera ${cameraId} is OUTSIDE of scheduled time. Ignoring.`);
            return res.status(200).send('Alert ignored: outside of schedule.');
        }
        
        const alertsCollection = db.collection('alerts');
        const dispatchGroupsCollection = db.collection('dispatchGroups');
        const group = await dispatchGroupsCollection.findOne({ siteIds: device._id });
        const targetGroupId = group ? group._id : 'general';

        const newAlertDocument = { 
            status: 'New', createdAt: new Date(), originalData: alertData, siteProfile: device, notes: [] 
        };

        const result = await alertsCollection.insertOne(newAlertDocument);
        
        if (req.broadcastToGroup) {
            req.broadcastToGroup(targetGroupId, { type: 'new_alert', alert: { _id: result.insertedId, ...newAlertDocument } });
        }
        
        console.log(`[Webhook] Successfully processed event_id: ${alertData.event_id}. Inserted DB ID: ${result.insertedId}.`);
        res.status(200).send('Webhook processed successfully.');
    } catch (error) {
        console.error('Error processing webhook:', error);
        res.status(500).send('Error processing webhook.');
    }
});

// Add the JSON body parser for all subsequent routes
router.use(express.json());

// Public status check
router.get('/status', (req, res) => {
    res.status(200).json({ status: 'ok', message: 'Server is running.' });
});

// Public login route
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
            dispatchGroupId: user.dispatchGroupId,
        };

        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '8h' });
        
        const userResponse = {
            username: user.username,
            role: user.role,
            dispatchGroupId: user.dispatchGroupId,
        };

        res.json({ token, user: userResponse });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: 'An internal server error occurred.' });
    }
});


// --- PROTECTED ROUTES ---
// All routes defined below this line require a valid JWT.
router.use(authenticateToken);

// Change password for the logged-in user
router.post('/auth/change-password', async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const { userId } = req.user;

    if (!currentPassword || !newPassword || newPassword.length < 6) {
        return res.status(400).json({ message: 'New password must be at least 6 characters long.' });
    }

    try {
        const db = getDb();
        const usersCollection = db.collection('users');
        const user = await usersCollection.findOne({ _id: new ObjectId(userId) });

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const isValid = await bcrypt.compare(currentPassword, user.password);
        if (!isValid) {
            return res.status(401).json({ message: 'Incorrect current password.' });
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        await usersCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: { password: hashedNewPassword } }
        );

        console.log(`[AUTH] User ${user.username} successfully changed their password.`);
        res.json({ success: true, message: 'Password updated successfully.' });
    } catch (error) {
        console.error("Error changing password:", error);
        res.status(500).json({ message: 'An internal server error occurred.' });
    }
});


// --- The rest of the protected routes ---

router.post('/cameras/:cameraId/sleep', async (req, res) => {
    if (req.user.role !== 'Administrator') {
        return res.status(403).json({ message: 'Forbidden' });
    }
    try {
        const cameraId = parseInt(req.params.cameraId);
        const { hours } = req.body;
        if (!hours || typeof hours !== 'number' || hours <= 0) {
            return res.status(400).json({ message: 'A positive number of hours is required.' });
        }
        const devicesCollection = getDb().collection('devices');
        const expirationDate = new Date();
        expirationDate.setHours(expirationDate.getHours() + hours);
        const result = await devicesCollection.updateOne(
            { "cameras.id": cameraId },
            { $set: { "cameras.$.isSleeping": true, "cameras.$.sleepExpiresAt": expirationDate } }
        );
        if (result.matchedCount === 0) return res.status(404).json({ message: 'Camera not found.' });
        res.json({ success: true, message: `Camera will sleep until ${expirationDate.toLocaleString()}` });
    } catch (error) {
        res.status(500).json({ message: 'An error occurred.' });
    }
});

router.post('/cameras/:cameraId/wakeup', async (req, res) => {
    if (req.user.role !== 'Administrator') {
        return res.status(403).json({ message: 'Forbidden' });
    }
    try {
        const cameraId = parseInt(req.params.cameraId);
        const devicesCollection = getDb().collection('devices');
        const result = await devicesCollection.updateOne(
            { "cameras.id": cameraId },
            { $set: { "cameras.$.isSleeping": false, "cameras.$.sleepExpiresAt": null } }
        );
        if (result.matchedCount === 0) return res.status(404).json({ message: 'Camera not found.' });
        res.json({ success: true, message: 'Camera monitoring has been resumed.' });
    } catch (error) {
        res.status(500).json({ message: 'An error occurred.' });
    }
});

router.post('/alerts/resolve-all', async (req, res) => {
    if (req.user.role !== 'Administrator') {
        return res.status(403).json({ message: 'Forbidden: Only administrators can resolve all alerts.' });
    }
    try {
        const db = getDb();
        const alertsCollection = db.collection('alerts');
        const result = await alertsCollection.updateMany(
            { status: { $ne: 'Resolved' } },
            { $set: { status: 'Resolved' } }
        );
        res.json({ success: true, message: `Successfully resolved ${result.modifiedCount} active alerts.` });
    } catch (error) {
        res.status(500).json({ message: 'An error occurred while resolving alerts.' });
    }
});

router.get('/alerts/active', async (req, res) => {
    try {
        const db = getDb();
        const { role, dispatchGroupId } = req.user;
        const alertsCollection = db.collection('alerts');
        const filter = { status: { $ne: 'Resolved' } };

        if (role === 'Dispatcher') {
            const dispatchGroupsCollection = db.collection('dispatchGroups');
            let siteIds = [];
            if (dispatchGroupId) {
                const group = await dispatchGroupsCollection.findOne({ _id: new ObjectId(dispatchGroupId) });
                if (group) siteIds = group.siteIds;
            } else {
                const allGroupedSiteIds = await dispatchGroupsCollection.distinct('siteIds');
                const devicesCollection = db.collection('devices');
                const unassignedSites = await devicesCollection.find({ _id: { $nin: allGroupedSiteIds } }).project({ _id: 1 }).toArray();
                siteIds = unassignedSites.map(site => site._id);
            }
            filter['siteProfile._id'] = { $in: siteIds };
        }
        const activeAlerts = await alertsCollection.find(filter).sort({ createdAt: -1 }).toArray();
        res.json(activeAlerts);
    } catch (error) {
        res.status(500).json([]);
    }
});

router.get('/monitored-devices', async (req, res) => {
    try {
        const db = getDb();
        const devicesCollection = db.collection('devices');
        const sitesWithMonitoredCameras = await devicesCollection.find({ "cameras.isMonitored": true }).sort({ name: 1 }).toArray();
        const monitoredSites = sitesWithMonitoredCameras.map(site => {
            const monitoredCameras = site.cameras.filter(camera => camera.isMonitored);
            return { ...site, cameras: monitoredCameras };
        });
        res.json(monitoredSites);
    } catch(error) { 
        res.status(500).json([]); 
    }
});

router.use('/video', videoRoutes);

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
    const { username } = req.user;
    const objectId = new ObjectId(id);
    const statusChangeNote = { username: username, text: `Status changed to ${status}`, timestamp: new Date() };
    await alertsCollection.updateOne({ _id: objectId }, { $set: { status, updatedAt: new Date() }, $push: { notes: statusChangeNote } });
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
    const { username } = req.user;
    const note = { username: username, text: noteText, timestamp: new Date() };
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

router.get('/schedules', async (req, res) => {
    res.json(await getDb().collection('schedules').find().toArray());
});

router.post('/schedules', async (req, res) => {
    const { name, days } = req.body;
    const result = await getDb().collection('schedules').insertOne({ name, days });
    res.status(201).json({ success: true, schedule: { _id: result.insertedId, name, days } });
});

router.put('/schedules/:id', async (req, res) => {
    const { id } = req.params;
    const scheduleData = req.body;
    delete scheduleData._id;
    await getDb().collection('schedules').updateOne({ _id: new ObjectId(id) }, { $set: scheduleData });
    res.json({ success: true });
});

router.delete('/schedules/:id', async (req, res) => {
    await getDb().collection('schedules').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ success: true });
});

router.get('/schedule-assignments', async (req, res) => {
    res.json(await getDb().collection('settings').findOne({ name: 'scheduleAssignments' }) || { assignments: {} });
});

router.post('/schedule-assignments', async (req, res) => {
    await getDb().collection('settings').updateOne({ name: 'scheduleAssignments' }, { $set: req.body }, { upsert: true });
    res.json({ success: true });
});

router.get('/settings', async (req, res) => {
    res.json(await getDb().collection('settings').findOne({ _id: 'global_settings' }) || {});
});

router.put('/settings', async (req, res) => {
    await getDb().collection('settings').updateOne({ _id: 'global_settings' }, { $set: req.body }, { upsert: true });
    await loadSystemSettings();
    res.json({ success: true });
});

router.get('/users', async (req, res) => {
    res.json(await getDb().collection('users').find({}, { projection: { password: 0 } }).toArray());
});

router.post('/users', async (req, res) => {
    const { username, password, role, dispatchGroupId } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { username, password: hashedPassword, role, createdAt: new Date() };
    if (role === 'Dispatcher' && dispatchGroupId) newUser.dispatchGroupId = new ObjectId(dispatchGroupId);
    const result = await getDb().collection('users').insertOne(newUser);
    res.status(201).json({ success: true, user: { _id: result.insertedId, username, role } });
});

router.put('/users/:userId', async (req, res) => {
    const { userId } = req.params;
    const { username, password, role, dispatchGroupId } = req.body;
    const updateData = { username, role };
    if (password) updateData.password = await bcrypt.hash(password, 10);
    if (role === 'Dispatcher' && dispatchGroupId) {
        updateData.dispatchGroupId = new ObjectId(dispatchGroupId);
    } else {
        await getDb().collection('users').updateOne({ _id: new ObjectId(userId) }, { $unset: { dispatchGroupId: "" } });
    }
    await getDb().collection('users').updateOne({ _id: new ObjectId(userId) }, { $set: updateData });
    res.json({ success: true });
});

router.delete('/users/:userId', async (req, res) => {
    await getDb().collection('users').deleteOne({ _id: new ObjectId(req.params.userId) });
    res.json({ success: true });
});

router.get('/dispatch-groups', async (req, res) => {
    res.json(await getDb().collection('dispatchGroups').find().sort({ name: 1 }).toArray());
});

router.post('/dispatch-groups', async (req, res) => {
    const { name, siteIds } = req.body;
    const result = await getDb().collection('dispatchGroups').insertOne({ name, siteIds: siteIds.map(id => parseInt(id)) });
    res.status(201).json({ success: true, group: { _id: result.insertedId, name, siteIds } });
});

router.put('/dispatch-groups/:id', async (req, res) => {
    const { id } = req.params;
    const { name, siteIds } = req.body;
    await getDb().collection('dispatchGroups').updateOne({ _id: new ObjectId(id) }, { $set: { name, siteIds: siteIds.map(id => parseInt(id)) } });
    res.json({ success: true });
});

router.delete('/dispatch-groups/:id', async (req, res) => {
    const { id } = req.params;
    await getDb().collection('dispatchGroups').deleteOne({ _id: new ObjectId(id) });
    await getDb().collection('users').updateMany({ dispatchGroupId: new ObjectId(id) }, { $unset: { dispatchGroupId: "" } });
    res.json({ success: true });
});

module.exports = router;