// VMS_Project/backend/database.js
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');

const MONGO_CONNECTION_STRING = process.env.MONGO_CONNECTION_STRING;
let db;

async function connectToDb() {
    try {
        const client = new MongoClient(MONGO_CONNECTION_STRING);
        await client.connect();
        db = client.db();
        console.log('✅ Successfully connected to MongoDB.');
        
        // Ensure a default admin user exists on startup
        const usersCollection = db.collection('users');
        const userCount = await usersCollection.countDocuments();
        if (userCount === 0) {
            const hashedPassword = await bcrypt.hash('password', 10);
            await usersCollection.insertOne({ username: 'admin', password: hashedPassword, role: 'Administrator', createdAt: new Date() });
            console.log("✅ Default admin user created. User: admin, Pass: password");
        }
    } catch (err) {
        console.error('Failed to connect to MongoDB', err);
        process.exit(1);
    }
}

// Function to get the database instance
function getDb() {
    return db;
}

module.exports = { connectToDb, getDb };
