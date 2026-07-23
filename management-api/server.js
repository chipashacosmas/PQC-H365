const express = require('express');
const cors = require('cors');
const { spawn } = require('child_process');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3000;
let vpnProcess = null;
let logs = [];

// Paths to the executable
const VPN_EXECUTABLE = path.join(__dirname, '../build/server');

app.get('/api/status', (req, res) => {
    res.json({
        running: vpnProcess !== null,
        pid: vpnProcess ? vpnProcess.pid : null
    });
});

app.post('/api/start', (req, res) => {
    if (vpnProcess) {
        return res.status(400).json({ error: 'VPN server is already running' });
    }

    logs = [];
    
    // Spawn the C executable
    vpnProcess = spawn(VPN_EXECUTABLE);

    vpnProcess.stdout.on('data', (data) => {
        const text = data.toString();
        console.log(`[VPN] ${text}`);
        logs.push({ type: 'info', text });
        if (logs.length > 500) logs.shift(); // Keep last 500 lines
    });

    vpnProcess.stderr.on('data', (data) => {
        const text = data.toString();
        console.error(`[VPN ERR] ${text}`);
        logs.push({ type: 'error', text });
        if (logs.length > 500) logs.shift();
    });

    vpnProcess.on('close', (code) => {
        logs.push({ type: 'info', text: `VPN server exited with code ${code}` });
        vpnProcess = null;
    });

    res.json({ message: 'VPN server started successfully', pid: vpnProcess.pid });
});

app.post('/api/stop', (req, res) => {
    if (!vpnProcess) {
        return res.status(400).json({ error: 'VPN server is not running' });
    }

    vpnProcess.kill('SIGTERM');
    res.json({ message: 'Stop signal sent' });
});

app.get('/api/logs', (req, res) => {
    res.json(logs);
});

// Mock metrics data for the dashboard charts
let timeCounter = 0;
app.get('/api/metrics', (req, res) => {
    if (!vpnProcess) {
        return res.json([]);
    }
    
    timeCounter++;
    // Simulate ML-KEM handshake latency (usually higher than classical)
    const baseLatency = 45; 
    const jitter = Math.random() * 15;
    
    // Return last 20 data points
    const data = [];
    for(let i=0; i<20; i++) {
        data.push({
            time: `T-${20-i}`,
            latency: Math.round(baseLatency + (Math.random() * 15))
        });
    }
    
    res.json(data);
});

app.listen(PORT, () => {
    console.log(`Management API listening on http://localhost:${PORT}`);
});
