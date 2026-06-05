const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const pool = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../Client')));

// ============================================
// HEALTH CHECK
// ============================================
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Network Security API is running', timestamp: new Date() });
});

// ============================================
// DEVICES (Full CRUD)
// ============================================
app.get('/api/devices', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT d.*, m.name as manufacturer_name 
            FROM DEVICE d
            JOIN MANUFACTURER m ON d.manufacturer_id = m.manufacturer_id
            ORDER BY d.device_id
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/devices/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query(`
            SELECT d.*, m.name as manufacturer_name 
            FROM DEVICE d
            JOIN MANUFACTURER m ON d.manufacturer_id = m.manufacturer_id
            WHERE d.device_id = $1
        `, [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Device not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/devices', async (req, res) => {
    const { manufacturer_id, device_name, device_type, model_number, serial_number, ip_address, mac_address, firmware_version, status, location } = req.body;
    try {
        const result = await pool.query(`
            INSERT INTO DEVICE (manufacturer_id, device_name, device_type, model_number, serial_number, ip_address, mac_address, firmware_version, status, install_date, last_seen, location)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_DATE, CURRENT_DATE, $10)
            RETURNING *
        `, [manufacturer_id, device_name, device_type, model_number, serial_number, ip_address, mac_address, firmware_version, status, location]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/devices/:id', async (req, res) => {
    const { id } = req.params;
    const { device_name, firmware_version, status, ip_address, location } = req.body;
    try {
        const result = await pool.query(`
            UPDATE DEVICE 
            SET device_name = COALESCE($1, device_name),
                firmware_version = COALESCE($2, firmware_version),
                status = COALESCE($3, status),
                ip_address = COALESCE($4, ip_address),
                location = COALESCE($5, location),
                last_seen = CURRENT_DATE
            WHERE device_id = $6
            RETURNING *
        `, [device_name, firmware_version, status, ip_address, location, id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Device not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/devices/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM DEVICE WHERE device_id = $1 RETURNING device_id', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Device not found' });
        res.json({ message: 'Device deleted successfully', device_id: id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// SECURITY LOGS
// ============================================
app.get('/api/logs', async (req, res) => {
    const { severity, limit = 100, device_id } = req.query;
    let query = `
        SELECT sl.*, d.device_name, d.ip_address as device_ip
        FROM SECURITY_LOG sl
        JOIN DEVICE d ON sl.device_id = d.device_id
        WHERE 1=1
    `;
    const params = [];
    let idx = 1;
    if (severity) { query += ` AND sl.severity = $${idx++}`; params.push(severity); }
    if (device_id) { query += ` AND sl.device_id = $${idx++}`; params.push(device_id); }
    query += ` ORDER BY sl.log_time DESC LIMIT $${idx++}`;
    params.push(limit);
    try {
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/logs/summary/severity', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT severity, COUNT(*) as count
            FROM SECURITY_LOG
            GROUP BY severity
            ORDER BY CASE severity
                WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/logs/trend', async (req, res) => {
    const { days = 7 } = req.query;
    try {
        const result = await pool.query(`
            SELECT DATE(log_time) as date, severity, COUNT(*) as count
            FROM SECURITY_LOG
            WHERE log_time >= CURRENT_DATE - ($1 || ' days')::INTERVAL
            GROUP BY DATE(log_time), severity
            ORDER BY date DESC
        `, [days]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// ALERTS
// ============================================
app.get('/api/alerts', async (req, res) => {
    const { resolved_status } = req.query;
    let query = `
        SELECT a.*, d.device_name
        FROM ALERT a
        JOIN DEVICE d ON a.device_id = d.device_id
    `;
    const params = [];
    if (resolved_status) {
        query += ` WHERE a.resolved_status = $1`;
        params.push(resolved_status);
    }
    query += ` ORDER BY a.triggered_at DESC`;
    try {
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/alerts/open/count', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT resolved_status, COUNT(*) as count
            FROM ALERT
            GROUP BY resolved_status
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/alerts/:id/resolve', async (req, res) => {
    const { id } = req.params;
    const { resolution_notes, resolved_by } = req.body;
    try {
        const result = await pool.query(`
            UPDATE ALERT 
            SET resolved_status = 'Resolved', 
                resolved_at = CURRENT_DATE,
                resolution_notes = COALESCE($1, resolution_notes),
                resolved_by = COALESCE($2, resolved_by)
            WHERE alert_id = $3
            RETURNING *
        `, [resolution_notes, resolved_by, id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Alert not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// PATCHES
// ============================================
app.get('/api/patches', async (req, res) => {
    const { status } = req.query;
    let query = `
        SELECT p.*, d.device_name, d.ip_address
        FROM PATCH p
        JOIN DEVICE d ON p.device_id = d.device_id
    `;
    const params = [];
    if (status) {
        query += ` WHERE p.status = $1`;
        params.push(status);
    }
    query += ` ORDER BY p.release_date DESC`;
    try {
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/patches', async (req, res) => {
    const { device_id, patch_name, version, patch_type, release_date, description, reboot_required } = req.body;
    try {
        const result = await pool.query(`
            INSERT INTO PATCH (device_id, patch_name, version, patch_type, release_date, description, reboot_required, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'Pending')
            RETURNING *
        `, [device_id, patch_name, version, patch_type, release_date, description, reboot_required]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/patches/:id/apply', async (req, res) => {
    const { id } = req.params;
    const { applied_by } = req.body;
    try {
        const result = await pool.query(`
            UPDATE PATCH 
            SET status = 'Applied', 
                applied_date = CURRENT_DATE,
                applied_by = $1
            WHERE patch_id = $2
            RETURNING *
        `, [applied_by, id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Patch not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// DASHBOARD STATISTICS (For Charts)
// ============================================
app.get('/api/dashboard/stats', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                (SELECT COUNT(*) FROM DEVICE) as total_devices,
                (SELECT COUNT(*) FROM DEVICE WHERE status = 'Active') as active_devices,
                (SELECT COUNT(*) FROM DEVICE WHERE status = 'Inactive' OR status = 'Offline') as inactive_devices,
                (SELECT COUNT(*) FROM SECURITY_LOG WHERE severity = 'Critical') as critical_logs,
                (SELECT COUNT(*) FROM SECURITY_LOG WHERE severity = 'High') as high_logs,
                (SELECT COUNT(*) FROM SECURITY_LOG WHERE severity = 'Medium') as medium_logs,
                (SELECT COUNT(*) FROM SECURITY_LOG WHERE severity = 'Low') as low_logs,
                (SELECT COUNT(*) FROM ALERT WHERE resolved_status = 'Open') as open_alerts,
                (SELECT COUNT(*) FROM ALERT WHERE resolved_status = 'Resolved') as resolved_alerts,
                (SELECT COUNT(*) FROM PATCH WHERE status = 'Pending') as pending_patches,
                (SELECT COUNT(*) FROM PATCH WHERE status = 'Applied') as applied_patches,
                (SELECT COUNT(*) FROM INCIDENT WHERE status != 'Resolved') as active_incidents,
                (SELECT COUNT(*) FROM VULNERABILITY WHERE cvss_score >= 7.0) as critical_vulnerabilities
        `);
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/dashboard/device-types', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT device_type, COUNT(*) as count
            FROM DEVICE
            GROUP BY device_type
            ORDER BY count DESC
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/dashboard/patch-status', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT status, COUNT(*) as count
            FROM PATCH
            GROUP BY status
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/dashboard/alert-status', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT resolved_status, COUNT(*) as count
            FROM ALERT
            GROUP BY resolved_status
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/dashboard/top-devices', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT d.device_name, COUNT(sl.log_id) as log_count
            FROM DEVICE d
            LEFT JOIN SECURITY_LOG sl ON d.device_id = sl.device_id
            GROUP BY d.device_id, d.device_name
            ORDER BY log_count DESC
            LIMIT 5
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/dashboard/security-trend', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT DATE(log_time) as date, 
                   COUNT(*) as total_logs,
                   COUNT(CASE WHEN severity = 'Critical' THEN 1 END) as critical,
                   COUNT(CASE WHEN severity = 'High' THEN 1 END) as high,
                   COUNT(CASE WHEN severity = 'Medium' THEN 1 END) as medium,
                   COUNT(CASE WHEN severity = 'Low' THEN 1 END) as low
            FROM SECURITY_LOG
            WHERE log_time >= CURRENT_DATE - INTERVAL '7 days'
            GROUP BY DATE(log_time)
            ORDER BY date DESC
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// MANUFACTURERS
// ============================================
app.get('/api/manufacturers', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM MANUFACTURER ORDER BY name');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// VULNERABILITIES
// ============================================
app.get('/api/vulnerabilities', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM VULNERABILITY ORDER BY cvss_score DESC NULLS LAST');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/device-vulnerabilities', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT dv.*, d.device_name, v.cve_id, v.title 
            FROM DEVICE_VULNERABILITY dv
            JOIN DEVICE d ON dv.device_id = d.device_id
            JOIN VULNERABILITY v ON dv.vuln_id = v.vuln_id
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// CONFIGURATIONS
// ============================================
app.get('/api/configurations', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT c.*, d.device_name 
            FROM CONFIGURATION c
            JOIN DEVICE d ON c.device_id = d.device_id
            ORDER BY c.backup_date DESC
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// INCIDENTS
// ============================================
app.get('/api/incidents', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT i.*, d.device_name 
            FROM INCIDENT i
            JOIN DEVICE d ON i.device_id = d.device_id
            ORDER BY i.start_time DESC
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// COMPLIANCE CHECKS
// ============================================
app.get('/api/compliance', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT c.*, d.device_name 
            FROM COMPLIANCE_CHECK c
            JOIN DEVICE d ON c.device_id = d.device_id
            ORDER BY c.check_date DESC
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// MAINTENANCE SCHEDULE
// ============================================
app.get('/api/maintenance', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT m.*, d.device_name 
            FROM MAINTENANCE_SCHEDULE m
            JOIN DEVICE d ON m.device_id = d.device_id
            ORDER BY m.scheduled_date
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// AUDIT TRAIL
// ============================================
app.get('/api/audit', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT a.*, u.username 
            FROM AUDIT_TRAIL a
            LEFT JOIN "USER" u ON a.user_id = u.user_id
            ORDER BY a.action_time DESC
            LIMIT 100
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// NETWORK ZONES
// ============================================
app.get('/api/zones', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM NETWORK_ZONE ORDER BY zone_name');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// 404 HANDLER - MUST BE LAST
// ============================================
app.use((req, res) => {
    if (req.url.startsWith('/api/')) {
        res.status(404).json({ error: 'API endpoint not found: ' + req.url });
    } else {
        // For non-API routes, let the frontend handle it
        res.status(404).sendFile(path.join(__dirname, '../Client/index.html'));
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📍 URL: http://localhost:${PORT}`);
    console.log(`\n✅ Available API endpoints:`);
    console.log(`   GET    /api/health`);
    console.log(`   GET    /api/devices`);
    console.log(`   POST   /api/devices`);
    console.log(`   PUT    /api/devices/:id`);
    console.log(`   DELETE /api/devices/:id`);
    console.log(`   GET    /api/logs`);
    console.log(`   GET    /api/alerts`);
    console.log(`   PUT    /api/alerts/:id/resolve`);
    console.log(`   GET    /api/patches`);
    console.log(`   GET    /api/dashboard/stats`);
    console.log(`   GET    /api/dashboard/device-types`);
    console.log(`   GET    /api/dashboard/patch-status`);
    console.log(`   GET    /api/dashboard/alert-status`);
    console.log(`   GET    /api/dashboard/top-devices`);
    console.log(`   GET    /api/dashboard/security-trend`);
    console.log(`   GET    /api/manufacturers`);
    console.log(`   GET    /api/vulnerabilities`);
    console.log(`   GET    /api/device-vulnerabilities`);
    console.log(`   GET    /api/configurations`);
    console.log(`   GET    /api/incidents`);
    console.log(`   GET    /api/compliance`);
    console.log(`   GET    /api/maintenance`);
    console.log(`   GET    /api/audit`);
    console.log(`   GET    /api/zones`);
});
