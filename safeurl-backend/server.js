require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');

const app = express();
app.use(cors());
app.use(express.json());

// MySQL Database Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Helper function to extract domain from URL
function extractDomain(url) {
    try {
        const { hostname } = new URL(url);
        return hostname;
    } catch (e) {
        return "unknown";
    }
}

// POST /predict - The endpoint our Chrome Extension will call
// POST /predict - The endpoint our Chrome Extension will call
app.post('/predict', async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }

    const domain = extractDomain(url);

    try {
        // --- NEW CODE: Call the Python ML Service ---
        // Dynamically import node-fetch (required for newer versions of fetch in Node)
        const fetch = (await import('node-fetch')).default;
        
        const mlResponse = await fetch('https://safeurl-ml-api.onrender.com/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const mlData = await mlResponse.json();
        const mlProbability = mlData.phishing_probability;
        // ---------------------------------------------

        let prediction = "LEGITIMATE";
        let risk_level = "LOW";

        if (mlProbability >= 0.70) {
            prediction = "PHISHING";
            risk_level = "HIGH";
        } else if (mlProbability >= 0.40) {
            prediction = "SUSPICIOUS";
            risk_level = "MEDIUM";
        }

        // Log the scan to MySQL
        try {
            const [result] = await pool.execute(
                'INSERT INTO scan_logs (url, domain, prediction, probability) VALUES (?, ?, ?, ?)',
                [url, domain, prediction, mlProbability]
            );
            console.log(`Logged scan for ${domain}: ${prediction} (${(mlProbability * 100).toFixed(1)}%)`);
        } catch (error) {
            console.error('Database logging failed:', error);
        }

        // Return the payload to the Chrome extension
        res.json({
            is_phishing: prediction === "PHISHING",
            probability: mlProbability,
            risk_level: risk_level,
            status: prediction
        });

    } catch (error) {
        console.error("Error communicating with Python ML Service:", error);
        res.status(500).json({ error: "Machine Learning service is offline." });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`SafeURL API Gateway running on http://localhost:${PORT}`);
});