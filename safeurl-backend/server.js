require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');

const app = express();
app.use(cors());
app.use(express.json());

// Aiven MySQL connection pool with SSL support
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 27693,
    ssl: {
        rejectUnauthorized: false
    },
    waitForConnections: true,
    connectionLimit: 5,
    queueLimit: 0
});

function extractDomain(url) {
    try {
        const { hostname } = new URL(url.startsWith('http') ? url : 'http://' + url);
        return hostname;
    } catch (e) {
        return "unknown";
    }
}

app.get('/', (req, res) => {
    res.json({ status: "SafeURL Gateway Online" });
});

app.post('/predict', async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }

    const domain = extractDomain(url);

    try {
        const fetch = (await import('node-fetch')).default;
        
        const mlResponse = await fetch('https://safeurl-ml-api.onrender.com/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        if (!mlResponse.ok) {
            const errorText = await mlResponse.text();
            console.error(`Python ML service returned status ${mlResponse.status}:`, errorText);
            return res.status(502).json({ error: "ML service error", details: errorText });
        }

        const mlData = await mlResponse.json();
        const mlProbability = mlData.phishing_probability;

        let prediction = "LEGITIMATE";
        let risk_level = "LOW";

        if (mlProbability >= 0.70) {
            prediction = "PHISHING";
            risk_level = "HIGH";
        } else if (mlProbability >= 0.40) {
            prediction = "SUSPICIOUS";
            risk_level = "MEDIUM";
        }

        // Log to Aiven MySQL
        try {
            await pool.execute(
                'INSERT INTO scan_logs (url, domain, prediction, probability) VALUES (?, ?, ?, ?)',
                [url, domain, prediction, mlProbability]
            );
            console.log(`Logged scan for ${domain}: ${prediction} (${(mlProbability * 100).toFixed(1)}%)`);
        } catch (dbError) {
            console.error('Database logging failed:', dbError.message);
        }

        res.json({
            is_phishing: prediction === "PHISHING",
            probability: mlProbability,
            risk_level: risk_level,
            status: prediction
        });

    } catch (error) {
        console.error("Error communicating with Python ML Service:", error);
        res.status(500).json({ error: "Machine Learning service unavailable." });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`SafeURL API Gateway running on port ${PORT}`);
});