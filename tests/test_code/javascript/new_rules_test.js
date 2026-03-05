// Node.js test case
const express = require('express');
const app = express();

app.get('/log', (req, res) => {
    const id = req.query.id;
    // VULNERABLE: LOG_INJECTION
    console.log("User requested ID: " + id);
    res.send("ID logged");
});

function leakPII() {
    const cc = "1234-5678-9012-3456";
    // VULNERABLE: PII_LEAKAGE
    console.log("Processing credit card: " + cc);
}
