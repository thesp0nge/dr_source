const express = require('express');
const app = express();

app.post('/update', (req, res) => {
    const config = {};
    const key = req.body.key; // e.g. "__proto__.isAdmin"
    const value = req.body.value;
    
    // VULNERABLE: PROTOTYPE_POLLUTION (Dynamic access)
    config[key] = value;
    
    res.send("Config updated");
});

function insecureToken() {
    // VULNERABLE: INSECURE_TOKEN_GENERATION
    const token = Math.random().toString(36).substring(7);
    return token;
}
