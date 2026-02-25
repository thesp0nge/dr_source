// File 2: app.js
const express = require('express');
const { runCommand } = require('./db');
const app = express();

app.get('/run', (req, res) => {
    const cmd = req.query.cmd;
    
    // Cross-file taint flow
    runCommand(cmd);
    res.send('Executed');
});
