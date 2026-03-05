const axios = require('axios');
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

app.get('/fetch', (req, res) => {
    const target = req.query.url;
    // VULNERABLE: SSRF via axios
    axios.get(target).then(response => res.send(response.data));
});

app.post('/verify', (req, res) => {
    const token = req.body.token;
    // VULNERABLE: INSECURE_JWT (none algorithm)
    jwt.verify(token, secret, { algorithms: ['none', 'HS256'] }, (err, decoded) => {
        res.send(decoded);
    });
});
