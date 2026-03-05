const ejs = require('ejs');
const express = require('express');
const app = express();

app.get('/render', (req, res) => {
    const userTemplate = req.query.template;
    // VULNERABLE: SSTI
    const html = ejs.render(userTemplate, { name: 'User' });
    res.send(html);
});
