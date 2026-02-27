// advanced_logic_test.js
const express = require('express');
const app = express();

// 1. CONSTANT PROPAGATION TEST
app.get('/test', (req, res) => {
    const userInput = req.query.name;
    const safeBase = "<div>Hello ";
    const safeSuffix = "!</div>";
    
    // FALSE POSITIVE: Costruito solo con costanti (Dovrebbe essere ignorato)
    const safeHtml = safeBase + "Guest" + safeSuffix;
    document.getElementById('display').innerHTML = safeHtml;

    // VULNERABLE: Input utente diretto (Dovrebbe essere rilevato)
    document.getElementById('display').innerHTML = userInput;
});

// 2. BOOLEAN ENGINE TEST
// Regola ipotetica: Trova chiamate a 'eval' ma ignora se l'argomento è '1+1'
eval("2+2"); // Dovrebbe essere rilevato (se configurato)
eval("1+1"); // Dovrebbe essere ignorato (se configurato)

app.listen(3000);
