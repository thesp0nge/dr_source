const crypto = require('crypto');

function insecureHash(data) {
    // VULNERABLE: WEAK_CRYPTO
    return crypto.createHash('md5').update(data).digest('hex');
}

function safeHash(data) {
    // SAFE
    return crypto.createHash('sha256').update(data).digest('hex');
}
