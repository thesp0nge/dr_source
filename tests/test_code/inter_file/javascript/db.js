// File 1: db.js
const cp = require('child_process');

function runCommand(command) {
    // Now it matches "child_process.exec" or "cp.exec" logic
    // Our visitor handles the suffix "exec" anyway
    cp.exec(command);
}

module.exports = { runCommand };
