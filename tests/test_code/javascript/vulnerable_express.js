const express = require("express");
const app = express();

app.get("/exec", (req, res) => {
  const cmd = req.query.command; // Taint Source

  // Taint Sink - Vulnerability here
  eval(cmd); // Line 8

  res.send("Done");
});

// Safe method
app.get("/safe", (req, res) => {
  const data = req.query.data;
  console.log(data);
  res.send("Safe");
});
