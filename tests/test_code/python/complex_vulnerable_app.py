import os
from flask import Flask, request
import sqlite3  # Mock DB

app = Flask(__name__)
db = sqlite3.connect(":memory:")


@app.route("/user")
def get_user():
    # VULNERABILITY 1: SQLi via f-string
    # Taint Source
    user_id = request.args.get("id")

    # Taint Sink (This is an ast.JoinedStr)
    db.cursor().execute(f"SELECT * FROM users WHERE id = {user_id}")  # Line 16

    # SAFE CODE (for comparison)
    db.cursor().execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return "User"


@app.route("/host")
def ping_host():
    # VULNERABILITY 2: Command Injection via BinOp
    # Taint Source
    hostname = request.args.get("host")

    # Taint Propagation (This is an ast.BinOp)
    # Your current visitor will MISS this.
    command = "ping -c 1 " + hostname

    # Taint Sink
    os.system(command)  # Line 30

    # SAFE CODE (for comparison)
    os.system("ls -l")
    return "Host"
