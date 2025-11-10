import os
from flask import Flask, request  # We import these so the AST can parse them
import subprocess

app = Flask(__name__)


@app.route("/run")
def run_command():
    # 1. Taint Source
    # We'll get this from our Knowledge Base
    command = request.args.get("cmd")

    # 2. Taint Sink
    # We'll get this from our Knowledge Base
    os.system(command)  # Vulnerability on line 15

    return "ok"


@app.route("/run2")
def run_command_safe():
    # This is safe, no taint
    command = "ls -l"
    os.system(command)

    return "ok"
