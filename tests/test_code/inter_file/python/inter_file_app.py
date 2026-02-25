# File 2: source_app.py
from flask import request
from inter_file_utils import vulnerable_execute

def main_route():
    user_input = request.args.get("cmd")
    
    # This call should be flagged by the inter-file analysis
    vulnerable_execute(user_input)
