import logging
import importlib
from flask import Flask, request

app = Flask(__name__)
# VULNERABLE: INSECURE_CONFIG (Debug Mode)
DEBUG = True 

@app.route('/log')
def log_it():
    user_data = request.args.get('data')
    # VULNERABLE: LOG_INJECTION
    logging.info(f"User accessed the page with data: {user_data}")
    return "Logged"

@app.route('/reflect')
def reflect_it():
    module_name = request.args.get('module')
    # VULNERABLE: INSECURE_REFLECTION
    mod = importlib.import_module(module_name)
    return str(mod)

def process_user():
    email = "user@example.com"
    # VULNERABLE: PII_LEAKAGE
    print(f"Processing user with email: {email}")
