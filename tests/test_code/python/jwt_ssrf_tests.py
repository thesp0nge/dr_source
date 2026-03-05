import httpx
import jwt
from flask import Flask, request

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    # VULNERABLE: SSRF via httpx
    return httpx.get(url).text

@app.route('/auth')
def auth():
    token = request.headers.get('Authorization')
    # VULNERABLE: INSECURE_JWT (verify=False)
    payload = jwt.decode(token, verify=False)
    
    # VULNERABLE: INSECURE_JWT (none algorithm allowed)
    payload2 = jwt.decode(token, algorithms=['none', 'HS256'])
    return str(payload)
