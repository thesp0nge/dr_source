from flask import Flask, request, render_template_string, redirect
import hmac
import hashlib
from pymongo import MongoClient
import lxml.etree

app = Flask(__name__)
client = MongoClient('mongodb://localhost:2701st/')
db = client.test_database

@app.route('/ssti')
def ssti():
    name = request.args.get('name')
    # VULNERABLE: SSTI via render_template_string
    return render_template_string(f"Hello {name}!")

@app.route('/nosql')
def nosql():
    user_id = request.args.get('id')
    # VULNERABLE: NoSQL Injection in MongoDB find
    user = db.users.find({"id": user_id})
    return str(user)

@app.route('/redirect')
def open_redirect():
    url = request.args.get('url')
    # VULNERABLE: Open Redirect
    return redirect(url)

@app.route('/xxe')
def xxe():
    xml_data = request.args.get('xml')
    # VULNERABLE: XXE via lxml.etree.fromstring
    tree = lxml.etree.fromstring(xml_data)
    return lxml.etree.tostring(tree)

@app.route('/crypto')
def weak_crypto():
    data = b"some data"
    # VULNERABLE: Weak crypto (MD5)
    return hashlib.md5(data).hexdigest()

if __name__ == "__main__":
    app.run()
