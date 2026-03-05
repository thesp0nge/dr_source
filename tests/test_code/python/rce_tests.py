import pickle
import yaml
import jinja2
from flask import Flask, request

app = Flask(__name__)

@app.route('/unpickle')
def unpickle():
    data = request.args.get('data')
    # VULNERABLE: INSECURE_DESERIALIZATION
    pickle.loads(data)
    return "Done"

@app.route('/yaml')
def load_yaml():
    data = request.args.get('config')
    # VULNERABLE: INSECURE_DESERIALIZATION (if not using SafeLoader)
    yaml.load(data)
    return "Loaded"

@app.route('/template')
def template():
    user_input = request.args.get('name')
    # VULNERABLE: SSTI
    template = jinja2.Environment().from_string("Hello " + user_input)
    return template.render()
