from flask import Flask, request
import sqlite3

app = Flask(__name__)

class User:
    def __init__(self):
        self.name = ""
        self.id = 0

@app.route('/test')
def test_field_sensitivity():
    user = User()
    user.name = request.args.get('name')
    user.id = 123 # Safe constant
    
    conn = sqlite3.connect('db.db')
    cursor = conn.cursor()

    # VULNERABLE: user.name is tainted
    cursor.execute("SELECT * FROM users WHERE name = '" + user.name + "'")

    # SAFE: user.id is a constant, should be ignored
    cursor.execute("SELECT * FROM users WHERE id = " + str(user.id))

    return "Done"
