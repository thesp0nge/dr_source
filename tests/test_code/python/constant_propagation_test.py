from flask import Flask, request
import sqlite3

app = Flask(__name__)

def get_db_connection():
    return sqlite3.connect('database.db')

@app.route('/test')
def test_sql():
    user_id = request.args.get('id')
    conn = get_db_connection()
    cursor = conn.cursor()

    # VULNERABLE: Input utente diretto nel sink
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)

    # FALSE POSITIVE (Now ignored by Constant Propagation):
    # Query costruita solo con costanti
    table = "logs"
    safe_query = "SELECT * FROM " + table
    cursor.execute(safe_query)

    # ANOTHER SAFE CALL:
    cursor.execute("SELECT name FROM roles")

    return "Done"

if __name__ == "__main__":
    app.run()
