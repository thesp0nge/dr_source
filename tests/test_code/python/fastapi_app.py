from fastapi import FastAPI, Depends
import sqlite3

app = FastAPI()

@app.get("/search")
def search(query: str):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # VULNERABLE: 'query' is a FastAPI parameter (source)
    cursor.execute("SELECT * FROM products WHERE name = '" + query + "'")
    return {"results": []}

@app.get("/safe")
def safe(id: int):
    # SAFE: id is not used in a sink
    return {"id": id}

@app.post("/update")
async def update_item(name: str, description: str = None):
    conn = sqlite3.connect('database.db')
    # VULNERABLE: 'name' is a source
    conn.execute(f"UPDATE items SET desc = '...' WHERE name = '{name}'")
    return {"status": "ok"}
