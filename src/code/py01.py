import sqlite3

from flask import Flask, g, jsonify, request

app = Flask(__name__)
DB_PATH = "inventory.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/items")
def list_items():
    category = request.args.get("category", "")
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
    except ValueError:
        return jsonify(error="bad limit"), 400
    rows = get_db().execute(
        f"SELECT id, name, price FROM items WHERE category = '{category}' LIMIT ?", (limit,)  # @@VULN@@
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/items/<int:item_id>")
def get_item(item_id):
    row = get_db().execute(
        "SELECT id, name, price, stock FROM items WHERE id = ?", (item_id,)
    ).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(dict(row))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
