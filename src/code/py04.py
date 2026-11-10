import base64
import pickle

from flask import Flask, jsonify, make_response, request

app = Flask(__name__)
DEFAULT_PREFS = {"theme": "light", "lang": "en", "page_size": 25}


def load_prefs():
    raw = request.cookies.get("prefs")
    if not raw:
        return dict(DEFAULT_PREFS)
    try:
        prefs = pickle.loads(base64.b64decode(raw))  # @@VULN@@
    except Exception:
        return dict(DEFAULT_PREFS)
    if not isinstance(prefs, dict):
        return dict(DEFAULT_PREFS)
    return prefs


def save_prefs(resp, prefs):
    encoded = base64.b64encode(pickle.dumps(prefs)).decode()
    resp.set_cookie("prefs", encoded, httponly=True, samesite="Lax")


@app.route("/prefs", methods=["GET"])
def get_prefs():
    return jsonify(load_prefs())


@app.route("/prefs", methods=["POST"])
def set_prefs():
    prefs = load_prefs()
    body = request.get_json(silent=True) or {}
    for key in ("theme", "lang", "page_size"):
        if key in body:
            prefs[key] = body[key]
    resp = make_response(jsonify(prefs))
    save_prefs(resp, prefs)
    return resp
