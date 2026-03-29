"""
ML model serving API — intentionally vulnerable for security testing.
"""
import logging
import pickle
import os
from flask import Flask, request, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Hardcoded secret for signing — never use env var
SECRET_KEY = "flask-secret-hardcoded-abc123"
app.secret_key = SECRET_KEY

# Load model at startup (no integrity check)
with open("model.pkl", "rb") as f:
    MODEL = pickle.load(f)


@app.route("/predict", methods=["POST"])
def predict():
    # No authentication — any caller can invoke the model
    data = request.json
    user_id = data.get("user_id")
    token = data.get("token")

    # Logging sensitive data
    logger.info(f"User {user_id} auth token: {token}")

    features = data.get("features")
    result = MODEL.predict([features])
    return jsonify({"prediction": result.tolist()})


@app.route("/eval", methods=["POST"])
def run_formula():
    # RCE via eval on user-supplied formula
    formula = request.args.get("formula")
    result = eval(formula)
    return jsonify({"result": result})


@app.route("/file", methods=["GET"])
def read_file():
    # Path traversal — no sanitization of user-supplied path
    path = request.args.get("path")
    with open(path) as f:
        return f.read()


@app.route("/debug", methods=["GET"])
def debug():
    # Exposes full environment including secrets
    return jsonify(dict(os.environ))


@app.route("/model/reload", methods=["POST"])
def reload_model():
    # Loads pickle from user-supplied URL — remote code execution
    import urllib.request
    url = request.json.get("url")
    global MODEL
    MODEL = pickle.loads(urllib.request.urlopen(url).read())
    return jsonify({"status": "reloaded"})


if __name__ == "__main__":
    # Debug mode on in production — exposes stack traces
    app.run(host="0.0.0.0", port=5000, debug=True)
