from flask import Flask, request, abort, jsonify
import hmac
import hashlib
import time
import os
import requests

app = Flask(__name__)

# Use environment variables for security (set these in Render dashboard)
SECRET = os.environ.get("SECRET").encode("utf-8")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL")

if not SECRET or not DISCORD_WEBHOOK_URL:
    raise ValueError("Missing SECRET or DISCORD_WEBHOOK_URL env vars")

@app.route("/bgsijoin", methods=["POST"])
def receive_hit():
    timestamp = request.headers.get("X-Timestamp")
    signature = request.headers.get("X-Signature")

    if not timestamp or not signature:
        abort(403, "Missing headers")

    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > 300:  # ±5 min window
            abort(403, "Timestamp expired/invalid")
    except:
        abort(403, "Bad timestamp")

    payload = request.get_data(as_text=True)
    message = f"{timestamp}.{payload}"
    expected = hmac.new(SECRET, message.encode("utf-8"), hashlib.sha256).hexdigest()

    if not hmac.compare_digest("v1=" + expected, signature):
        abort(403, "Invalid signature")

    # Forward to Discord
    try:
        resp = requests.post(
            DISCORD_WEBHOOK_URL,
            json=request.json,
            headers={"Content-Type": "application/json"}
        )
        resp.raise_for_status()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"status": "ok"}), 200

# For local testing only (Render uses Gunicorn)
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
