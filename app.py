from flask import Flask, request, abort, jsonify
import hmac
import hashlib
import time
import os
import requests  # to forward to Discord

app = Flask(__name__)

# CHANGE THESE TWO
SECRET = b"your-very-long-random-secret-here-at-least-64-chars-change-this-now!!!"  # same as in your Lua script
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"  # your real _G.webhook_url

@app.route("/bgsijoin", methods=["POST"])  # keep same path as before, or change to whatever
def receive_hit():
    timestamp = request.headers.get("X-Timestamp")
    signature = request.headers.get("X-Signature")

    if not timestamp or not signature:
        abort(403, "Missing headers")

    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > 300:  # allow ±5 minutes
            abort(403, "Timestamp expired or invalid")
    except:
        abort(403, "Bad timestamp")

    # Get raw body (important for accurate HMAC)
    payload = request.get_data(as_text=True)

    # Recompute expected signature (same as Lua side)
    message = f"{timestamp}.{payload}"
    expected = hmac.new(SECRET, message.encode("utf-8"), hashlib.sha256).hexdigest()

    # Secure compare (prevents timing attacks)
    if not hmac.compare_digest("v1=" + expected, signature):
        abort(403, "Invalid signature")

    # Valid! Forward to your Discord webhook
    try:
        resp = requests.post(
            DISCORD_WEBHOOK_URL,
            json=request.json,  # the original embed/payload
            headers={"Content-Type": "application/json"}
        )
        resp.raise_for_status()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)