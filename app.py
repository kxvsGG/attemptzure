from flask import Flask, request, abort
import time
import os
import requests

app = Flask(__name__)

SECRET = os.environ.get("SECRET", "").encode("utf-8")
PRIVATE_WEBHOOK = os.environ.get("PRIVATE_WEBHOOK")

if not SECRET or not PRIVATE_WEBHOOK:
    raise ValueError("Missing SECRET or PRIVATE_WEBHOOK env vars!")

def simple_hash(s):
    hash_val = 0
    for c in s.encode("utf-8"):
        hash_val = (hash_val * 31 + c) % 4294967296
    return f"{hash_val:08x}"

@app.route("/bgsijoin", methods=["POST"])
def receive_hit():
    timestamp = request.headers.get("X-Timestamp")
    signature = request.headers.get("X-Signature")
    target_code = request.headers.get("Target")   # "private", "dh", or "public"

    if not timestamp or not signature or not target_code:
        abort(403, "Missing headers")

    # Timestamp check (5 min window)
    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > 300:
            abort(403, "Timestamp expired")
    except:
        abort(403, "Invalid timestamp")

    payload_raw = request.get_data(as_text=True)
    message = payload_raw + timestamp
    expected_sig = simple_hash(SECRET.decode("utf-8") + message)

    if expected_sig != signature:
        abort(403, "Invalid signature")

    # Map short code → real URL
    if target_code == "private":
        forward_url = PRIVATE_WEBHOOK
    elif target_code == "dh":
        forward_url = "https://sentinelhook.lol/api.php?id=84G8pHk1nXxicwk"
    elif target_code == "public":
        forward_url = "https://sentinelhook.lol/api.php?id=Gc19GPjuqjxrrMQ"
    else:
        abort(400, "Invalid target")

    try:
        resp = requests.post(forward_url, data=payload_raw, headers={"Content-Type": "application/json"})
        resp.raise_for_status()
        return {"status": "ok"}, 200
    except Exception as e:
        return {"error": str(e)}, 502

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
