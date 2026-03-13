from flask import Flask, request, abort
import time
import os
import requests

app = Flask(__name__)

# ←←← MUST match exactly what you put in the Roblox script
SECRET = os.environ.get("SECRET", "k9FvT3xQ7mL2Zr8Pw6YdH1sU4aJcN5Bq0EoR7tVxM2uK9iC4yGfD8Wl3S6pAhZ1n")

def simple_hash(s):
    hash_val = 0
    for c in s.encode("utf-8"):
        hash_val = (hash_val * 31 + c) % 4294967296
    return f"{hash_val:08x}"

@app.route("/bgsijoin", methods=["POST"])
def receive_hit():
    timestamp = request.headers.get("X-Timestamp")
    signature = request.headers.get("X-Signature")
    target_webhook = request.headers.get("DiscUser")   # ← this is what your script sends

    if not timestamp or not signature or not target_webhook:
        abort(403, "Missing required headers")

    # Timestamp check (5 min window)
    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > 300:
            abort(403, "Timestamp expired")
    except:
        abort(403, "Invalid timestamp")

    payload_raw = request.get_data(as_text=True)
    message = payload_raw + timestamp
    expected_sig = simple_hash(SECRET + message)

    if expected_sig != signature:
        abort(403, "Invalid signature")

    # Forward to the real webhook (Discord or sentinelhook)
    try:
        resp = requests.post(
            target_webhook,
            data=payload_raw,
            headers={"Content-Type": "application/json"}
        )
        resp.raise_for_status()
        return {"status": "ok"}, 200
    except Exception as e:
        return {"error": str(e)}, 502

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
