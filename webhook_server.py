from flask import Flask, request, jsonify
import json
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/webhook', methods=['POST'])
def webhook():
    """
    Receives callback data from the honeypot API and logs it.
    """
    try:
        # specific force=True to handle cases where Content-Type might be missing
        data = request.get_json(force=True, silent=True)
        
        if not data and request.data:
            try:
                data = json.loads(request.data)
            except Exception:
                data = {"raw_body": str(request.data)}

        print("\n" + "⬇" * 20 + " WEBHOOK RECEIVED " + "⬇" * 20)
        print(json.dumps(data, indent=2))
        print("⬆" * 20 + " END PAYLOAD " + "⬆" * 20 + "\n")

        return jsonify({"status": "success", "message": "Callback received"}), 200

    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    print(f"🚀 Mock Webhook Server running on port 9999...")
    print(f"👉 Local URL: http://localhost:9999/webhook")
    app.run(host='0.0.0.0', port=9999, debug=True)