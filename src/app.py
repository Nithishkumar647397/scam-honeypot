"""
Flask application - Main API endpoint
Owner: Member B
"""

import os
import json
import logging
from flask import Flask, request, jsonify, render_template, make_response

from src.auth import validate_api_key
from src.session import (
    get_session,
    create_session,
    update_session,
    should_send_callback
)
from src.detector import detect_scam
from src.extractor import extract_intelligence
from src.agent import generate_agent_reply, generate_agent_notes
from src.callback import send_final_callback
from src.config import Config

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
app = Flask(__name__, template_folder=template_dir)


def _build_cors_response(data, status_code=200):
    response = make_response(jsonify(data), status_code)
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, x-api-key'
    response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
    return response


@app.route('/health', methods=['GET'])
def health_check():
    return _build_cors_response({"status": "healthy"}, 200)


def process_honeypot_request():
    """Core honeypot logic"""
    # 1. Auth (Strict header check)
    if not validate_api_key(request):
        return _build_cors_response({"status": "error", "message": "Unauthorized"}, 401)
    
    # 2. Parse
    try:
        data = request.get_json(force=True, silent=True)
        if not data:
            try:
                data = json.loads(request.data)
            except ValueError:
                data = {}
        
        logger.info(f"[HONEYPOT] RAW DATA: {str(data)[:200]}...")
        
        if not data:
             return _build_cors_response({"status": "success", "reply": "Connection established."}, 200)

        # Extract fields
        session_id = data.get("sessionId") or data.get("session_id") or "default-session"
        metadata = data.get("metadata") or {}
        conversation_history = data.get("conversationHistory") or []
        
        scammer_text = ""
        sender = "scammer"
        timestamp = None

        if "message" in data and isinstance(data["message"], dict):
            scammer_text = data["message"].get("text") or data["message"].get("content")
            sender = data["message"].get("sender", "scammer")
            timestamp = data["message"].get("timestamp")
        elif "message" in data and isinstance(data["message"], str):
            scammer_text = data["message"]
        elif "text" in data:
            scammer_text = data["text"]
        elif "content" in data:
            scammer_text = data["content"]
            
        if not scammer_text:
            scammer_text = "Hello"
            
    except Exception as e:
        logger.error(f"[HONEYPOT] Parse error: {e}")
        return _build_cors_response({"status": "success", "reply": "System online."}, 200)
    
    # 3. Process
    try:
        session = get_session(session_id)
        if session is None:
            session = create_session(session_id)
        
        # Logic
        is_scam, confidence, indicators = detect_scam(scammer_text, conversation_history)
        current_intel = extract_intelligence(scammer_text)
        
        # Update session ONCE with scammer message
        session = update_session(
            session_id,
            scam_detected=is_scam or session.scam_detected,
            confidence=max(confidence, session.confidence),
            new_message={"sender": sender, "text": scammer_text, "timestamp": timestamp},
            extracted_intelligence=current_intel,
            indicators=indicators
        )
        
        # Generate reply (Pass metadata)
        reply = generate_agent_reply(
            current_message=scammer_text,
            conversation_history=session.conversation_history,
            scam_indicators=session.indicators,
            metadata=metadata
        )
        
        # Update session with agent reply AND increment count by 2
        # (1 for scammer + 1 for agent = accurate totalMessagesExchanged)
        new_count = session.message_count + 2
        session = update_session(
            session_id,
            message_count=new_count,
            new_message={"sender": "user", "text": reply}
        )
        
        # Callback check
        if should_send_callback(session):
            agent_notes = generate_agent_notes(
                conversation_history=session.conversation_history,
                scam_indicators=session.indicators,
                extracted_intelligence=session.extracted_intelligence,
                emails_found=session.extracted_intelligence.get("emails", [])
            )
            send_final_callback(session, agent_notes)
        
        return _build_cors_response({
            "status": "success",
            "reply": reply,
            "message": reply
        }, 200)
        
    except Exception as e:
        logger.error(f"[HONEYPOT] Processing Error: {e}", exc_info=True)
        return _build_cors_response({
            "status": "success",
            "reply": "I am having trouble understanding."
        }, 200)


@app.route('/', methods=['GET', 'POST', 'OPTIONS'])
def home():
    if request.method == 'OPTIONS':
        return _build_cors_response({})
    if request.method == 'POST':
        return process_honeypot_request()
    return _build_cors_response({"status": "running", "service": "Scam Honeypot API"})


@app.route('/honeypot', methods=['POST', 'OPTIONS'])
def honeypot_endpoint():
    if request.method == 'OPTIONS':
        return _build_cors_response({})
    return process_honeypot_request()


@app.route('/test', methods=['GET'])
def test_page():
    return render_template('test.html')


@app.route('/chat', methods=['GET'])
def chat_page():
    return render_template('chat.html')


@app.route('/debug/session/<session_id>', methods=['GET'])
def debug_session(session_id):
    if not validate_api_key(request):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    session = get_session(session_id)
    if session is None:
        return jsonify({"status": "error", "message": "Session not found"}), 404
    
    return jsonify({
        "status": "success",
        "session": {
            "session_id": session.session_id,
            "message_count": session.message_count,
            "scam_detected": session.scam_detected,
            "confidence": session.confidence,
            "indicators": session.indicators,
            "extracted_intelligence": session.extracted_intelligence,
            "conversation_history": session.conversation_history
        }
    }), 200


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"[ERROR] 500: {error}")
    return _build_cors_response({"status": "error", "message": "Internal Server Error"}, 500)


@app.errorhandler(404)
def not_found(error):
    return _build_cors_response({"status": "error", "message": "Endpoint not found"}, 404)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
