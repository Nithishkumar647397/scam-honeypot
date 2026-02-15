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
    get_session, create_session, update_session, 
    should_send_callback, delete_session, get_all_sessions
)
from src.detector import detect_scam, check_abuse
from src.extractor import extract_intelligence, merge_intelligence, extract_from_conversation
from src.agent import generate_agent_reply, generate_agent_notes
from src.callback import send_callback_async
from src.config import Config

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
    if not validate_api_key(request):
        key = request.args.get('key') or request.args.get('x-api-key')
        if key != Config.API_SECRET_KEY:
            return _build_cors_response({"status": "error", "message": "Unauthorized"}, 401)
    
    try:
        data = request.get_json(force=True, silent=True) or {}
        if not data and request.data:
            try: data = json.loads(request.data)
            except: pass
        
        logger.info(f"[HONEYPOT] RAW DATA: {str(data)[:200]}...")
        if not data: return _build_cors_response({"status": "success", "reply": "Connection established."}, 200)

        session_id = data.get("sessionId") or data.get("session_id") or "default-session"
        metadata = data.get("metadata") or {}
        conversation_history = data.get("conversationHistory") or []
        
        scammer_text = ""
        if "message" in data and isinstance(data["message"], dict):
            scammer_text = data["message"].get("text")
        elif "message" in data and isinstance(data["message"], str):
            scammer_text = data["message"]
        elif "text" in data:
            scammer_text = data["text"]
            
        if not scammer_text: scammer_text = "Hello"
            
    except Exception as e:
        logger.error(f"[HONEYPOT] Parse error: {e}")
        return _build_cors_response({"status": "success", "reply": "System online."}, 200)
    
    try:
        # Check for abuse (Priority 3)
        abuse_check = check_abuse(scammer_text)
        if abuse_check["abusive"]:
            logger.warning(f"Abuse detected in session {session_id}: {abuse_check['matched']}")
            return _build_cors_response({
                "status": "success",
                "reply": ""  # Disengage silently
            }, 200)

        session = get_session(session_id)
        if session is None: session = create_session(session_id)
        
        # Detect scam with modifiers
        is_scam, confidence, indicators, modifiers = detect_scam(scammer_text, conversation_history)
        
        history_intel = extract_from_conversation(conversation_history)
        current_intel = extract_intelligence(scammer_text)
        combined_intel = merge_intelligence(history_intel, current_intel)
        
        true_message_count = len(conversation_history) + 2
        
        session = update_session(
            session_id,
            scam_detected=is_scam or session.scam_detected,
            confidence=max(confidence, session.confidence),
            new_message={"sender": "scammer", "text": scammer_text},
            extracted_intelligence=combined_intel,
            indicators=indicators,
            message_count=true_message_count
        )
        
        reply = generate_agent_reply(
            current_message=scammer_text,
            conversation_history=session.conversation_history,
            scam_indicators=session.indicators,
            metadata=metadata
        )
        
        update_session(session_id, new_message={"sender": "user", "text": reply})
        
        if should_send_callback(session):
            agent_notes = generate_agent_notes(
                conversation_history=session.conversation_history,
                scam_indicators=session.indicators,
                extracted_intelligence=session.extracted_intelligence,
                emails_found=session.extracted_intelligence.get("emails", [])
            )
            logger.info(f"Triggering ASYNC callback for session: {session_id}")
            send_callback_async(session, agent_notes)
        
        return _build_cors_response({
            "status": "success",
            "reply": reply,
            "message": reply
        }, 200)
        
    except Exception as e:
        logger.error(f"[HONEYPOT] Processing Error: {e}", exc_info=True)
        return _build_cors_response({"status": "success", "reply": "I am having trouble understanding."}, 200)

@app.route('/', methods=['GET', 'POST', 'OPTIONS'])
def home():
    if request.method == 'OPTIONS': return _build_cors_response({})
    if request.method == 'POST': return process_honeypot_request()
    return _build_cors_response({"status": "running", "service": "Scam Honeypot API"})

@app.route('/honeypot', methods=['POST', 'OPTIONS'])
def honeypot_endpoint():
    if request.method == 'OPTIONS': return _build_cors_response({})
    return process_honeypot_request()

@app.route('/dashboard', methods=['GET'])
def dashboard_page(): return render_template('dashboard.html')

@app.route('/debug/dashboard', methods=['GET'])
def dashboard_data():
    if not validate_api_key(request): return jsonify({"status": "error", "message": "Unauthorized"}), 401
    all_sessions = get_all_sessions()
    sessions_dict = {sid: {
        "session_id": s.session_id,
        "message_count": s.message_count,
        "scam_detected": s.scam_detected,
        "confidence": s.confidence,
        "indicators": s.indicators,
        "extracted_intelligence": s.extracted_intelligence,
        "conversation_history": s.conversation_history[-10:],
        "last_activity": str(s.last_activity)
    } for sid, s in all_sessions.items()}
    return _build_cors_response({"status": "success", "count": len(sessions_dict), "sessions": sessions_dict})

@app.route('/chat', methods=['GET'])
def chat_page(): return render_template('chat.html')

@app.route('/test', methods=['GET'])
def test_page(): return render_template('test.html')

@app.route('/debug/session/<session_id>', methods=['GET'])
def debug_session(session_id):
    if not validate_api_key(request): return jsonify({"status": "error", "message": "Unauthorized"}), 401
    session = get_session(session_id)
    if not session: return jsonify({"status": "error", "message": "Not found"}), 404
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
def internal_error(error): return _build_cors_response({"status": "error", "message": "Internal Server Error"}, 500)

@app.errorhandler(404)
def not_found(error): return _build_cors_response({"status": "error", "message": "Endpoint not found"}, 404)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
