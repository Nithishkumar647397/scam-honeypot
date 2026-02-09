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
    should_send_callback,
    delete_session,
    get_all_sessions
)
from src.detector import detect_scam
from src.extractor import extract_intelligence, merge_intelligence, extract_from_conversation
from src.agent import generate_agent_reply, generate_agent_notes
from src.callback import send_callback_async
from src.config import Config

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
app = Flask(__name__, template_folder=template_dir)


def _build_cors_response(data, status_code=200):
    """Helper to add CORS headers to every response"""
    response = make_response(jsonify(data), status_code)
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, x-api-key'
    response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
    return response


@app.route('/health', methods=['GET'])
def health_check():
    return _build_cors_response({"status": "healthy"}, 200)


def process_honeypot_request():
    """Core honeypot logic - EXTREMELY ROBUST VERSION"""
    # Step 1: Validate API key
    if not validate_api_key(request):
        key_in_args = request.args.get('key') or request.args.get('api_key') or request.args.get('x-api-key')
        if key_in_args != Config.API_SECRET_KEY:
            return _build_cors_response({"status": "error", "message": "Unauthorized"}, 401)
    
    # Step 2: Parse request body
    try:
        data = request.get_json(force=True, silent=True)
        if not data:
            try:
                data = json.loads(request.data)
            except:
                data = {}
        
        logger.info(f"[HONEYPOT] RAW DATA: {str(data)[:200]}...")
        
        if not data:
             return _build_cors_response({"status": "success", "reply": "Connection established."}, 200)

        session_id = data.get("sessionId") or data.get("session_id") or "default-session"
        metadata = data.get("metadata") or {}
        conversation_history = data.get("conversationHistory") or data.get("conversation_history") or []
        
        scammer_text = ""
        if "message" in data and isinstance(data["message"], dict):
            scammer_text = data["message"].get("text") or data["message"].get("content")
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
    
    # Step 3: Normal processing...
    try:
        session = get_session(session_id)
        if session is None:
            session = create_session(session_id)
        
        # Logic
        is_scam, confidence, indicators = detect_scam(scammer_text, conversation_history)
        
        # --- FIX 1: Extract from HISTORY + CURRENT message ---
        # This ensures we don't lose intel if session was wiped
        history_intel = extract_from_conversation(conversation_history)
        current_intel = extract_intelligence(scammer_text)
        combined_intel = merge_intelligence(history_intel, current_intel)
        
        session = update_session(
            session_id,
            scam_detected=is_scam or session.scam_detected,
            confidence=max(confidence, session.confidence),
            new_message={"sender": "scammer", "text": scammer_text},
            extracted_intelligence=combined_intel,
            indicators=indicators
        )
        
        reply = generate_agent_reply(
            current_message=scammer_text,
            conversation_history=session.conversation_history,
            scam_indicators=session.indicators,
            metadata=metadata
        )
        
        # Update message count by 2 (User + Agent)
        new_count = session.message_count + 2
        session = update_session(
            session_id,
            message_count=new_count,
            new_message={"sender": "user", "text": reply}
        )
        
        if should_send_callback(session):
            agent_notes = generate_agent_notes(
                conversation_history=session.conversation_history,
                scam_indicators=session.indicators,
                extracted_intelligence=session.extracted_intelligence,
                emails_found=session.extracted_intelligence.get("emails", [])
            )
            
            # --- FIX 2: Async Callback ---
            logger.info(f"Triggering ASYNC callback for session: {session_id}")
            send_callback_async(session, agent_notes)
        
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


# ============== DASHBOARD ROUTES ==============

@app.route('/dashboard', methods=['GET'])
def dashboard_page():
    return render_template('dashboard.html')


@app.route('/debug/dashboard', methods=['GET'])
def dashboard_data():
    if not validate_api_key(request):
        key_in_args = request.args.get('key') or request.args.get('x-api-key')
        if key_in_args != Config.API_SECRET_KEY:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    all_sessions = get_all_sessions()
    sessions_dict = {}
    for sid, session in all_sessions.items():
        sessions_dict[sid] = {
            "session_id": session.session_id,
            "message_count": session.message_count,
            "scam_detected": session.scam_detected,
            "confidence": session.confidence,
            "indicators": session.indicators,
            "extracted_intelligence": session.extracted_intelligence,
            "conversation_history": session.conversation_history[-10:], 
            "last_activity": str(session.last_activity)
        }
    
    return _build_cors_response({
        "status": "success",
        "count": len(sessions_dict),
        "sessions": sessions_dict
    })


@app.route('/chat', methods=['GET'])
def chat_page():
    return render_template('chat.html')


@app.route('/test', methods=['GET'])
def test_page():
    return render_template('test.html')


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
