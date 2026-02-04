"""
Flask application - Main API endpoint
Owner: Member B
"""
from flask import Flask, request, jsonify, render_template
from flask import Flask, request, jsonify
from src.auth import validate_api_key
from src.session import (
    get_session,
    create_session,
    update_session,
    should_send_callback,
    delete_session
)
from src.detector import detect_scam
from src.extractor import extract_intelligence, merge_intelligence
from src.agent import generate_agent_reply, generate_agent_notes
from src.callback import send_final_callback
from src.config import Config

import os
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
app = Flask(__name__, template_folder=template_dir)


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Render"""
    return jsonify({"status": "healthy"}), 200
@app.route('/chat', methods=['GET'])
def chat_page():
    """WhatsApp-style chat interface for testing"""
    return render_template('chat.html')

@app.route('/', methods=['GET'])
def home():
    """Home endpoint"""
    return jsonify({
        "status": "running",
        "service": "Scam Honeypot API",
        "endpoints": {
            "health": "/health",
            "honeypot": "/honeypot (POST)"
        }
    }), 200

@app.route('/test', methods=['GET'])
def test_page():
    """Test webpage for manual testing"""
    return render_template('test.html')

@app.route('/honeypot', methods=['POST'])
def honeypot_endpoint():
    """
    Main honeypot API endpoint
    
    Request format:
        {
            "sessionId": "...",
            "message": {"sender": "scammer", "text": "...", "timestamp": ...},
            "conversationHistory": [...],
            "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
        }
    
    Response format:
        {
            "status": "success",
            "reply": "Agent's response..."
        }
    """
    
    # Step 1: Validate API key
    if not validate_api_key(request):
        return jsonify({
            "status": "error",
            "message": "Unauthorized: Invalid or missing API key"
        }), 401
    
    # Step 2: Parse request body
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "status": "error",
                "message": "Bad Request: No JSON body provided"
            }), 400
        
        # Extract required fields
        session_id = data.get("sessionId")
        message = data.get("message", {})
        conversation_history = data.get("conversationHistory", [])
        metadata = data.get("metadata", {})
        
        # Validate required fields
        if not session_id:
            return jsonify({
                "status": "error",
                "message": "Bad Request: sessionId is required"
            }), 400
        
        if not message or not message.get("text"):
            return jsonify({
                "status": "error",
                "message": "Bad Request: message.text is required"
            }), 400
        
        scammer_text = message.get("text", "")
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Bad Request: Invalid JSON - {str(e)}"
        }), 400
    
    # Step 3: Get or create session
    session = get_session(session_id)
    if session is None:
        session = create_session(session_id)
    
    # Step 4: Detect scam
    is_scam, confidence, indicators = detect_scam(scammer_text, conversation_history)
    
    # Step 5: Extract intelligence from current message
    current_intel = extract_intelligence(scammer_text)
    
    # Step 6: Update session with scammer message
    session = update_session(
        session_id,
        message_count=session.message_count + 1,
        scam_detected=is_scam or session.scam_detected,
        confidence=max(confidence, session.confidence),
        new_message={"sender": "scammer", "text": scammer_text},
        extracted_intelligence=current_intel,
        indicators=indicators
    )
    
    # Step 7: Generate agent reply
    reply = generate_agent_reply(
        current_message=scammer_text,
        conversation_history=session.conversation_history,
        scam_indicators=session.indicators
    )
    
    # Step 8: Update session with agent reply
    session = update_session(
        session_id,
        message_count=session.message_count + 1,
        new_message={"sender": "user", "text": reply}
    )
    
    # Step 9: Check if should send callback
    if should_send_callback(session):
        # Generate agent notes
        agent_notes = generate_agent_notes(
            conversation_history=session.conversation_history,
            scam_indicators=session.indicators,
            extracted_intelligence=session.extracted_intelligence
        )
        
        # Send callback to GUVI
        callback_success = send_final_callback(session, agent_notes)
        
        if callback_success:
            print(f"[HONEYPOT] Callback sent for session {session_id}")
        
        # Don't delete session immediately - keep for potential follow-up
    
    # Step 10: Return response
    return jsonify({
        "status": "success",
        "reply": reply
    }), 200


@app.route('/debug/session/<session_id>', methods=['GET'])
def debug_session(session_id):
    """Debug endpoint to view session data (remove in production)"""
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
    """Handle internal server errors"""
    return jsonify({
        "status": "error",
        "message": "Internal Server Error"
    }), 500


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        "status": "error",
        "message": "Endpoint not found"
    }), 404


if __name__ == '__main__':
    print("="*50)
    print("SCAM HONEYPOT API STARTING")
    print("="*50)
    print(f"GROQ API Key Set: {bool(Config.GROQ_API_KEY)}")
    print(f"API Secret Key Set: {bool(Config.API_SECRET_KEY)}")
    print("="*50)
    app.run(debug=True, host='0.0.0.0', port=5000)
