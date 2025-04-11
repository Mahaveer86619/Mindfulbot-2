import os
import logging
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import requests
from dotenv import load_dotenv
from google.cloud import logging as google_logging

# --- Configuration & Initialization ---
load_dotenv() # Load environment variables from .env file if it exists

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your-flask-secret-key") # Change this for production!

# --- Google Cloud Logging Setup ---
try:
    logging_client = google_logging.Client()
    # Attaches a Google Cloud Logging handler to the root logger
    logging_client.setup_logging()
    logging.info("Google Cloud Logging initialized for Flask.")
except Exception as e:
    logging.warning(f"Could not initialize Google Cloud Logging for Flask: {e}")


# --- Backend API Configuration ---
BACKEND_API_URL = os.getenv("BACKEND_API_URL", "http://localhost:8000") # Adjust if your backend runs elsewhere

# --- Helper Functions ---

def get_auth_header():
    """Retrieves the Firebase ID token from the session for backend requests."""
    token = session.get('firebase_id_token')
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}

# --- Routes ---

@app.route('/')
def index():
    """Redirects to login if not authenticated, otherwise to analysis selection."""
    if 'user_email' in session and 'firebase_id_token' in session:
        logging.info(f"User {session['user_email']} already logged in, redirecting to select.")
        return redirect(url_for('select_analysis'))
    logging.info("No active session, redirecting to login.")
    return redirect(url_for('login'))

@app.route('/login')
def login():
    """Renders the login page."""
    # Check if already logged in, redirect if so
    if 'user_email' in session and 'firebase_id_token' in session:
        return redirect(url_for('select_analysis'))
    # The actual Firebase login happens on the client-side (see login.html)
    logging.info("Rendering login page.")
    firebase_config = {
        'apiKey': os.getenv("FIREBASE_API_KEY"),
        'authDomain': os.getenv("FIREBASE_AUTH_DOMAIN"),
        'projectId': os.getenv("FIREBASE_PROJECT_ID"),
        'storageBucket': os.getenv("FIREBASE_STORAGE_BUCKET"),
        'messagingSenderId': os.getenv("FIREBASE_MESSAGING_SENDER_ID"),
        'appId': os.getenv("FIREBASE_APP_ID")
    }
    # Filter out None values before sending to template
    firebase_config_filtered = {k: v for k, v in firebase_config.items() if v is not None}
    if len(firebase_config_filtered) < 6:
        logging.error("Firebase configuration is incomplete. Check environment variables.")
        # Optionally render an error page or message
        return "Error: Firebase configuration is incomplete.", 500

    return render_template('login.html', firebase_config=firebase_config_filtered)


@app.route('/auth_success', methods=['POST'])
def auth_success():
    """Endpoint called by client-side JS after successful Firebase login."""
    data = request.json
    id_token = data.get('idToken')
    email = data.get('email')
    # display_name = data.get('displayName') # Optional

    if not id_token or not email:
        logging.warning("Incomplete auth data received.")
        return jsonify({"error": "Missing token or email"}), 400

    # Store token and user info in server-side session
    session['firebase_id_token'] = id_token
    session['user_email'] = email
    # session['user_name'] = display_name
    session.permanent = True # Make session last longer (configure lifetime in Flask app config if needed)
    logging.info(f"User {email} successfully authenticated. Session created.")

    return jsonify({"status": "success", "redirect_url": url_for('select_analysis')})

@app.route('/logout')
def logout():
    """Clears the session and redirects to login."""
    user_email = session.get('user_email', 'Unknown user')
    session.pop('firebase_id_token', None)
    session.pop('user_email', None)
    # session.pop('user_name', None)
    session.clear() # Ensure everything is cleared
    logging.info(f"User {user_email} logged out. Session cleared.")
    return redirect(url_for('login'))

@app.route('/select')
def select_analysis():
    """Displays the analysis selection page. Requires authentication."""
    if 'user_email' not in session or 'firebase_id_token' not in session:
        logging.warning("Unauthorized access attempt to /select.")
        return redirect(url_for('login'))

    user_email = session.get('user_email')
    logging.info(f"Rendering analysis selection page for user {user_email}.")
    analysis_types = ["Depression", "Anxiety", "OCD", "Stress"] # Define available types
    return render_template('select_analysis.html', analysis_types=analysis_types, user_email=user_email)

@app.route('/chat/<analysis_type>')
def chat(analysis_type):
    """Renders the chat interface for a specific analysis type. Requires authentication."""
    if 'user_email' not in session or 'firebase_id_token' not in session:
        logging.warning(f"Unauthorized access attempt to /chat/{analysis_type}.")
        return redirect(url_for('login'))

    user_email = session.get('user_email')
    logging.info(f"Rendering chat page for user {user_email}, type: {analysis_type}.")

    # We'll fetch the *first* question from the backend when the page loads.
    # Subsequent questions will be handled via JavaScript calling /api/chat.
    headers = get_auth_header()
    if not headers:
        logging.error(f"Missing auth token for initial chat request. User: {user_email}")
        return redirect(url_for('logout')) # Force re-login if token missing

    initial_payload = {
        "analysis_type": analysis_type,
        "history": [] # Start with empty history
    }

    try:
        response = requests.post(f"{BACKEND_API_URL}/chat", json=initial_payload, headers=headers, timeout=15)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        chat_data = response.json()
        initial_question = chat_data.get("question")
        initial_history = chat_data.get("history", [])

        if not initial_question:
             logging.error(f"Backend did not return an initial question for {analysis_type}. Response: {chat_data}")
             # Handle error - maybe redirect back to selection with a message
             return redirect(url_for('select_analysis', error="Could not start chat"))

        logging.info(f"Initial question for {analysis_type} received: {initial_question}")
        return render_template('chat.html',
                               analysis_type=analysis_type,
                               initial_question=initial_question,
                               initial_history=initial_history, # Send history in case backend modifies it
                               user_email=user_email)

    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to get initial question from backend for {analysis_type}. User: {user_email}. Error: {e}")
        # Handle network or backend errors
        return redirect(url_for('select_analysis', error="Could not connect to chat service"))
    except Exception as e:
        logging.error(f"An unexpected error occurred loading the chat page for {analysis_type}. User: {user_email}. Error: {e}")
        return redirect(url_for('select_analysis', error="An internal error occurred"))


# --- API Endpoint (called by chat.html's JavaScript) ---

@app.route('/api/chat', methods=['POST'])
def api_chat():
    """Handles chat interaction requests from the client-side JavaScript."""
    if 'user_email' not in session or 'firebase_id_token' not in session:
        logging.warning("Unauthorized access attempt to /api/chat.")
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    analysis_type = data.get('analysis_type')
    history = data.get('history')
    user_response = data.get('response') # User's 'yes' or 'no'

    if not analysis_type or history is None or not user_response:
        logging.warning(f"Invalid payload received at /api/chat: {data}")
        return jsonify({"error": "Missing required data"}), 400

    # --- Prepare data for the backend ---
    # Add the user's latest response to the last entry in the history
    if history:
        if 'model' in history[-1] and 'user' not in history[-1]:
             history[-1]['user'] = user_response
        else:
             # This case shouldn't normally happen if frontend logic is correct
             logging.warning(f"Unexpected history format before adding user response: {history}")
             # Decide how to handle: append new entry or modify last?
             # Let's append defensively, though it might slightly confuse the AI
             history.append({'user': user_response})

    else:
         # Should not happen if initial question was fetched correctly
         logging.error("Received chat API request with empty history, but user provided a response.")
         history = [{'user': user_response}] # Try to recover


    backend_payload = {
        "analysis_type": analysis_type,
        "history": history
    }
    headers = get_auth_header()
    if not headers:
         logging.error(f"Missing auth token for API chat request. User: {session['user_email']}")
         return jsonify({"error": "Authentication token missing"}), 401

    logging.info(f"Forwarding chat request to backend for {session['user_email']}, type: {analysis_type}")

    # --- Call Backend API ---
    try:
        response = requests.post(f"{BACKEND_API_URL}/chat", json=backend_payload, headers=headers, timeout=15)
        response.raise_for_status()

        backend_response_data = response.json()
        next_question = backend_response_data.get("question")
        updated_history = backend_response_data.get("history")

        if not next_question or updated_history is None:
             logging.error(f"Backend response missing question or history. Response: {backend_response_data}")
             return jsonify({"error": "Invalid response from chat service"}), 502 # Bad Gateway

        logging.info(f"Received next question from backend for {session['user_email']}: {next_question}")
        return jsonify({
            "question": next_question,
            "history": updated_history
        })

    except requests.exceptions.Timeout:
        logging.error(f"Timeout calling backend API /chat for user {session['user_email']}.")
        return jsonify({"error": "Chat service timed out"}), 504 # Gateway Timeout
    except requests.exceptions.ConnectionError:
        logging.error(f"Connection error calling backend API /chat for user {session['user_email']}.")
        return jsonify({"error": "Could not connect to chat service"}), 503 # Service Unavailable
    except requests.exceptions.HTTPError as e:
         status_code = e.response.status_code
         error_detail = e.response.text
         logging.error(f"Backend API returned error ({status_code}) for user {session['user_email']}: {error_detail}")
         # Forward appropriate status code if possible
         forwarded_status = status_code if status_code >= 400 and status_code < 600 else 500
         return jsonify({"error": f"Chat service error: {error_detail}"}), forwarded_status
    except Exception as e:
        logging.error(f"An unexpected error occurred in /api/chat for user {session['user_email']}: {e}")
        return jsonify({"error": "An internal server error occurred"}), 500


# --- Run the app ---
if __name__ == '__main__':
    # Use debug=True only for development
    app.run(debug=True, port=5000) # Port 5000 for Flask frontend by default
