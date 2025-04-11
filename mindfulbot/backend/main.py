import logging
import os
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
import firebase_admin
from firebase_admin import credentials, auth, firestore
from google.cloud import logging as google_logging
import google.generativeai as genai
from pydantic import BaseModel
from typing import List, Optional

# --- Configuration & Initialization ---

# Environment Variables (Replace with your actual keys and config)
# It's recommended to use a .env file or environment variables for production
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key") # Keep this secret!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# --- Firebase Setup ---
try:
    # Option 1: Use Application Default Credentials (ADC) - Recommended for Cloud Run/Functions
    # firebase_admin.initialize_app()

    # Option 2: Use a Service Account Key file (Ensure path is correct)
    cred_path = os.getenv("FIREBASE_SERVICE_ACCOUNT_KEY_PATH", "path/to/your/serviceAccountKey.json")
    if os.path.exists(cred_path):
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
    else:
        # Attempt ADC initialization if key path not found or specified
        print("Service account key not found at specified path, attempting ADC initialization.")
        firebase_admin.initialize_app()
        print("Initialized Firebase using Application Default Credentials.")

    db = firestore.client()
    print("Firebase initialized successfully.")
except Exception as e:
    print(f"Error initializing Firebase: {e}. Some features might not work.")
    db = None # Set db to None if initialization fails


# --- Google Cloud Logging Setup ---
try:
    logging_client = google_logging.Client()
    # Attaches a Google Cloud Logging handler to the root logger
    logging_client.setup_logging()
    logging.info("Google Cloud Logging initialized.")
except Exception as e:
    logging.warning(f"Could not initialize Google Cloud Logging: {e}")


# --- Gemini AI Setup ---
if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-pro') # Or the specific model you want
        logging.info("Gemini AI initialized.")
    except Exception as e:
        logging.error(f"Error initializing Gemini AI: {e}")
        model = None
else:
    logging.warning("GEMINI_API_KEY not set. AI features will be disabled.")
    model = None


# --- Security ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") # Points to the /token endpoint

# --- Pydantic Models ---
class User(BaseModel):
    username: str # Corresponds to email in Firebase Auth
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: Optional[str] = None # Firebase handles password hashing

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class ChatRequest(BaseModel):
    analysis_type: str # e.g., "Depression", "Anxiety"
    history: Optional[List[dict]] = [] # List of {"user": "yes/no", "model": "question"}

class ChatResponse(BaseModel):
    question: str
    history: List[dict]

# --- Utility Functions ---

def verify_password(plain_password, hashed_password):
    # In a real Firebase scenario, you'd verify the ID token, not a stored hash
    # This is a placeholder if you were managing users directly
    # For Firebase Auth, password verification happens during token exchange
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Verify the token using Firebase Admin SDK
        decoded_token = auth.verify_id_token(token)
        username = decoded_token.get("email") # Use email as username
        if username is None:
            logging.warning(f"Token verification succeeded but email not found in token: {decoded_token}")
            raise credentials_exception
        token_data = TokenData(username=username)
        # You could potentially check if the user exists in your Firestore DB here if needed
        # user = get_user_from_db(username) # Example function
        # if user is None:
        #     raise credentials_exception
    except (JWTError, auth.InvalidIdTokenError, auth.ExpiredIdTokenError, auth.RevokedIdTokenError) as e:
        logging.error(f"Token validation error: {e}")
        raise credentials_exception
    except Exception as e: # Catch other potential Firebase errors
        logging.error(f"An unexpected error occurred during token verification: {e}")
        raise credentials_exception

    # We don't have user object details like 'disabled' readily from verify_id_token
    # You might fetch user details from Firebase Auth or your DB if needed
    user = User(username=token_data.username, disabled=False) # Assuming not disabled
    # if user.disabled: # If you add a 'disabled' field in your user store
    #     raise HTTPException(status_code=400, detail="Inactive user")
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    # Already validated by get_current_user using Firebase token verification
    # The 'disabled' check is conceptual here unless implemented with Firestore
    if current_user.disabled:
         raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# --- FastAPI App Instance ---
app = FastAPI(title="MindfulBot Backend")

# --- API Endpoints ---

@app.post("/token", response_model=Token)
async def login_for_access_token(request: Request):
    # This endpoint now expects a Firebase ID Token in the Authorization header
    # It verifies the Firebase token and issues a *separate* JWT for session management if needed,
    # OR you could rely solely on the Firebase ID token passed from the frontend.
    # Let's simplify: Assume frontend sends Firebase ID token for *all* authenticated requests.
    # This /token endpoint might be less necessary if the frontend handles Firebase login
    # and just sends the ID token with each API call.

    # Alternative: Traditional username/password login (requires managing users outside Firebase Auth)
    # This requires form_data: OAuth2PasswordRequestForm = Depends()
    # ... find user in DB, verify password ...
    # For simplicity with Firebase, let's assume the frontend gets the ID token and sends it.
    # We'll make this endpoint primarily for demonstration or if you needed a secondary token system.

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    id_token = auth_header.split("Bearer ")[1]

    try:
        decoded_token = auth.verify_id_token(id_token)
        username = decoded_token.get("email")
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email not found in token")

        # Create *your* application's access token (optional, could just use Firebase ID token)
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": username}, expires_delta=access_token_expires
        )
        logging.info(f"Generated internal access token for user: {username}")
        return {"access_token": access_token, "token_type": "bearer"}

    except (auth.InvalidIdTokenError, auth.ExpiredIdTokenError, ValueError) as e:
        logging.error(f"Firebase ID token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Firebase token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logging.error(f"An unexpected error occurred during token exchange: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during token exchange",
        )


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    # This endpoint now uses the Firebase ID token verification via get_current_active_user
    logging.info(f"User details requested for: {current_user.username}")
    return current_user

@app.post("/chat", response_model=ChatResponse)
async def handle_chat(chat_request: ChatRequest, current_user: User = Depends(get_current_active_user)):
    if not model:
        logging.error("Gemini AI model not initialized. Cannot process chat request.")
        raise HTTPException(status_code=503, detail="AI Service Unavailable")
    if not db:
        logging.error("Firestore database not initialized. Cannot save chat history.")
        # Decide if you want to proceed without saving or raise an error
        # raise HTTPException(status_code=503, detail="Database Service Unavailable")

    user_email = current_user.username
    analysis_type = chat_request.analysis_type
    history = chat_request.history or [] # Ensure history is a list

    logging.info(f"Chat request received for user {user_email}, type: {analysis_type}")

    # Construct the prompt for Gemini
    prompt_parts = [
        f"You are MindfulBot, an AI assistant helping users explore feelings related to {analysis_type}.",
        "Ask simple, empathetic, yes/no questions one at a time to understand the user's state.",
        "Do not give advice or diagnosis. Keep questions concise.",
        "Based on the conversation history, ask the next relevant yes/no question.",
        "If the history is empty, ask an appropriate starting question for {analysis_type}.
",
        "Conversation History:"
    ]
    for turn in history:
        prompt_parts.append(f"User: {turn.get('user', 'N/A')}") # Use .get with default
        prompt_parts.append(f"MindfulBot: {turn.get('model', 'N/A')}") # Use .get with default

    prompt_parts.append("MindfulBot:") # Ask Gemini to generate the next question
    prompt = "
".join(prompt_parts)

    try:
        # --- Gemini Interaction ---
        response = model.generate_content(prompt)
        next_question = response.text.strip()
        logging.info(f"Generated question for {user_email}: {next_question}")

        # Append the new question to the history (without user answer yet)
        new_history_entry = {"model": next_question}
        history.append(new_history_entry) # This history will be sent back

        # --- Firestore Interaction (Optional but Recommended) ---
        if db:
            try:
                # Structure: users/{user_email}/chats/{analysis_type}_{timestamp}
                # Or maintain one document per analysis type per user, updating history array
                user_ref = db.collection('users').document(user_email)
                # Example: Store each full session
                # session_id = f"{analysis_type}_{datetime.now(timezone.utc).isoformat()}"
                # chat_ref = user_ref.collection('chats').document(session_id)
                # await chat_ref.set({"analysis_type": analysis_type, "history": history, "timestamp": firestore.SERVER_TIMESTAMP})

                # Example: Update a single document per analysis type with latest history
                analysis_doc_ref = user_ref.collection('analyses').document(analysis_type)
                # Use server timestamp for last update
                await analysis_doc_ref.set({"history": history, "last_updated": firestore.SERVER_TIMESTAMP}, merge=True)
                logging.info(f"Chat history saved for user {user_email}, type: {analysis_type}")

            except Exception as e:
                logging.error(f"Failed to save chat history to Firestore for user {user_email}: {e}")
                # Decide if this error should be surfaced to the user

        return ChatResponse(question=next_question, history=history)

    except Exception as e:
        logging.error(f"Error during Gemini generation or processing for user {user_email}: {e}")
        # Check for specific Gemini API errors if needed
        # if isinstance(e, GoogleAPICallError): # Example
        #    raise HTTPException(status_code=502, detail=f"AI service error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error during chat processing: {e}")


# --- Root Endpoint ---
@app.get("/")
async def root():
    logging.info("Root endpoint accessed.")
    return {"message": "Welcome to the MindfulBot Backend API"}

# --- Optional: Add user registration if not using Firebase UI ---
# @app.post("/register")
# async def register_user(user_data: UserCreate): # Define UserCreate model
#    # Check if user exists in Firebase Auth
#    try:
#        existing_user = auth.get_user_by_email(user_data.email)
#        raise HTTPException(status_code=400, detail="Email already registered")
#    except auth.UserNotFoundError:
#        # Create user in Firebase Authentication
#        try:
#            new_user = auth.create_user(
#                email=user_data.email,
#                password=user_data.password,
#                # Add display_name if needed
#            )
#            logging.info(f"User registered successfully: {new_user.email}")
#            # Optionally store additional user info in Firestore
#            if db:
#                user_ref = db.collection('users').document(new_user.email)
#                await user_ref.set({"registered_at": firestore.SERVER_TIMESTAMP, "email": new_user.email}) # Add other fields as needed
#            return {"message": "User created successfully", "uid": new_user.uid}
#        except Exception as e:
#            logging.error(f"Error creating user in Firebase Auth: {e}")
#            raise HTTPException(status_code=500, detail="Error creating user")


# --- Health Check Endpoint ---
@app.get("/health")
async def health_check():
    # Basic check, can be expanded (e.g., check DB connection)
    logging.info("Health check requested.")
    return {"status": "ok"}


# --- Uvicorn runner ---
# This part is usually not included directly in main.py but is useful for simple execution
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)

