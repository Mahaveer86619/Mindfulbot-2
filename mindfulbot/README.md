# MindfulBot

A Sentiment Analysis Chat Application using FastAPI, Flask, Firebase, and Gemini AI.

## Project Structure

- `backend/`: FastAPI application (API, authentication, Gemini integration)
- `frontend/`: Flask application (SSR frontend, user interface)
- `README.md`: This file
- `.gitignore`: Git ignore file

## Setup

1.  **Backend:**
    ```bash
    cd backend
    pip install -r requirements.txt
    # Configure Firebase Admin SDK (add serviceAccountKey.json)
    # Set environment variables (e.g., FIREBASE_CONFIG, GEMINI_API_KEY)
    uvicorn main:app --reload
    ```

2.  **Frontend:**
    ```bash
    cd frontend
    pip install -r requirements.txt
    # Set environment variables (e.g., BACKEND_URL)
    flask run
    ```

## Description

MindfulBot helps users assess their mental well-being (Depression, Anxiety, OCD, Stress) through a conversational interface. Users authenticate, choose an analysis type, and answer yes/no questions generated dynamically by the Gemini AI based on the chosen topic. The frontend is server-side rendered using Flask, and the backend API is built with FastAPI.
