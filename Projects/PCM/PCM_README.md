
# PCM Ultra

PCM Ultra is a lightweight conversational reflection system designed to run locally on low‑resource hardware such as a Raspberry Pi.
It analyzes user input, detects emotional tone and behavioral patterns, and generates structured reflective responses that help users think more clearly about problems and decisions.

The system combines rule‑based reasoning, lightweight NLP techniques, and an optional local LLM to produce practical guidance without relying on cloud APIs.

---

# Overview

PCM Ultra is designed around three core goals:

• Run locally on low‑resource devices (e.g., Raspberry Pi 2‑4GB)  
• Provide structured psychological reflection instead of generic chat responses  
• Maintain conversation history for pattern detection and insights  

The assistant detects conversational modes, identifies recurring thinking patterns, and returns a structured response that includes:

Mirror – reflection of the user's statement  
Pattern – detected behavioral or thinking patterns  
Evidence – relevant past statements  
Questions – targeted reflection questions  
Next step – a practical 10‑minute action  
Follow‑up – guidance for continuing progress  

---

# Key Features

## Local‑First Design
Runs entirely on a local machine without external APIs.

## Raspberry Pi Optimized
The system is optimized for low memory environments (2GB+).

## Structured Responses
Instead of free‑form chat, responses follow a strict framework that promotes reflection and action.

## Pattern Detection
The system detects behavioral loops such as:

- avoidance
- perfectionism
- rumination
- conflict avoidance

## Context Awareness
Conversation history is stored in SQLite and used to detect patterns across sessions.

## Optional Local LLM
If a GGUF model is provided, the system can use a local LLM (via `llama-cpp-python`) to generate richer responses.

---

# Architecture

The project consists of five main components.

## 1. Flask Web Server
Handles the web interface and API endpoints.

## 2. Conversation Database
SQLite database storing users and message history.

Tables:
- users
- messages

## 3. PCM Brain
Core logic that analyzes user input.

Responsibilities:
- detect conversational mode
- detect behavior loops
- extract themes
- retrieve relevant message evidence
- build structured response packages

## 4. Response Writers

Two response writers exist:

### LLM Writer
Uses a local GGUF model through llama.cpp.

### Fallback Writer
A deterministic response generator that guarantees the system always responds even if the LLM fails.

## 5. Web UI
A lightweight HTML interface served directly from Flask.

---

# Conversation Modes

PCM detects three interaction modes.

Supportive Mode  
Triggered when emotional language is detected.

Direct Mode  
Triggered when the user expresses uncertainty or asks what to do.

Socratic Mode  
Triggered when the user asks for insight or analysis.

Each mode produces different reflection questions and action steps.

---

# Project Structure

```
pcm-ultra/
│
├── app.py
├── pcm.db
├── models/
│   └── qwen2.5-0.5b-instruct.gguf
│
└── README.md
```

---

# Installation

Clone the repository.

```
git clone https://github.com/yourusername/pcm-ultra
cd pcm-ultra
```

Create a Python virtual environment.

```
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies.

```
pip install flask scikit-learn numpy llama-cpp-python
```

---

# Running the Server

Start the application.

```
python app.py
```

Open the interface in a browser.

```
http://<raspberry-pi-ip>:8080
```

---

# Optional: Enable Local LLM

Set environment variables for the model.

Example:

```
export PCM_MODEL_PATH="/home/pi/models/qwen2.5-0.5b-instruct-q4_k_m.gguf"
export PCM_N_THREADS=4
export PCM_N_CTX=512
```

Then run the server again.

---

# Database

The SQLite database is automatically created at:

```
~/pcm_buddy/pcm.db
```

It stores:

Users  
Conversation history  
Session timestamps  

This allows the system to detect recurring patterns over time.

---

# Example Response

Mirror:
I keep putting off studying even though I know I need to.

Pattern:
Likely loop: avoidance

Evidence:
Earlier messages showed similar hesitation around starting tasks.

2 Questions:
1) What exactly makes starting the task difficult?
2) What would a 10‑minute version of the task look like?

Next step (10 min):
Set a 10‑minute timer and start the first page or concept.

Follow-up:
What time today will you do the next 10 minutes?

---

# Design Notes

The system was designed with reliability as the highest priority.

Important design principles:

• The assistant must never fail silently  
• If the LLM fails, fallback logic guarantees a response  
• Strict output formatting prevents model drift  
• Local memory enables long‑term pattern detection  

The project intentionally avoids heavy frameworks and cloud dependencies to keep it portable and efficient.

---

# Acknowledgements

This project was developed by **Nayef Alhunaiti**.

The architecture, behavioral logic, and system design were developed collaboratively with the assistance of **ChatGPT (OpenAI)**, which helped design:

- the PCM reflection framework
- loop detection logic
- structured response format
- LLM prompting strategy
- fallback response architecture
- UI interaction flow

ChatGPT served as a design and engineering assistant during the development of the system.

---

# Future Improvements

Possible future directions:

• Emotion classification models  
• Vector database for long‑term memory  
• Conversation summarization  
• Multi‑user analytics  
• Mobile interface  
• Voice interaction  

---

# License

MIT License

You are free to use, modify, and distribute this project.
