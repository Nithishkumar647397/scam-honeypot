# 🍯 Agentic Honey-Pot for Scam Detection & Intelligence Extraction
### GUVI | HCL Hackathon 2026 - Problem Statement 2

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-lightgrey?style=for-the-badge&logo=flask)
![Groq](https://img.shields.io/badge/AI-Groq%20LLM-orange?style=for-the-badge)
![Render](https://img.shields.io/badge/Deployment-Render-purple?style=for-the-badge&logo=render)

## 📜 Project Overview

Traditional scam prevention systems simply block suspicious messages. **This solution fights back.**

The **Agentic Honey-Pot** is an autonomous AI system that detects scam intent and engages scammers in a multi-turn conversation. By adopting the persona of a gullible elderly victim ("Mrs. Kamala Devi"), the system keeps scammers engaged to:
1.  **Waste their time** (preventing them from targeting real victims).
2.  **Extract actionable intelligence** (UPI IDs, bank accounts, phone numbers).
3.  **Report findings** to authorities via a secure callback.

---

## ✨ Key Features

### 🧠 Intelligent Agent
*   **Persona:** "Mrs. Kamala Devi," a 67-year-old retired teacher who is tech-unsavvy but polite.
*   **Adaptive Language:** Automatically switches between **English**, **Hindi**, and **Hinglish** based on the scammer's language style.
*   **Conversation Phases:** Progresses through `Initial` -> `Trust Building` -> `Information Gathering` -> `Extraction`.

### 🕵️‍♂️ Advanced Detection & Extraction
*   **Scam Classification:** Identifies 8 types of scams (Bank Fraud, Lottery, KYC, etc.) with severity scoring.
*   **Smart Extraction:** Captures UPI IDs, Bank Accounts, IFSC codes, Phone numbers, and Phishing Links.
*   **Obfuscation Handling:** Decodes disguised numbers (e.g., *"nine eight seven..."* → `987`) and symbols (*"paytm at ybl"* → `paytm@ybl`).

### 🛡️ Enterprise-Grade Security
*   **Input Sanitization:** Prevents prompt injection attacks against the LLM.
*   **Thread Safety:** Handles concurrent requests safely.
*   **Robust Parsing:** "Fail-open" architecture ensures the API never crashes on malformed inputs.

---

## 🛠️ Tech Stack

*   **Language:** Python 3.10+
*   **Framework:** Flask (Gunicorn for production)
*   **AI Model:** Llama-3-8b via Groq API (High speed, low latency)
*   **Data Handling:** Regex + NLP patterns
*   **Deployment:** Render Cloud

---

## 🚀 Live Demo

**API Endpoint:**
