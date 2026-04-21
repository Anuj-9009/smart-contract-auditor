# 📖 Smart Contract Auditor AI — Complete User Guide

Welcome to the **Smart Contract Auditor AI**. This application allows you to paste Solidity smart contracts and instantly receive a comprehensive security audit detailing vulnerabilities, severity ratings, and actionable fixes.

---

## 📑 Table of Contents
1. [How It Works](#1-how-it-works)
2. [Getting Started (Running Locally)](#2-getting-started-running-locally)
3. [Using the Application](#3-using-the-application)
4. [Unlocking AI Analysis (Zero-Cost LLM)](#4-unlocking-ai-analysis-zero-cost-llm)
5. [Understanding the Dashboard](#5-understanding-the-dashboard)

---

## 1. How It Works
The auditor utilizes a **two-layer detection engine**:
*   **Layer 1: Pattern Analyzer (Always On):** A lightning-fast, rule-based engine that uses regular expressions to instantly detect the 8 most critical vulnerability types (e.g., Reentrancy via `.call{value:}`, unprotected `selfdestruct`). It works entirely offline without any AI APIs.
*   **Layer 2: LLM Engine (Optional but Recommended):** Uses advanced AI models (like local Ollama, Groq, or Claude) to read your code like a human security researcher. This catches complex logical flaws, off-by-one errors, and subtle DeFi exploits that pattern-matching misses.

---

## 2. Getting Started (Running Locally)

If you haven't started the servers yet, open your terminal and run these commands:

### Start the Backend (Terminal 1)
```bash
cd smart-contract-auditor/backend
source venv/bin/activate
python main.py
```
*(Runs on http://localhost:8000)*

### Start the Frontend (Terminal 2)
```bash
cd smart-contract-auditor/frontend
npm run dev
```
*(Runs on http://localhost:5173)*

Now, open your web browser and go to **[http://localhost:5173](http://localhost:5173)**.

---

## 3. Using the Application

### Method A: Testing with Built-in Samples (Easiest)
1. On the right side of the screen, ensure the **⚡ SAMPLES** tab is selected.
2. Click on any of the pre-loaded contracts (e.g., **"Reentrancy"** or **"Access Control"**).
3. The vulnerable Solidity code will populate the editor on the left.
4. Click the purple **"Run Audit"** button.
5. Scroll down to view the detected vulnerabilities and your Risk Score.

### Method B: Auditing Your Own Code
1. Click the **"Clear"** button located just below the code editor to empty the textarea.
2. Paste your custom Solidity (`.sol`) code into the editor.
3. Click **"Run Audit"**.
4. The engine will process the code and generate a full security report.

---

## 4. Unlocking AI Analysis (Zero-Cost LLM)

By default, the application runs in "Pattern-Only" mode. To get the best results, you should enable the AI. We built this with a "Zero-Dollar Architecture," meaning you don't have to pay for expensive APIs like OpenAI if you don't want to.

### Option 1: Use Groq (Cloud — Blazing Fast & Free)
*Best if you have an older computer or don't want to download large files.*
1. Go to [console.groq.com/keys](https://console.groq.com/keys) and create a free account.
2. Generate an API Key (it starts with `gsk_`).
3. Open the `backend/.env` file in your project folder.
4. Find `GROQ_API_KEY=` and paste your key there: `GROQ_API_KEY=gsk_your_actual_key_here`
5. **Restart your backend server** in the terminal (Press `Ctrl+C`, then run `python main.py` again).

### Option 2: Use Ollama (Local — 100% Private & Free)
*Best for maximum privacy; your code never leaves your computer.*
1. Download and install [Ollama](https://ollama.com/).
2. Open a terminal and run: `ollama pull qwen2.5-coder` (this downloads a ~4GB coding model).
3. Leave Ollama running in the background. 
4. The Smart Contract Auditor will automatically detect it on `localhost:11434` and use it for audits.

---

## 5. Understanding the Dashboard

When an audit finishes, you will see a detailed dashboard:

*   **Risk Score (0-100):** A weighted score calculating the overall danger of deploying the contract. 
    *   **0-24:** Low Risk (Safe)
    *   **25-49:** Medium Risk
    *   **50-74:** High Risk
    *   **75-100:** Critical Risk (Do NOT deploy)
*   **Vulnerability Cards:** Displayed in a staggered masonry layout. Each card features:
    *   **Glowing Border:** Red for Critical, Orange for High, Yellow for Medium, Green for Low.
    *   **Location:** The exact line number (`ln: 16`) where the flaw was found.
    *   **Confidence:** The engine's certainty (`95% conf`) that this is a true vulnerability, helping to filter out false positives.
    *   **Fix Recommendation:** A green highlighted box explaining exactly how to patch the code (e.g., "Use OpenZeppelin's ReentrancyGuard").
*   **History Tab:** Located on the right sidebar. Click this to view past audits you've run, making it easy to track your progress as you fix your code.
