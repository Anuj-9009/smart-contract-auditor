# Smart Contract Auditor 🛡️🔍

<p>
  <img src="https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-0.104+-green?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-18+-blue?style=for-the-badge&logo=react&logoColor=white" alt="React" />
  <img src="https://img.shields.io/badge/Ollama-Local%20LLM-orange?style=for-the-badge" alt="Ollama" />
</p>

Smart Contract Auditor is a highly-polished, AI-powered security analysis tool designed specifically for Solidity smart contracts. Operating on a **Zero-Dollar Architecture** by utilizing local privacy-preserving LLMs and free-tier cloud databases, it identifies critical vulnerabilities, evaluates contract integrity, and delivers full-stack auditing reports in real-time.

---

## ✨ Features

- **🔍 AST Vulnerability Sweeper:** Combines rule-based Static Analysis with deep abstract syntax tree (AST) scans to detect common vulnerability anti-patterns (such as reentrancy, timestamp dependencies, reentrancy vectors, and integer overflows).
- **🤖 Private Local AI Audit:** Interfaces with `Ollama` (`codellama` or `llama3`) running locally, keeping your smart contract intellectual property 100% private and eliminating cloud API costs.
- **🗄️ SQL Supabase Database:** Manages and persists projects, audit records, and history tables using standard Supabase PostgreSQL integrations with active Row-Level Security (RLS) protections.
- **🎨 Glassmorphic Interface Workspace:** An incredibly responsive React 18 frontend displaying contract editors, vulnerability highlights, and dynamic real-time audit progress meters.

---

## 🧠 AST Solidity Scans & Security Checks

The auditor incorporates multi-layered static auditing routines:
1. **Solidity Parser Engine:**
   - Translates Solidity files into an Abstract Syntax Tree (AST).
   - Traverses standard node branches to identify dangerous patterns like `tx.origin` authorization, low-level calls without checks (`.call{value: ...}`), and raw assembly blocks.
2. **Local AI Auditor Verification:**
   - Feeds code fragments to your private local Ollama instance with specialized system instructions.
   - Enforces a strictly validated JSON output schema detailing the isolated lines, severity rating (Critical, High, Medium, Low), attack vector description, and suggested remediations.

---

## 🚀 Quick Start Guide

### Prerequisites
- **Python** 3.9+
- **Node.js** 18+
- **Ollama** installed locally (with `codellama` or `llama3` model downloaded)
- A free **Supabase** database instance (or a local PostgreSQL container)

### 1. Backend Service Setup (FastAPI)

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Install python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Setup environment variables (`.env`):
   ```properties
   SUPABASE_URL=your_supabase_url
   SUPABASE_KEY=your_supabase_anon_key
   OLLAMA_HOST=http://localhost:11434
   ```

4. Start the backend application:
   ```bash
   uvicorn main:app --reload --port 8000
   ```

### 2. Frontend Application Setup (React Vite)

1. Navigate to the frontend directory:
   ```bash
   cd ../frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environmental values (`.env`):
   ```properties
   VITE_API_URL=http://localhost:8000
   ```

4. Run the Vite development server:
   ```bash
   npm run dev
   ```

---

<div align="center" style="margin-top: 40px;">
  <img src="assets/footer-v2.svg" width="100%" alt="footer">
</div>
<p style="font-family: 'Sora', sans-serif; font-size: 13px; font-weight: 600; color: #ef4444; margin: 0; text-align: center;">
  built by ANUJ with ❤️ to the raw frequencies of kendrick lamar's 'HUMBLE.'
</p>
