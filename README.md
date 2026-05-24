<!-- Header Block -->
<div align="center">
  <br />
  <!-- Glowing Cyberpunk Animated Banner (Pure Vector CSS SVG) -->
  <svg width="100%" height="160" viewBox="0 0 800 160" fill="none" xmlns="http://www.w3.org/2000/svg" style="background: #09090b; border-radius: 24px; border: 1px solid rgba(239, 68, 68, 0.15);">
    <style>
      .text-title {
        font-family: 'Sora', 'Inter', system-ui, -apple-system, sans-serif;
        font-weight: 800;
        font-size: 42px;
        fill: url(#cyberGradient);
        filter: drop-shadow(0px 10px 15px rgba(239, 68, 68, 0.3));
      }
      .text-subtitle {
        font-family: 'Inter', system-ui, sans-serif;
        font-weight: 500;
        font-size: 14px;
        fill: #a1a1aa;
        letter-spacing: 0.2em;
      }
      .glow-core {
        animation: floatCore 6s ease-in-out infinite alternate;
      }
      @keyframes floatCore {
        0% { transform: translate(0px, 0px) scale(1); filter: blur(25px); opacity: 0.35; }
        100% { transform: translate(-20px, 10px) scale(1.1); filter: blur(35px); opacity: 0.55; }
      }
    </style>
    <!-- Background Neon Blobs -->
    <circle class="glow-core" cx="250" cy="80" r="60" fill="#dc2626" />
    <circle class="glow-core" cx="550" cy="80" r="50" fill="#f59e0b" style="animation-delay: -3s;" />
    
    <!-- Title Text -->
    <text x="50%" y="80" dominant-baseline="middle" text-anchor="middle" class="text-title">CONTRACT AUDITOR AI</text>
    <text x="50%" y="120" dominant-baseline="middle" text-anchor="middle" class="text-subtitle">ZERO-API COST SOLIDITY SECURITY ENGINE</text>
    
    <defs>
      <linearGradient id="cyberGradient" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="#ef4444" />
        <stop offset="50%" stop-color="#f59e0b" />
        <stop offset="100%" stop-color="#ef4444" />
      </linearGradient>
    </defs>
  </svg>

  <p>
    <br />
    <img src="https://img.shields.io/badge/Python-3.9+-ef4444?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
    <img src="https://img.shields.io/badge/FastAPI-0.104+-f59e0b?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
    <img src="https://img.shields.io/badge/React-18+-ef4444?style=for-the-badge&logo=react&logoColor=black" alt="React" />
    <img src="https://img.shields.io/badge/Ollama-Local--LLM-f59e0b?style=for-the-badge&logo=ollama&logoColor=white" alt="Ollama" />
  </p>
  
  <p>
    A highly-polished, AI-powered security analysis tool for Solidity smart contracts. Built entirely on a <b>Zero-Dollar Architecture</b> using free-tier cloud databases and local privacy-preserving LLMs.
  </p>
</div>

<hr style="border: 0; height: 1px; background-image: linear-gradient(to right, rgba(239, 68, 68, 0), rgba(239, 68, 68, 0.4), rgba(239, 68, 68, 0));" />

<!-- Cyber Audit Scanner Visual (Pure HTML/CSS SVG) -->
<div align="center">
  <h3>🛡️ Active Static Audit Scanner</h3>
  <br />
  <svg width="640" height="150" viewBox="0 0 640 150" fill="none" xmlns="http://www.w3.org/2000/svg" style="background: #09090b; border-radius: 20px; border: 1px solid rgba(239,68,68,0.25); box-shadow: 0 10px 30px rgba(239,68,68,0.15);">
    <style>
      .scanner-beam {
        animation: scanSweep 3s infinite ease-in-out alternate;
      }
      .code-line {
        font-family: 'Fira Code', monospace;
        font-size: 11px;
        fill: #52525b;
      }
      .vuln-glow {
        animation: pulseVuln 1.5s infinite alternate ease-in-out;
      }
      @keyframes scanSweep {
        0% { y: 20; opacity: 0.2; }
        50% { opacity: 0.85; }
        100% { y: 130; opacity: 0.2; }
      }
      @keyframes pulseVuln {
        0% { fill: #7f1d1d; stroke: #ef4444; filter: drop-shadow(0 0 2px #ef4444); }
        100% { fill: #ef4444; stroke: #f87171; filter: drop-shadow(0 0 10px #ef4444); }
      }
    </style>
    
    <!-- Code Mock Background -->
    <text x="40" y="35" class="code-line">01: contract SecurityScanner {</text>
    <text x="40" y="55" class="code-line">02:     function transferFunds(address payable to) public {</text>
    <text x="40" y="75" class="code-line" style="fill: #f87171; font-weight: bold;">03:         to.call{value: address(this).balance}(""); // &lt;-- REENTRANCY ATTACK</text>
    <text x="40" y="95" class="code-line">04:         balances[msg.sender] = 0;</text>
    <text x="40" y="115" class="code-line">05:     }</text>

    <!-- Scan Line -->
    <rect class="scanner-beam" x="30" y="20" width="580" height="2" fill="#ef4444" filter="drop-shadow(0 0 4px #ef4444)" />
    
    <!-- Vulnerability Found Circle -->
    <circle class="vuln-glow" cx="500" cy="72" r="8" stroke-width="2" />
    <text x="515" y="76" font-family="'Sora', sans-serif" font-weight="bold" font-size="9px" fill="#ef4444">CRITICAL VULN</text>
  </svg>
</div>

<br />

---

## ✨ The Zero-Dollar Architecture

This project was engineered to deliver premium AI auditing without the massive API costs typically associated with LLM applications.

* **LLM Engine**: Runs locally via **[Ollama](https://ollama.com/)** (`qwen2.5-coder` or `llama3`) for absolute zero cost and total privacy. Falls back to **Groq**'s generous free tier for cloud inference if local hardware is insufficient.
* **Database**: Powered by **[Supabase](https://supabase.com/)**'s free tier (PostgreSQL), providing a robust cloud database without hosting fees. Includes a local SQLite fallback for complete offline capability.
* **Backend**: **FastAPI**, designed to be deployed for free on platforms like Render or Railway.
* **Frontend**: **React + Vite** with Tailwind CSS v4, optimized for static hosting on Vercel or Netlify.

---

## 🎨 UI/UX Aesthetic

We rejected standard, generic SaaS templates in favor of a curated, high-contrast visual experience:
* **Minimal Cyberpunk**: Deep, clinical off-black backgrounds (`#09090b` void).
* **Glassmorphism**: Semi-transparent dark cards with backdrop blurs and subtle 1px borders.
* **Pinterest Masonry**: Results are displayed in a staggered, dynamic masonry grid rather than a boring vertical table.
* **Neon Semantics**: High-contrast, glowing accents dictate severity (e.g., glowing electric red for 'Critical', neon amber for 'Medium').

---

## 🚀 Quick Start Guide

### 1. Backend Setup (FastAPI)
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Copy environment template
cp .env.example .env
```

### 2. Configure Zero-Cost LLM (Ollama)
Download and install [Ollama](https://ollama.com/), then pull the required model in a separate terminal:
```bash
ollama pull qwen2.5-coder
```
*The FastAPI backend will automatically detect Ollama running on `http://localhost:11434`.*

### 3. Start Backend Server
```bash
python main.py
```
*Server runs at `http://localhost:8000` (API docs at `/docs`)*

### 4. Frontend Setup (React/Vite)
Open a new terminal window:
```bash
cd frontend
npm install
npm run dev
```
*Frontend runs at `http://localhost:5173`*

---

## 🗄️ Supabase SQL Schema

If you choose to use the free Supabase tier instead of the local SQLite fallback, run this SQL in your Supabase project's SQL Editor:

```sql
-- Create Audit Jobs Table
CREATE TABLE public.audit_jobs (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    contract_name TEXT DEFAULT 'Unknown',
    contract_code TEXT NOT NULL,
    status TEXT DEFAULT 'processing',
    risk_score INTEGER DEFAULT 0,
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- Create Vulnerabilities Table
CREATE TABLE public.vulnerabilities (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    audit_job_id BIGINT REFERENCES public.audit_jobs(id) ON DELETE CASCADE,
    vulnerability_type TEXT,
    severity TEXT,
    line_number INTEGER,
    description TEXT,
    suggested_fix TEXT,
    confidence_score INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);
```

Once executed, add your `SUPABASE_URL` and `SUPABASE_ANON_KEY` to the `backend/.env` file.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center" style="background: radial-gradient(circle, rgba(239,68,68,0.08) 0%, transparent 80%); padding: 24px; border-radius: 16px;">
  <p style="font-family: 'Sora', sans-serif; font-size: 13px; font-weight: 600; color: #ef4444; margin: 0;">
    built by anuj with love and nicotine
  </p>
</div>
