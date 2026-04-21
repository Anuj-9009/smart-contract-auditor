"""
Smart Contract Audit Engine — Zero-Cost LLM Stack
Supports: Ollama (local), Groq (free tier), Claude, OpenAI
Falls back to pattern-based analysis when no LLM is available.
"""
import json
import re
import os
import requests
from typing import Dict, List
from datetime import datetime, timezone

from .prompt_templates import SYSTEM_PROMPT, QUICK_SCAN_PROMPT, GAS_OPTIMIZATION_PROMPT


# ═══════════════════════════════════════════════════════════════════════════════
#  Pattern Analyzer — Zero-cost, instant, rule-based detection
# ═══════════════════════════════════════════════════════════════════════════════

class PatternAnalyzer:
    """Rule-based pattern analyzer. Always runs. Zero cost."""

    VULNERABILITY_PATTERNS = [
        {
            "pattern": r"\.call\{value:",
            "type": "reentrancy",
            "severity": "critical",
            "description": "External call via .call{value:} detected. If state is updated after this call, a reentrancy attack is possible — the called contract can re-enter this function before state changes take effect.",
            "fix": "Apply the Checks-Effects-Interactions pattern: update all state variables before making external calls. Use OpenZeppelin's ReentrancyGuard modifier.",
            "confidence": 85,
        },
        {
            "pattern": r"tx\.origin",
            "type": "tx_origin_auth",
            "severity": "high",
            "description": "tx.origin used for authentication. This is vulnerable to phishing: a malicious contract can trick a user into calling it, then relay the call to your contract with the victim's tx.origin.",
            "fix": "Replace tx.origin with msg.sender for all authentication checks.",
            "confidence": 95,
        },
        {
            "pattern": r"selfdestruct\(",
            "type": "unprotected_selfdestruct",
            "severity": "critical",
            "description": "selfdestruct found. If not restricted to the owner, anyone can destroy the contract permanently and steal remaining ETH.",
            "fix": "Add strict access control (onlyOwner modifier). Consider removing selfdestruct entirely — it's deprecated in newer EVM versions.",
            "confidence": 80,
        },
        {
            "pattern": r"block\.timestamp",
            "type": "timestamp_dependency",
            "severity": "medium",
            "description": "block.timestamp used in logic. Miners can manipulate this value within a ~15 second window, making it unreliable for time-critical operations or randomness.",
            "fix": "Use block.number for relative timing. For randomness, use Chainlink VRF. Never use block.timestamp as a sole condition for fund transfers.",
            "confidence": 70,
        },
        {
            "pattern": r"delegatecall\(",
            "type": "delegatecall_risk",
            "severity": "high",
            "description": "delegatecall executes external code in this contract's storage context. If the target is untrusted or upgradeable, it can overwrite storage slots and drain funds.",
            "fix": "Only delegatecall to trusted, immutable contracts. Use EIP-1967 proxy pattern with proper storage layout management.",
            "confidence": 75,
        },
        {
            "pattern": r"pragma solidity \^",
            "type": "floating_pragma",
            "severity": "low",
            "description": "Floating pragma (^) allows compilation with different compiler versions, potentially introducing subtle bugs across deployments.",
            "fix": "Lock the pragma: use 'pragma solidity 0.8.19;' instead of 'pragma solidity ^0.8.0;'",
            "confidence": 95,
        },
        {
            "pattern": r"\.send\(",
            "type": "unchecked_send",
            "severity": "high",
            "description": "send() returns false on failure instead of reverting. If the return value is not checked, failed ETH transfers are silently ignored.",
            "fix": "Use call{value:}() with a require check, or use transfer() which auto-reverts. Always check return values.",
            "confidence": 90,
        },
        {
            "pattern": r"assembly\s*\{",
            "type": "inline_assembly",
            "severity": "medium",
            "description": "Inline assembly bypasses Solidity's type system and safety checks. Memory corruption, stack manipulation errors, and gas miscalculations are common.",
            "fix": "Avoid inline assembly unless absolutely necessary for gas optimization. When used, add extensive testing and formal verification.",
            "confidence": 60,
        },
    ]

    SAFE_PATTERNS = [
        "ReentrancyGuard", "nonReentrant", "onlyOwner",
        "Ownable", "AccessControl", "SafeMath", "SafeERC20",
    ]

    def analyze(self, code: str) -> List[Dict]:
        vulnerabilities = []
        lines = code.split("\n")

        for pattern_def in self.VULNERABILITY_PATTERNS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern_def["pattern"], line):
                    # Skip if protected by safe patterns
                    if pattern_def["type"] == "reentrancy":
                        if "nonReentrant" in code or "ReentrancyGuard" in code:
                            continue
                        remaining = "\n".join(lines[i:])
                        if not re.search(r"=\s*0|=\s*false|\-=|\+=", remaining[:200]):
                            continue

                    vulnerabilities.append({
                        "type": pattern_def["type"],
                        "severity": pattern_def["severity"],
                        "line": i,
                        "description": pattern_def["description"],
                        "fix": pattern_def["fix"],
                        "confidence": pattern_def["confidence"],
                    })

        return vulnerabilities

    def get_standards_check(self, code: str) -> List[str]:
        checks = {
            "ReentrancyGuard": "Reentrancy Protection",
            "AccessControl": "Role-Based Access Control",
            "Ownable": "Ownership Pattern",
            "SafeMath": "Overflow Protection",
            "SafeERC20": "Safe Token Transfers",
            "Pausable": "Emergency Pause",
            "IERC20": "ERC20 Interface",
        }
        return [label for pattern, label in checks.items() if pattern in code]


# ═══════════════════════════════════════════════════════════════════════════════
#  LLM Providers — Ollama (local) / Groq (free) / Claude / OpenAI
# ═══════════════════════════════════════════════════════════════════════════════

class OllamaProvider:
    """Local Ollama instance — completely free, private, offline."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = None):
        self.base_url = base_url
        self.model = model or os.getenv("OLLAMA_MODEL", "qwen2.5-coder")
        self.available = self._check_available()

    def _check_available(self) -> bool:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": f"{system_prompt}\n\nUser:\n{user_prompt}",
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 4096},
                },
                timeout=120,
            )
            if response.status_code == 200:
                return response.json().get("response", "")
            return ""
        except Exception as e:
            print(f"Ollama error: {e}")
            return ""


class GroqProvider:
    """Groq — free tier, blazing fast inference for Llama/Qwen models."""

    def __init__(self, api_key: str = None, model: str = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.model = model or os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
        self.available = bool(self.api_key)

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        if not self.api_key:
            return ""
        try:
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": 0.1,
                    "max_tokens": 4096,
                },
                timeout=30,
            )
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"]
            print(f"Groq error {response.status_code}: {response.text[:200]}")
            return ""
        except Exception as e:
            print(f"Groq error: {e}")
            return ""


class AnthropicProvider:
    """Claude API — paid, best code analysis quality."""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("CLAUDE_API_KEY")
        self.available = bool(self.api_key)

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        if not self.api_key:
            return ""
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return message.content[0].text
        except Exception as e:
            print(f"Claude error: {e}")
            return ""


class OpenAIProvider:
    """OpenAI GPT — paid, good general analysis."""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.available = bool(self.api_key)

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        if not self.api_key:
            return ""
        try:
            import openai
            client = openai.OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=4096,
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"OpenAI error: {e}")
            return ""


# ═══════════════════════════════════════════════════════════════════════════════
#  Main Auditor Engine
# ═══════════════════════════════════════════════════════════════════════════════

class SmartContractAuditor:
    """
    Core audit engine.
    Priority: Ollama (free local) → Groq (free cloud) → Claude → OpenAI → Pattern-only
    """

    def __init__(self):
        self.pattern_analyzer = PatternAnalyzer()

        # Initialize providers in priority order
        self.providers = []
        self.active_provider = None

        # 1. Ollama — local, free
        ollama = OllamaProvider()
        if ollama.available:
            self.providers.append(("ollama", ollama))

        # 2. Groq — free tier cloud
        groq = GroqProvider()
        if groq.available:
            self.providers.append(("groq", groq))

        # 3. Claude — paid
        claude = AnthropicProvider()
        if claude.available:
            self.providers.append(("claude", claude))

        # 4. OpenAI — paid
        openai_p = OpenAIProvider()
        if openai_p.available:
            self.providers.append(("openai", openai_p))

        if self.providers:
            self.active_provider = self.providers[0]
            print(f"  ✓ Active LLM: {self.active_provider[0]}")
        else:
            print("  ⚠ No LLM available — using pattern analysis only")

    @property
    def llm_enabled(self) -> bool:
        return self.active_provider is not None

    @property
    def provider_name(self) -> str:
        return self.active_provider[0] if self.active_provider else "none"

    def _llm_analyze(self, contract_code: str, prompt: str = None) -> List[Dict]:
        if not self.active_provider:
            return []

        system = prompt or SYSTEM_PROMPT
        user_msg = f"Audit this Solidity smart contract for security vulnerabilities:\n\n```solidity\n{contract_code}\n```"

        # Try providers in priority order
        for name, provider in self.providers:
            response_text = provider.generate(system, user_msg)
            if response_text:
                return self._parse_llm_response(response_text)

        return []

    def _parse_llm_response(self, text: str) -> List[Dict]:
        """Extract and validate JSON vulnerability array from LLM response."""
        try:
            # Try to find JSON array in response
            json_match = re.search(r'\[.*\]', text, re.DOTALL)
            if json_match:
                raw = json_match.group()
                # Clean common LLM JSON issues
                raw = raw.replace("```json", "").replace("```", "")
                vulnerabilities = json.loads(raw)

                valid = []
                for v in vulnerabilities:
                    if isinstance(v, dict) and "type" in v:
                        valid.append({
                            "type": str(v.get("type", "unknown")),
                            "severity": str(v.get("severity", "medium")).lower(),
                            "line": int(v.get("line", 0)),
                            "description": str(v.get("description", "")),
                            "fix": str(v.get("fix", "")),
                            "confidence": min(100, max(0, int(v.get("confidence", 50)))),
                        })
                return valid
        except (json.JSONDecodeError, ValueError) as e:
            print(f"JSON parse error: {e}")
        return []

    def audit_contract(self, contract_code: str, mode: str = "full") -> Dict:
        """
        Main audit function.
        Modes: 'full' (LLM + patterns), 'quick' (patterns only), 'gas' (gas optimization)
        """
        vulnerabilities = []

        # Always run pattern analysis
        pattern_results = self.pattern_analyzer.analyze(contract_code)
        vulnerabilities.extend(pattern_results)

        # Run LLM analysis if available
        if self.active_provider and mode in ("full", "gas"):
            prompt = GAS_OPTIMIZATION_PROMPT if mode == "gas" else None
            llm_results = self._llm_analyze(contract_code, prompt)

            # Merge, deduplicate
            for llm_vuln in llm_results:
                is_dup = False
                for existing in vulnerabilities:
                    if (existing["type"] == llm_vuln["type"] and
                            abs(existing.get("line", 0) - llm_vuln.get("line", 0)) <= 2):
                        if llm_vuln["confidence"] > existing["confidence"]:
                            existing.update(llm_vuln)
                        is_dup = True
                        break
                if not is_dup:
                    vulnerabilities.append(llm_vuln)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulnerabilities.sort(key=lambda v: severity_order.get(v.get("severity", "medium"), 2))

        risk_score = self._calculate_risk_score(vulnerabilities)
        standards = self.pattern_analyzer.get_standards_check(contract_code)
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulnerabilities:
            sev = v.get("severity", "medium")
            if sev in counts:
                counts[sev] += 1

        return {
            "status": "success",
            "vulnerabilities": vulnerabilities,
            "total_found": len(vulnerabilities),
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
            "risk_score": risk_score,
            "standards_used": standards,
            "analysis_mode": mode,
            "llm_enabled": self.llm_enabled,
            "llm_provider": self.provider_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> int:
        score = 0
        for vuln in vulnerabilities:
            sev = vuln.get("severity", "medium")
            conf = vuln.get("confidence", 50) / 100
            weights = {"critical": 30, "high": 20, "medium": 10, "low": 3}
            score += weights.get(sev, 5) * conf
        return min(int(score), 100)

    def generate_report(self, audit_result: Dict) -> str:
        if audit_result["status"] != "success":
            return f"Audit failed: {audit_result.get('message', 'Unknown error')}"

        risk = audit_result["risk_score"]
        risk_label = "CRITICAL" if risk >= 75 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 25 else "LOW"

        report = f"""
╔══════════════════════════════════════════════════════════════╗
║             SMART CONTRACT AUDIT REPORT                      ║
╚══════════════════════════════════════════════════════════════╝

Generated: {audit_result['timestamp']}
Engine: {audit_result['llm_provider'].upper()} {'+ Pattern Analysis' if audit_result['llm_enabled'] else '(Pattern Analysis Only)'}

Risk Score: {risk}/100 [{risk_label}]

  🔴 Critical: {audit_result['critical_count']}
  🟠 High:     {audit_result['high_count']}
  🟡 Medium:   {audit_result['medium_count']}
  🟢 Low:      {audit_result['low_count']}
"""

        for i, vuln in enumerate(audit_result["vulnerabilities"], 1):
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(vuln["severity"], "⚪")
            report += f"""
─── [{i}] {vuln['type'].upper()} ───
  {icon} {vuln['severity'].upper()} | Line {vuln['line']} | {vuln['confidence']}% confidence
  Issue: {vuln['description']}
  Fix:   {vuln['fix']}
"""

        if not audit_result["vulnerabilities"]:
            report += "\n✅ No vulnerabilities detected.\n"

        return report
