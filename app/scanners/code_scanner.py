"""
CodeGuardian - Code Scanner Module
===================================
Hybrid scanner: AST (static analysis) + LLM (AI-powered detection).

Detects:
- Dangerous function calls (eval, exec, etc.)
- Hardcoded secrets (passwords, API keys, tokens)
- SQL injection patterns
- Command injection patterns
- OWASP Top 10 vulnerabilities (via LLM)
"""

import ast
import logging
from typing import List, Dict, Any

import requests

from app.core.config import settings

logger = logging.getLogger(__name__)


class CodeScanner:
    """
    Scans source code for security vulnerabilities.

    Combines two engines:
      1. AST-based static analysis (fast, deterministic)
      2. LLM-based semantic analysis (via Ollama)
    """

    def __init__(self):
        """Initialize scanner with settings."""
        self.ollama_url = settings.OLLAMA_URL
        self.model = settings.MODEL_NAME
        self.timeout = settings.LLM_TIMEOUT
        self.max_tokens = settings.LLM_MAX_TOKENS
        self.dangerous_functions = settings.DANGEROUS_FUNCTIONS

        logger.info(f"CodeScanner initialized | model={self.model}")

    # ==========================================================
    # PUBLIC API
    # ==========================================================

    def scan(self, code: str) -> Dict[str, Any]:
        """
        Scan code and return combined findings.

        Args:
            code: Source code as a string.

        Returns:
            Dictionary with ast_issues, llm_issues, and total count.
        """
        if not code or not code.strip():
            return {
                "ast_issues": ["[ERROR] Empty code"],
                "llm_issues": [],
                "total": 1,
            }

        logger.info(f"Starting scan | {len(code)} bytes")

        ast_issues = self._analyze_ast(code)
        llm_issues = self._analyze_with_llm(code)

        total = len(ast_issues) + len(llm_issues)
        logger.info(f"Scan complete | {total} issues found")

        return {
            "ast_issues": ast_issues,
            "llm_issues": llm_issues,
            "total": total,
        }

    # ==========================================================
    # STATIC ANALYSIS (AST)
    # ==========================================================

    def _analyze_ast(self, code: str) -> List[str]:
        """Static analysis using Python's AST module."""
        issues: List[str] = []

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return [f"[ERROR] Syntax error: {e.msg} (line {e.lineno})"]

        for node in ast.walk(tree):
            # --- 1. Dangerous function calls ---
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in self.dangerous_functions:
                        issues.append(
                            f"[CRITICAL] Dangerous function '{node.func.id}()' "
                            f"at line {getattr(node, 'lineno', '?')}"
                        )

            # --- 2. Hardcoded secrets ---
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(
                            kw in var_name
                            for kw in ["password", "secret", "api_key", "token", "passwd"]
                        ):
                            if isinstance(node.value, ast.Constant) and isinstance(
                                node.value.value, str
                            ):
                                issues.append(
                                    f"[HIGH] Hardcoded secret in variable "
                                    f"'{target.id}' at line "
                                    f"{getattr(node, 'lineno', '?')}"
                                )

            # --- 3. Subprocess / os.system calls ---
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ["system", "popen", "call", "run"]:
                        issues.append(
                            f"[HIGH] Potentially unsafe call "
                            f"'{node.func.attr}()' at line "
                            f"{getattr(node, 'lineno', '?')}"
                        )

        return issues

    # ==========================================================
    # AI ANALYSIS (LLM)
    # ==========================================================

    def _analyze_with_llm(self, code: str) -> List[str]:
        """AI-powered analysis using local LLM via Ollama."""
        prompt = self._build_prompt(code)

        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            result = response.json().get("response", "").strip()

            if not result:
                return ["[INFO] LLM returned empty response"]

            return [result]

        except requests.exceptions.Timeout:
            logger.warning(f"LLM timeout after {self.timeout}s")
            return [f"[ERROR] LLM timeout after {self.timeout}s"]

        except requests.exceptions.ConnectionError:
            logger.error(f"Cannot connect to Ollama at {self.ollama_url}")
            return [f"[ERROR] Cannot connect to Ollama at {self.ollama_url}"]

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return [f"[ERROR] LLM error: {str(e)}"]

    def _build_prompt(self, code: str) -> str:
        """Build security analysis prompt."""
        return (
            "You are a security code reviewer. "
            "Analyze this code for vulnerabilities.\n\n"
            "Focus on:\n"
            "- SQL injection\n"
            "- Command injection\n"
            "- Hardcoded secrets\n"
            "- Insecure deserialization\n"
            "- OWASP Top 10 issues\n\n"
            "Return a short, structured list. "
            "Each finding on a new line with severity "
            "[CRITICAL/HIGH/MEDIUM/LOW].\n\n"
            "Code:\n"
            + code[: self.max_tokens]
            + "\n\nFindings:"
        )