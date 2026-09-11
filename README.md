# 🛡️ CodeGuardian

**Local-first, AI-powered code security scanner. Zero data exfiltration. GDPR-compliant by design.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141-009688)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

## 🎯 What It Does

CodeGuardian scans source code for security vulnerabilities **entirely on your machine**. No cloud, no API keys, no data leaks. Built for teams that can't use cloud-based SAST tools (banks, healthcare, government, defense).

## 🔥 Why CodeGuardian?

| Feature | Cloud SAST (Snyk, Checkmarx) | CodeGuardian |
|---------|------------------------------|--------------|
| **Data location** | Their servers | **Your server** |
| **GDPR compliant** | Partial | **Full** |
| **Air-gapped** | ❌ | ✅ |
| **Monthly cost** | $50-500/dev | **$0** |
| **Setup time** | Hours | **Minutes** |

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.ai) installed
- 16GB RAM (recommended)

### Installation

```bash
# 1. Clone the repo
git clone https://github.com/SrTural/codeguardian.git
cd codeguardian

# 2. Install dependencies
pip install -r requirements.txt

# 3. Pull the LLM model
ollama pull qwen2.5:7b

# 4. Start the server
uvicorn app.main:app --reload
