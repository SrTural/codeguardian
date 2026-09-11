# 🛡️ CodeGuardian

**Local-first, AI-powered code security scanner. Zero data exfiltration. GDPR-compliant by design.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141-009688)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## 🎯 What It Does

CodeGuardian scans source code for security vulnerabilities **entirely on your machine**. No cloud, no API keys, no data leaks. Built for teams that **cannot** use cloud-based SAST tools — banks, healthcare, government, and defense organizations.

---

## 🔥 Why CodeGuardian?

| Feature | Cloud SAST (Snyk, Checkmarx) | **CodeGuardian** |
|---------|------------------------------|------------------|
| **Data location** | Their servers | **Your server** |
| **GDPR compliant** | Partial | **Full** |
| **Air-gapped** | ❌ | ✅ |
| **Monthly cost** | $50–500/dev | **$0** |
| **Setup time** | Hours | **Minutes** |
| **Data exfiltration** | Possible | **Impossible** |

---

## 🐳 Docker (Recommended)

The fastest way to run CodeGuardian:

```bash
# 1. Clone the repo
git clone https://github.com/SrTural/codeguardian.git
cd codeguardian

# 2. Start everything with one command
docker compose up --build
