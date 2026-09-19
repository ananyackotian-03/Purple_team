# SentinelForge — Developer Handover & Quickstart Guide

Welcome to **SentinelForge**! This document is a complete handover guide for developers picking up the codebase to complete, test, deploy, or extend the project.

---

## 🚀 1. Executive Summary

SentinelForge is an **Evidence-Driven Autonomous Security Validation & Remediation Platform**. It simulates adversarial attack vectors (Red Agent), captures telemetry, evaluates detection gaps (Sigma/Falco), generates defensive patch proposals (Remediation Engine), tests patches in isolated Docker clones, and maintains organization-wide defense memory (Immune Memory).

- **Backend**: Python 3.11+, FastAPI, SQLAlchemy, Alembic, Pydantic v2, Pytest
- **Frontend**: React 18, Vite, TypeScript, Tailwind CSS, Lucide Icons, Vitest
- **Security Engine**: Multi-tier safety boundary, HMAC blueprint signing, state machine lifecycle

---

## 📁 2. Repository Structure

```
Purple/
├── backend/
│   ├── alembic/                      # Database schema migrations
│   ├── src/sentinelforge/
│   │   ├── adaptive/                 # Adaptive experiment selection & scoring
│   │   ├── agents/                   # Red Agent, LLM Provider layer (OpenAI/Anthropic/Gemini/Ollama)
│   │   ├── api/                      # FastAPI REST API endpoints & schemas (`/api/v1/...`)
│   │   ├── defensive/                # Patch proposal generator & comparison engine
│   │   ├── detection/                # Sigma rule engine & telemetry collector
│   │   ├── digital_twin/             # Environment twin & service registration
│   │   ├── domain/                   # State machine, Action IR, Blueprints, Security Exceptions
│   │   ├── organization/             # Security state & context management
│   │   ├── policy/                   # Policy engine, safety allowlists, HMAC signer
│   │   ├── remediation/              # Docker clone manager & remediation executor
│   │   ├── immune_cycle_orchestrator.py # Full closed-loop security cycle orchestrator
│   │   └── immune_memory.py          # Defense memory & knowledge retention
│   └── tests/                        # Comprehensive test suite (unit, security, integration, phase9-13)
├── frontend/
│   ├── src/
│   │   ├── components/               # Layout, Navigation, Shared UI Cards & Badges
│   │   ├── pages/                    # 11 Interactive Dashboard pages (Overview, Telemetry, etc.)
│   │   ├── lib/api.ts                # REST API client with live backend connection + fallback
│   │   └── __tests__/                # Vitest React UI unit & integration tests
│   ├── package.json
│   └── vite.config.ts
├── target/                           # Target application Dockerfile & Falco rules
├── README.md                         # Project Overview
├── TODO_NEXT.md                      # Milestone checklist & roadmap
└── HANDOVER_GUIDE.md                 # (This File)
```

---

## 🛠️ 3. How to Run & Test

### A. Running the Backend Server
```bash
cd backend

# Create & activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run FastAPI Dev Server (runs on http://localhost:8000)
python -m sentinelforge.api.server
```
- Interactive API Docs will be available at: `http://localhost:8000/docs`

### B. Running Backend Tests
```bash
cd backend
pytest -v
```

### C. Running the Frontend Dashboard
```bash
cd frontend

# Install node dependencies
npm install

# Start Vite Development Server (runs on http://localhost:5173)
npm run dev
```

### D. Running Frontend Tests
```bash
cd frontend
npm test
```

---

## 🔑 4. Environment Variables & Live LLM Setup

SentinelForge runs out-of-the-box using mock/deterministic providers for development and offline testing. To enable **Live LLMs**:

Create a `.env` file in `backend/`:
```env
# Choose provider: openai | anthropic | gemini | ollama
SENTINELFORGE_LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your-openai-api-key-here

# Or for local Ollama / LM Studio (Free, No API key needed):
# SENTINELFORGE_LLM_PROVIDER=ollama
# OLLAMA_HOST=http://localhost:11434
```

---

## 🎯 5. Next Steps to Complete the Project

1. **Verify Docker Desktop Integration**:
   - Ensure Docker Desktop is running.
   - Test Docker clone execution: `pytest backend/tests/integration/test_docker_e2e.py -v`.
2. **Connect Live LLM Key**:
   - Set `OPENAI_API_KEY` (or `GEMINI_API_KEY` / `ANTHROPIC_API_KEY`) and run `pytest backend/tests/integration/test_e2e_real_llm.py -v`.
3. **Database Migration**:
   - For PostgreSQL production deployment, set `DATABASE_URL` and run `alembic upgrade head`.
4. **Production Build**:
   - Run `npm run build` inside `frontend/` to produce the compiled distribution build in `frontend/dist/`.

---

## 💡 6. Architectural Rules & Security Invariants

- **LLM Safety Tiering**: The Red Agent / LLM is untrusted. All generated actions MUST pass through:
  `Pydantic Schema Validation` → `Novelty Evaluator` → `Policy Engine Allowlists` → `HMAC Blueprint Signer`.
- **Target Isolation**: Attack execution and remediation retesting MUST occur inside isolated Docker container clones (`DockerCloneManager`), never directly on production targets.
- **State Machine Integrity**: Exercise states follow strict valid transitions (`CREATED` → `PLANNING` → `POLICY_CHECK` → `APPROVED` → `SIMULATING` → `COLLECTING` → `DETECTING` → `ANALYZING` → `AWAITING_APPROVAL` → `RETESTING` → `VERIFIED`).

---

Good luck! Feel free to refer to `SECURITY_STATUS.md` and `ARCHITECTURE_DECISIONS.md` for in-depth design details.
