# AgentBench Setup & Installation Guide

This guide walks you through setting up AgentBench for evaluating your AI agents.

## Prerequisites

- **Python 3.14-compatible virtual environment**
- **pip** (usually included with Python)
- An **AI agent endpoint** (HTTP URL) to evaluate

## Step 1: Environment Setup

### Clone and Navigate

```bash
git clone https://github.com/yourusername/agentbench.git
cd agentbench
```

### Create Virtual Environment

```bash
# Create virtual environment
python -m venv .venv

# Activate it
source .venv/bin/activate
# On Windows: .venv\Scripts\activate
# On macOS/Linux: source .venv/bin/activate
```

### Install Dependencies

```bash
python -m pip install -r requirements.txt
```

Verify installation:

```bash
python -c "import fastapi, streamlit, openai; print('✓ Dependencies installed')"
```

## Step 2: Configure Your Agent

Set your upstream agent or agentic workflow URL for the local vendor adapter:

```bash
export UPSTREAM_AGENT_URL="https://your-agent-endpoint-here"
export AGENTBENCH_AGENT_CATEGORY="chat_only"  # or: rag_based, code_generation, autonomous, etc.
```

Start the local adapter in another terminal:

```bash
uvicorn app.copilot_vendor_adapter:app --host 127.0.0.1 --port 9010
```

Then keep the dashboard Agent Endpoint set to `http://127.0.0.1:9010/infer`.

**Supported Categories:**

- `chat_only` - Conversational agents (default)
- `rag_based` - RAG-based systems
- `code_generation` - Code-writing agents
- `autonomous` - Autonomous task execution
- `domain_specific` - Domain-specialized agents
- `offline` - Offline/batch agents

## Step 3: Start Services

### Option A: One-Command Startup (Recommended)

```bash
# If you have the run_dashboard_stack.sh script:
./run_dashboard_stack.sh
```

This starts all three services automatically.

### Option B: Manual Startup (3 Terminals)

#### Terminal 1 - Vendor Adapter

```bash
uvicorn app.copilot_vendor_adapter:app --host 127.0.0.1 --port 9010
```

Expected output: `INFO: Uvicorn running on http://127.0.0.1:9010`

The adapter reads `UPSTREAM_AGENT_URL` first, then the legacy `COPILOT_AGENT_URL`, and forwards prompts to your upstream agent or workflow.

#### Terminal 2 - API Service

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Expected output: `INFO: Uvicorn running on http://127.0.0.1:8000`

#### Terminal 3 - Dashboard

```bash
python -m streamlit run dashboard/app.py
```

Expected output: `You can now view your Streamlit app in your browser.`

## Step 4: Run Your First Assessment

### Via Dashboard

1. Open [http://127.0.0.1:8501](http://127.0.0.1:8501) in your browser
2. Enter your agent details
3. Select a framework (AIUC, OWASP, NIST AI RMF)
4. Click "Run Assessment"
5. View results and metrics in real-time

### Via API

```bash
curl -X POST http://localhost:8000/assess \
  -H "Content-Type: application/json" \
  -d '{
    "vendor_endpoint": "https://your-agent-url",
    "agent_category": "chat_only",
    "include_optional": true
  }'
```

### Via Quick Test Script

```bash
python test_quick_validation.py
```

## Step 5: Verify Everything Works

Run the test suite:

```bash
# Quick validation
python test_quick_validation.py

# Comprehensive tests
python test_comprehensive.py

# Or use pytest for specific tests
pytest tests/ -v
```

## Configuration Files

### `data/`

CSV files containing framework definitions:

- `aiuc_controls.csv` - AIUC-1 compliance controls
- `owasp_llm_controls.csv` - OWASP LLM Top 10 mappings
- `nist_ai_rmf_playbook.csv` - NIST AI RMF controls

### `app/prompt_configs.py`

Test prompts organized by agent category. Edit this file to:

- Add/modify test prompts
- Update scoring logic
- Add new agent categories

### `app/config_loader.py`

Environment configuration and settings.

## Troubleshooting

### Port Already in Use

If you get "Address already in use" errors:

```bash
# Kill processes on ports
lsof -ti:8000,8501,9010 | xargs kill -9  # macOS/Linux

# On Windows:
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

### Module Import Errors

```bash
# Ensure virtual environment is activated
source .venv/bin/activate

# Reinstall dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt --force-reinstall
```

The API service imports `openai` at startup. If `uvicorn app.main:app` fails with `ModuleNotFoundError: No module named 'openai'`, reinstall the requirements inside the active virtual environment.

### Agent Connection Issues

1. Verify the agent URL is correct and accessible
2. Check firewall/network settings
3. Ensure agent endpoint is responding: `curl https://your-agent-url`
4. Review logs in the API terminal for error details

### Dashboard Not Loading

```bash
# Clear Streamlit cache
rm -rf ~/.streamlit/cache

# Restart dashboard
python -m streamlit run dashboard/app.py --logger.level=debug
```

The dashboard uses the API URL in the sidebar to load the control catalog. The default is `http://127.0.0.1:8000`, so start the API service first or update the sidebar URL to match your backend.

## Next Steps

1. **Explore Frameworks**: Check `data/` for available compliance frameworks
2. **Customize Prompts**: Edit `app/prompt_configs.py` for your testing needs
3. **Extend Categories**: Add new agent categories in `prompt_configs.py`
4. **Review Results**: Check `reports/` for generated assessment reports
5. **Run Tests**: Use test files to validate your setup

## Environment Variables

Key environment variables for configuration:

```bash
# Agent configuration
UPSTREAM_AGENT_URL=https://your-agent-url
AGENTBENCH_AGENT_CATEGORY=chat_only

# Service ports (optional)
API_PORT=8000
DASHBOARD_PORT=8501
ADAPTER_PORT=9010

# Database (optional)
AGENTBENCH_DB_PATH=./agentbench.db
```

## API Documentation

Once the API is running, view interactive API docs at:

- Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
- ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- Control catalog: `GET /controls`
- Assessments: `POST /assess`

## Directory Layout After Setup

```text
agentbench/
├── .venv/                   # Virtual environment (created)
├── app/                     # API code
├── dashboard/               # UI code
├── data/                    # Framework definitions
├── frameworks/              # Framework files
├── tests/                   # Test suite
├── reports/                 # Generated assessment reports (created on first run)
├── agentbench.db            # SQLite database (created on first run)
├── requirements.txt
├── SETUP.md                 # This file
└── README.md
```

## Getting Help

- Check test files for usage examples
- Review API docs at `/docs` endpoint
- Check framework CSV files for control definitions
- Review `app/prompt_configs.py` for test prompt logic

---

**Ready to go!** You can now evaluate your AI agents against compliance frameworks.

Start with the Quick Test above to verify your setup, then move to the Dashboard for interactive assessment.
