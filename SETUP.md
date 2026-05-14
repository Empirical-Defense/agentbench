# AgentBench Setup & Installation Guide

This guide walks you through setting up AgentBench for evaluating your AI agents.

## Prerequisites

- **Python 3.9 or higher**
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
pip install -r requirements.txt
```

Verify installation:

```bash
python -c "import fastapi, streamlit; print('✓ Dependencies installed')"
```

## Step 2: Configure Your Agent

Set your AI agent's URL as an environment variable:

```bash
export AGENTBENCH_VENDOR_URL="https://your-agent-endpoint-here"
export AGENTBENCH_AGENT_CATEGORY="chat_only"  # or: rag_based, code_generation, autonomous, etc.
```

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

#### Terminal 1 - Vendor Adapter (Optional - skip if using direct URL)

```bash
uvicorn app.copilot_vendor_adapter:app --host 127.0.0.1 --port 9010
```

Expected output: `INFO: Uvicorn running on http://127.0.0.1:9010`

#### Terminal 2 - API Service

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Expected output: `INFO: Uvicorn running on http://127.0.0.1:8000`

#### Terminal 3 - Dashboard

```bash
streamlit run dashboard/app.py
```

Expected output: `You can now view your Streamlit app in your browser.`

## Step 4: Run Your First Assessment

### Via Dashboard

1. Open http://127.0.0.1:8501 in your browser
2. Enter your agent details
3. Select a framework (AIUC, OWASP, NIST AI RMF)
4. Click "Run Assessment"
5. View results and metrics in real-time

### Via API

```bash
curl -X POST http://localhost:8000/api/assessments \
  -H "Content-Type: application/json" \
  -d '{
    "vendor_id": "copilot",
    "vendor_url": "https://your-agent-url",
    "agent_category": "chat_only",
    "test_depth": "full"
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
pip install --upgrade pip
pip install -r requirements.txt --force-reinstall
```

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
streamlit run dashboard/app.py --logger.level=debug
```

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
AGENTBENCH_VENDOR_URL=https://your-agent-url
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

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Directory Layout After Setup

```
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
