# AgentBench

A comprehensive framework for evaluating and auditing AI agent compliance against industry standards and security frameworks.

## Overview

AgentBench is a production-ready evaluation system that:

- **Evaluates AI agents** against structured compliance frameworks (AIUC, OWASP LLM Top 10, NIST AI RMF)
- **Automates control testing** with category-aware prompts (Chat, RAG, Code Generation, Autonomous, etc.)
- **Generates audit reports** with detailed evidence and scoring
- **Provides interactive dashboards** for visualizing assessment results
- **Enables continuous monitoring** of agent security and compliance posture

## Key Features

- **Framework-Based Evaluation**: Built-in support for AIUC-1, OWASP LLM, and NIST AI RMF controls
- **Agent Category Support**: Realistic prompts tailored to your agent type (chat, RAG, code generation, autonomous, etc.)
- **Interactive Dashboard**: Real-time visualization of compliance metrics and control results
- **API-First Design**: RESTful API for programmatic access and integration
- **Audit-Ready Reports**: JSON exports with complete evidence trails
- **Test Suite Included**: Comprehensive test cases for validation and extension

## Quick Start

### Prerequisites

- Python 3.9+
- pip or virtual environment manager

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/agentbench.git
cd agentbench

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running AgentBench

See [SETUP.md](SETUP.md) for detailed instructions on:

1. Starting the API service
2. Configuring your agent endpoint
3. Running assessments
4. Using the interactive dashboard

### Quick Test

```bash
# Run a quick validation test
python test_quick_validation.py

# Run comprehensive tests
python test_comprehensive.py
```

## Project Structure

```
agentbench/
├── app/                      # Core evaluation engine
│   ├── main.py              # FastAPI application
│   ├── orchestrator.py       # Test orchestration
│   ├── evaluator.py          # Scoring logic
│   ├── llm_evaluator.py      # LLM-based evaluation
│   ├── models.py             # Data models
│   ├── prompt_configs.py     # Test prompts by category
│   └── ...
├── dashboard/               # Interactive Streamlit dashboard
│   ├── app.py              # Main dashboard app
│   ├── views.py            # Dashboard views
│   └── components/         # Reusable UI components
├── data/                    # Compliance framework data
│   ├── aiuc_controls.csv
│   ├── owasp_llm_controls.csv
│   ├── nist_ai_rmf_playbook.csv
│   └── ...
├── frameworks/              # Framework definitions and tests
├── tests/                   # Unit and integration tests
├── scripts/                 # Utility scripts
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Architecture

AgentBench operates as a three-tier system:

1. **API Service** (`app/main.py`): Handles assessment orchestration and control execution
2. **Vendor Adapter** (`app/copilot_vendor_adapter.py` or `app/openai_vendor_adapter.py`): Connects to your AI agent
3. **Dashboard** (`dashboard/app.py`): Interactive web UI for results visualization

## Usage Examples

### Via API

```bash
curl -X POST http://localhost:8000/api/assessments \
  -H "Content-Type: application/json" \
  -d '{
    "vendor_id": "copilot",
    "vendor_url": "https://your-agent-url",
    "agent_category": "chat_only"
  }'
```

### Via Dashboard

```bash
streamlit run dashboard/app.py
```

## Configuration

Agent categories define which control tests are executed:

- **chat_only**: Conversational agents
- **rag_based**: Retrieval-augmented generation systems
- **code_generation**: Agents that write code
- **autonomous**: Autonomous task execution agents
- **domain_specific**: Specialized domain agents
- **offline**: Offline/batch processing agents

Set the category via environment variable or request payload.

## Framework Data

All control definitions, descriptions, and mapping information is stored in CSV files under `data/`:

- `aiuc_controls.csv`: AIUC-1 compliance controls
- `owasp_llm_controls.csv`: OWASP LLM Top 10 risks
- `nist_ai_rmf_playbook.csv`: NIST AI Risk Management Framework

These are loaded dynamically at runtime, allowing framework updates without code changes.

## Extending AgentBench

### Adding New Controls

Edit the CSV files in `data/` and add corresponding test logic in `app/prompt_configs.py`.

### Adding New Agent Categories

Update `app/prompt_configs.py` with new category definitions and test prompts.

### Custom Evaluators

Extend `app/llm_evaluator.py` to implement custom scoring logic.

## Testing

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_evaluator_rules.py -v

# Run with coverage
pytest --cov=app tests/
```

## Reports

Assessment results are saved as JSON in the `reports/` directory (created automatically). Each report includes:

- Control-level results (PASS/FAIL/PARTIAL)
- Test evidence and reasoning
- Scoring metrics
- Timestamp and configuration

## License

[Add your license here]

## Contributing

Contributions welcome! Please submit issues and pull requests.

## Support

For questions or issues:
- Check [SETUP.md](SETUP.md) for setup troubleshooting
- Review test files in `tests/` for usage examples
- See `app/` source code for implementation details

---

**AgentBench**: Making AI agent compliance auditable, repeatable, and actionable.
