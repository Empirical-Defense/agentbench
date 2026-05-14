# Contributing to AgentBench

We welcome contributions! Please follow these guidelines:

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a new branch for your feature: `git checkout -b feature/your-feature-name`
4. Set up your development environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

## Making Changes

1. Write clear, descriptive commit messages
2. Add tests for new functionality
3. Ensure all tests pass: `pytest`
4. Update documentation as needed

## Adding New Controls or Frameworks

1. Add control definitions to appropriate CSV in `data/`
2. Add corresponding test prompts in `app/prompt_configs.py`
3. Create test cases in `tests/`
4. Document the changes

## Code Style

- Follow PEP 8
- Use type hints where possible
- Keep functions focused and testable
- Add docstrings for public functions

## Testing

Before submitting a PR:

```bash
# Run all tests
pytest

# Check coverage
pytest --cov=app tests/

# Validate specific test file
pytest tests/test_evaluator_rules.py -v
```

## Submitting Changes

1. Push your branch to your fork
2. Submit a Pull Request with:
   - Clear description of changes
   - Reference to any related issues
   - Test results showing everything passes
   - Updated documentation if applicable

## Reporting Issues

Please include:

- Description of the issue
- Steps to reproduce
- Expected vs. actual behavior
- Python version and OS
- Relevant logs or error messages

## Questions?

Feel free to open an issue or start a discussion. We're here to help!

---

Thank you for contributing to AgentBench!
