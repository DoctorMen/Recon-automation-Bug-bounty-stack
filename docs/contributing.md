# Contributing Guide

Thank you for your interest in contributing to Recon Bounty Stack!

## Code of Conduct

Please be respectful and professional in all interactions.

## Getting Started

### Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Recon-automation-Bug-bounty-stack.git
   cd Recon-automation-Bug-bounty-stack
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

4. Install pre-commit hooks (optional):
   ```bash
   pre-commit install
   ```

### Running Tests

```bash
# Run all tests
make test

# Run specific test file
pytest tests/test_pipeline.py -v

# Run with coverage
pytest tests/ --cov=src/recon_bounty_stack --cov-report=html
```

### Code Quality

```bash
# Format code
make format

# Run linting
make lint

# Type checking
mypy src/
```

## Making Changes

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation changes
- `refactor/description` - Code refactoring

### Commit Messages

Follow conventional commits:

```
type(scope): short description

Longer description if needed.

Fixes #123
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### Pull Request Process

1. Create a feature branch from `main`
2. Make your changes
3. Write/update tests
4. Run linting and tests
5. Submit a pull request

## Style Guide

### Python

- Follow PEP 8
- Use type hints
- Maximum line length: 100 characters
- Use docstrings for all public functions/classes

### Docstrings

```python
def my_function(param1: str, param2: int = 10) -> dict:
    """Short description.

    Longer description if needed.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of return value

    Raises:
        ValueError: When something is wrong
    """
    pass
```

### Testing

- Write tests for all new functionality
- Use pytest fixtures for common setup
- Mock external dependencies
- Aim for meaningful coverage, not just numbers

## Project Structure

```
src/recon_bounty_stack/
├── cli.py           # CLI interface
├── core/            # Core modules
├── scanners/        # Scanner implementations
├── agents/          # Agent modules
├── reports/         # Report generation
└── utils/           # Utilities

tests/
├── conftest.py      # Shared fixtures
├── test_pipeline.py # Pipeline tests
├── test_scanners.py # Scanner tests
└── test_utils.py    # Utility tests
```

## Adding New Features

### Adding a Scanner

1. Create `src/recon_bounty_stack/scanners/my_scanner.py`
2. Extend `BaseScanner`
3. Implement the `scan()` method
4. Add to `scanners/__init__.py`
5. Write tests in `tests/test_scanners.py`

### Adding a CLI Command

1. Add to `src/recon_bounty_stack/cli.py`
2. Use Click decorators
3. Follow existing patterns
4. Update documentation

## Documentation

- Update README.md for user-facing changes
- Update docs/ for detailed documentation
- Include docstrings for API changes

## Questions?

Open an issue for questions or discussions.

## License

By contributing, you agree that your contributions will be licensed under the project's license.
