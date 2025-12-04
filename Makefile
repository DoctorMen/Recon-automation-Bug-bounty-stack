.PHONY: install install-dev test lint format clean build demo help

# Default target
help:
	@echo "Recon Bounty Stack - Available Commands"
	@echo "========================================"
	@echo "  make install      Install package in production mode"
	@echo "  make install-dev  Install package with dev dependencies"
	@echo "  make test         Run tests with coverage"
	@echo "  make lint         Run linting checks"
	@echo "  make format       Auto-format code"
	@echo "  make clean        Remove build artifacts"
	@echo "  make build        Build package for distribution"
	@echo "  make demo         Run demo script"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --cov=src/recon_bounty_stack --cov-report=term-missing --cov-report=xml

lint:
	ruff check src/ tests/
	mypy src/ --ignore-missing-imports

format:
	black src/ tests/
	ruff check --fix src/ tests/

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache
	rm -rf src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -f .coverage coverage.xml

build:
	python -m build

demo:
	python scripts/demo.py --help
