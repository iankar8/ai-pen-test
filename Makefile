# Makefile for ai-pen-test

.PHONY: help install dev-install uninstall test format lint clean

help:
	@echo "ai-pen-test - Available Commands"
	@echo "================================="
	@echo ""
	@echo "Installation:"
	@echo "  make install        - Install the CLI"
	@echo "  make dev-install    - Install in development mode with dev deps"
	@echo "  make uninstall      - Remove installation"
	@echo ""
	@echo "Testing:"
	@echo "  make test           - Run test suite"
	@echo ""
	@echo "Development:"
	@echo "  make format         - Format code with black"
	@echo "  make lint           - Run linters"
	@echo "  make clean          - Remove generated files"
	@echo ""
	@echo "Usage:"
	@echo "  ai-pen-test scan <dir>  - Run security scan"
	@echo "  ai-pen-test help        - Show CLI help"
	@echo ""

install:
	@echo "Installing ai-pen-test..."
	@python3 -m pip install .

dev-install:
	@echo "Installing in development mode..."
	@python3 -m pip install -e ".[dev]"
	@echo "Development installation complete"
	@echo "   CLI available as: ai-pen-test"

uninstall:
	@echo "Uninstalling ai-pen-test..."
	@python3 -m pip uninstall -y ai-pen-test
	@echo "Uninstalled successfully"

test:
	@echo "Running test suite..."
	@python3 -m pytest tests/ -v

format:
	@echo "Formatting code..."
	@black handlers/ tests/ cli.py

lint:
	@echo "Running linters..."
	@pylint handlers/ cli.py
	@flake8 handlers/ cli.py

clean:
	@echo "Cleaning generated files..."
	@find . -type f -name '*.pyc' -delete
	@find . -type d -name '__pycache__' -delete
	@find . -type d -name '.pytest_cache' -delete
	@rm -f findings.json findings.csv
	@rm -f report_*.html report_*.json
	@rm -f *.log
	@echo "Cleaned"

.DEFAULT_GOAL := help
