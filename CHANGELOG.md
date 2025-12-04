# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-12-04

### Changed
- Complete repository restructure following Python best practices
- Modern Python packaging with pyproject.toml
- New CLI interface using Click
- Reorganized source code into proper package structure

### Added
- Professional package structure under `src/recon_bounty_stack/`
- Unit tests with pytest (`tests/` directory)
- GitHub Actions CI/CD pipeline
- Comprehensive documentation (`docs/` directory)
- pip-installable package with entry points
- Type hints throughout the codebase
- Rich console output for better UX
- Configuration management with Pydantic
- Makefile for common development tasks

### Deprecated
- Original file structure (preserved in `_archive/`)
- Legacy script-based workflow

### Security
- Legal authorization system preserved and enhanced
- Safety checks integrated into pipeline
- Audit logging for all scan attempts

## [1.0.0] - 2025-11-02

### Added
- Initial release
- Multi-agent orchestration system
- Pipeline automation (Recon → HTTPx → Nuclei → Triage → Report)
- Legal authorization framework
- Windows native support
- Neural network integration (optional)
