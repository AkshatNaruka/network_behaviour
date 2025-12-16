# Contributing to Network Behaviour Tool

Thank you for your interest in contributing to Network Behaviour! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming environment

## Getting Started

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/network_behaviour.git
   cd network_behaviour
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install in Development Mode**
   ```bash
   pip install -e .[dev]
   ```

4. **Install Pre-commit Hooks** (optional)
   ```bash
   pip install pre-commit
   pre-commit install
   ```

## Development Workflow

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make Your Changes**
   - Write clean, readable code
   - Follow existing code style
   - Add docstrings to functions and classes
   - Keep changes focused and minimal

3. **Test Your Changes**
   ```bash
   # Run existing tests
   pytest
   
   # Test CLI commands
   netbehaviour --help
   
   # Test installation
   pip install -e .
   ```

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "Add feature: your feature description"
   ```

5. **Push and Create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```
   Then create a Pull Request on GitHub.

## Code Style

### Python Style

- Follow [PEP 8](https://pep8.org/) style guide
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Use meaningful variable and function names

### Formatting

```bash
# Format code with black
black . --line-length 100

# Check with flake8
flake8 . --max-line-length=100
```

### Docstrings

Use Google-style docstrings:

```python
def example_function(param1, param2):
    """
    Brief description of function.
    
    Args:
        param1 (str): Description of param1
        param2 (int): Description of param2
        
    Returns:
        bool: Description of return value
        
    Raises:
        ValueError: Description of when this is raised
    """
    pass
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=modules --cov-report=html

# Run specific test file
pytest tests/test_specific.py
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files as `test_*.py`
- Name test functions as `test_*`
- Use pytest fixtures for setup/teardown
- Aim for high test coverage

Example test:

```python
def test_port_scanner():
    """Test port scanner functionality"""
    scanner = PortScanner()
    result = scanner.scan_port("127.0.0.1", 80, timeout=1)
    assert result is not None
```

## Documentation

### Updating Documentation

- Update README.md for user-facing changes
- Update docstrings for API changes
- Add examples for new features
- Update CHANGELOG.md

### Documentation Style

- Use clear, concise language
- Include code examples where helpful
- Add screenshots for UI changes
- Update version numbers when applicable

## Pull Request Guidelines

### PR Description

Include:
- **What**: Brief description of changes
- **Why**: Reason for the changes
- **How**: Technical approach used
- **Testing**: How changes were tested
- **Screenshots**: For UI changes

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Tests added/updated and passing
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Commits are clear and descriptive
- [ ] Branch is up to date with main

### Review Process

1. Maintainers will review your PR
2. Address any feedback or requested changes
3. Once approved, maintainers will merge

## Types of Contributions

### Bug Fixes

- Check if bug is already reported
- Create issue if not exists
- Reference issue in PR
- Include test that demonstrates the fix

### New Features

- Discuss in issue first for major features
- Keep features focused and cohesive
- Add comprehensive tests
- Update documentation

### Documentation

- Fix typos and improve clarity
- Add missing documentation
- Improve examples
- Update outdated information

### Performance Improvements

- Include benchmarks showing improvement
- Ensure no functionality is broken
- Document any trade-offs

## Module Structure

```
network_behaviour/
├── modules/              # Core functionality
│   ├── packet_capture/  # Packet sniffing
│   ├── network_scanner/ # Port scanning
│   ├── dns_tools/       # DNS/WHOIS
│   ├── network_info/    # Network info
│   ├── network_visualizer/ # Visualization
│   └── utils/           # Utilities
├── app.py               # Streamlit app
├── cli.py               # CLI interface
├── gui.py               # Desktop GUI
└── tests/               # Test suite
```

## Security

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email maintainers privately
2. Include detailed description
3. Provide steps to reproduce
4. Suggest fix if possible

### Security Guidelines

- Never commit credentials or secrets
- Validate all user inputs
- Use secure coding practices
- Follow principle of least privilege
- Keep dependencies updated

## Dependencies

### Adding New Dependencies

1. Check if really necessary
2. Prefer well-maintained packages
3. Check security advisories
4. Update requirements.txt
5. Update setup.py install_requires
6. Update pyproject.toml dependencies
7. Document in PR why dependency is needed

### Updating Dependencies

```bash
# Update specific package
pip install --upgrade package-name

# Update all packages
pip install --upgrade -r requirements.txt

# Check for outdated packages
pip list --outdated
```

## Release Process

Only maintainers can create releases. Process:

1. Update version in `modules/__init__.py`
2. Update `CHANGELOG.md`
3. Create release on GitHub
4. Automated workflow publishes to PyPI

## Getting Help

- **Questions**: Open a GitHub Discussion
- **Bugs**: Open a GitHub Issue
- **Security**: Email maintainers privately
- **Ideas**: Open a GitHub Discussion

## Recognition

Contributors will be:
- Listed in CHANGELOG.md
- Acknowledged in release notes
- Added to contributors list

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to Network Behaviour! 🎉
