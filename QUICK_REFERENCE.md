# Quick Reference - Network Behaviour Package

## Installation

```bash
# From PyPI (once published)
pip install network-behaviour

# From source
git clone https://github.com/AkshatNaruka/network_behaviour.git
cd network_behaviour
pip install -e .
```

## Commands

```bash
# CLI interface
netbehaviour --help
netbehaviour scan --host example.com --quick
netbehaviour dns --domain google.com

# Desktop GUI
netbehaviour-gui

# Web interface
netbehaviour-web
```

## Publishing Checklist

- [ ] Update version in `modules/__init__.py`
- [ ] Update version in `pyproject.toml`
- [ ] Update `CHANGELOG.md`
- [ ] Test locally: `python -m build && pip install dist/*.whl`
- [ ] Configure PyPI trusted publishing
- [ ] Create GitHub release with tag (e.g., v2.0.0)
- [ ] Workflow publishes automatically

## File Structure

```
network_behaviour/
├── LICENSE                    # MIT License
├── README.md                  # Main documentation
├── CHANGELOG.md               # Version history
├── CONTRIBUTING.md            # Contributor guide
├── ENTERPRISE_READY_SUMMARY.md # Implementation summary
├── pyproject.toml             # Modern packaging config
├── setup.py                   # Setup configuration
├── MANIFEST.in                # Package manifest
├── requirements.txt           # Dependencies
├── app.py                     # Web interface
├── cli.py                     # CLI interface
├── gui.py                     # Desktop GUI
├── modules/                   # Core functionality
├── docs/                      # Documentation
│   ├── QUICKSTART.md         # Quick start guide
│   └── PUBLISHING.md         # Publishing guide
└── .github/workflows/         # CI/CD workflows
    ├── ci.yml                # Testing workflow
    └── publish.yml           # Publishing workflow
```

## Key URLs

- **Repository**: https://github.com/AkshatNaruka/network_behaviour
- **Issues**: https://github.com/AkshatNaruka/network_behaviour/issues
- **PyPI** (after publishing): https://pypi.org/project/network-behaviour/

## Security

- All CodeQL checks passed ✅
- No security vulnerabilities found ✅
- Proper GitHub Actions permissions configured ✅

## Support

- Open GitHub Issues for bugs
- Use GitHub Discussions for questions
- See CONTRIBUTING.md for contribution guidelines
- See docs/PUBLISHING.md for release instructions

---

**Status**: ✅ Enterprise-Ready  
**Version**: 2.0.0  
**License**: MIT
