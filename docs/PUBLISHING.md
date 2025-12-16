# Publishing to PyPI

This document describes how to publish the `network-behaviour` package to PyPI.

## Prerequisites

1. **PyPI Account**: Create accounts on both [PyPI](https://pypi.org/) and [TestPyPI](https://test.pypi.org/)
2. **API Tokens**: Generate API tokens for publishing:
   - PyPI: https://pypi.org/manage/account/token/
   - TestPyPI: https://test.pypi.org/manage/account/token/

## Automated Publishing (Recommended)

The repository includes GitHub Actions workflows for automated publishing.

### Publishing to PyPI (Production)

1. Create a new release on GitHub:
   ```bash
   # Tag the release
   git tag -a v2.0.0 -m "Release version 2.0.0"
   git push origin v2.0.0
   ```

2. Go to GitHub repository → Releases → Draft a new release
3. Choose the tag (e.g., `v2.0.0`)
4. Add release notes
5. Click "Publish release"

The GitHub Action will automatically:
- Build the package
- Run tests
- Publish to PyPI using trusted publishing

### Publishing to TestPyPI (Testing)

1. Go to Actions tab in GitHub
2. Select "Publish Python Package" workflow
3. Click "Run workflow"
4. Select "Publish to TestPyPI instead of PyPI" checkbox
5. Click "Run workflow"

## Manual Publishing

If you need to publish manually:

### 1. Build the Package

```bash
# Install build tools
pip install build twine

# Clean previous builds
rm -rf dist/ build/ *.egg-info

# Build the package
python -m build
```

This creates:
- `dist/network_behaviour-2.0.0.tar.gz` (source distribution)
- `dist/network_behaviour-2.0.0-py3-none-any.whl` (wheel)

### 2. Check the Distribution

```bash
twine check dist/*
```

### 3. Test with TestPyPI

```bash
# Upload to TestPyPI
twine upload --repository testpypi dist/*

# Install from TestPyPI to test
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ network-behaviour
```

### 4. Upload to PyPI

```bash
# Upload to PyPI (production)
twine upload dist/*
```

## GitHub Actions Setup

### Configure PyPI Trusted Publishing

1. **On PyPI**:
   - Go to your project settings
   - Navigate to "Publishing" section
   - Add a new publisher:
     - Owner: `AkshatNaruka`
     - Repository: `network_behaviour`
     - Workflow: `publish.yml`
     - Environment: `pypi`

2. **On TestPyPI** (optional, for testing):
   - Same steps as above, but on test.pypi.org
   - Environment: `testpypi`

3. **On GitHub**:
   - Go to repository Settings → Environments
   - Create environment `pypi` (if not exists)
   - No secrets needed with trusted publishing

## Version Management

Update version in these files before release:
- `modules/__init__.py` (`__version__ = "x.y.z"`)
- `pyproject.toml` (`version = "x.y.z"`)
- `CHANGELOG.md` (add new version section)

## Release Checklist

Before creating a release:

- [ ] Update version numbers in all files
- [ ] Update CHANGELOG.md with new features/fixes
- [ ] Run tests locally: `pytest`
- [ ] Build package locally: `python -m build`
- [ ] Test installation locally: `pip install dist/*.whl`
- [ ] Verify CLI commands work: `netbehaviour --help`
- [ ] Check package metadata: `twine check dist/*`
- [ ] Push all changes to GitHub
- [ ] Create and push version tag
- [ ] Create GitHub release with release notes

## Troubleshooting

### "Module not found" errors
Ensure `cli.py`, `gui.py`, and `app.py` are listed in `py_modules` in `setup.py`.

### Entry points not working
Reinstall in editable mode for development:
```bash
pip install -e .
```

### Package metadata errors
Check that `pyproject.toml` and `setup.py` don't conflict.

### Upload rejected by PyPI
- Ensure version number is unique (never reuse versions)
- Check that all required metadata is present
- Verify package name is available

## Post-Release

After successful release:

1. Announce on GitHub Discussions
2. Update documentation if needed
3. Monitor GitHub Issues for any problems
4. Start planning next version in CHANGELOG.md

## Resources

- [Python Packaging Guide](https://packaging.python.org/)
- [PyPI Help](https://pypi.org/help/)
- [GitHub Actions for Python](https://docs.github.com/en/actions/automating-builds-and-tests/building-and-testing-python)
- [Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
