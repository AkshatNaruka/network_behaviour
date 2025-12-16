"""
Setup script for Network Behaviour Tool

This package provides comprehensive network analysis and monitoring capabilities
including packet capture, port scanning, DNS tools, and network visualization.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

# Read version from modules/__init__.py
version_file = this_directory / "modules" / "__init__.py"
version = "2.0.0"
if version_file.exists():
    with open(version_file, encoding="utf-8") as f:
        for line in f:
            if line.startswith("__version__"):
                version = line.split("=")[1].strip().strip('"').strip("'")
                break

setup(
    name="network-behaviour",
    version=version,
    author="Network Behaviour Contributors",
    author_email="",
    description="Comprehensive network analysis and monitoring suite",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AkshatNaruka/network_behaviour",
    packages=find_packages(exclude=["tests", "tests.*", "docs", "examples"]),
    py_modules=["cli", "gui", "app"],
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Networking",
        "Topic :: System :: Monitoring",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Environment :: Web Environment",
    ],
    python_requires=">=3.8",
    install_requires=[
        "matplotlib>=3.7.1,<4.0.0",
        "scapy>=2.5.0,<3.0.0",
        "streamlit>=1.23.1,<2.0.0",
        "psutil>=5.9.5,<6.0.0",
        "netifaces>=0.11.0,<1.0.0",
        "dnspython>=2.4.2,<3.0.0",
        "networkx>=3.1,<4.0.0",
        "plotly>=5.17.0,<6.0.0",
        "pandas>=2.0.3,<3.0.0",
        "numpy>=1.24.3,<2.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "flake8>=6.0",
            "mypy>=1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "netbehaviour=cli:main",
            "netbehaviour-gui=gui:main",
            "netbehaviour-web=app:main",
        ],
    },
    keywords=[
        "network",
        "analysis",
        "monitoring",
        "security",
        "packet-capture",
        "port-scanner",
        "dns",
        "wireshark",
        "nmap",
        "network-security",
        "network-tools",
        "bandwidth-monitor",
    ],
    project_urls={
        "Documentation": "https://github.com/AkshatNaruka/network_behaviour#readme",
        "Bug Reports": "https://github.com/AkshatNaruka/network_behaviour/issues",
        "Source": "https://github.com/AkshatNaruka/network_behaviour",
        "Changelog": "https://github.com/AkshatNaruka/network_behaviour/blob/main/CHANGELOG.md",
    },
    zip_safe=False,
)
