"""
Setup script for Network Behaviour Tool
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="network-behaviour",
    version="2.0.0",
    author="Network Behaviour Contributors",
    description="Comprehensive network analysis and monitoring suite",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AkshatNaruka/network_behaviour",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking",
        "Topic :: System :: Monitoring",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "matplotlib>=3.7.1",
        "scapy>=2.5.0",
        "streamlit>=1.23.1",
        "psutil>=5.9.5",
        "netifaces>=0.11.0",
        "dnspython>=2.4.2",
        "networkx>=3.1",
        "plotly>=5.17.0",
        "pandas>=2.0.3",
        "numpy>=1.24.3",
    ],
    entry_points={
        "console_scripts": [
            "netbehaviour=cli:main",
            "netbehaviour-gui=gui:main",
        ],
    },
    keywords="network analysis monitoring security packet-capture port-scanner dns wireshark nmap",
    project_urls={
        "Bug Reports": "https://github.com/AkshatNaruka/network_behaviour/issues",
        "Source": "https://github.com/AkshatNaruka/network_behaviour",
    },
)
