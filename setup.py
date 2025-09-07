#!/usr/bin/env python3
"""
Setup script for Taixin LibNetat GUI

A cross-platform GUI wrapper for the Taixin LibNetat Tool by aliosa27.
This makes the GUI installable via pip.
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    try:
        with open("README.md", "r", encoding="utf-8") as f:
            return f.read()
    except:
        return "A cross-platform GUI for the Taixin LibNetat Tool by aliosa27"

setup(
    name="taixin-gui",
    version="1.0.0",
    description="Cross-platform GUI wrapper for the Taixin LibNetat Tool by aliosa27",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="GUI Wrapper",
    author_email="",
    url="https://github.com/tradewithmeai/taixin-libnetat-gui",
    py_modules=["taixin_gui"],
    install_requires=[
        "scapy>=2.4.0",
    ],
    extras_require={
        "original": ["git+https://github.com/aliosa27/taixin_tools.git"],
    },
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators", 
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Software Development :: User Interfaces",
    ],
    entry_points={
        "console_scripts": [
            "taixin-gui=taixin_gui:main",
        ],
    },
    project_urls={
        "Original Tool": "https://github.com/aliosa27/taixin_tools",
        "Bug Reports": "https://github.com/tradewithmeai/taixin-libnetat-gui/issues",
        "Source": "https://github.com/tradewithmeai/taixin-libnetat-gui",
    },
)