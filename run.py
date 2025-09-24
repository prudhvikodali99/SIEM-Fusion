#!/usr/bin/env python3
"""
SIEM-Fusion Multi-LLM Integration System
Entry point for running the complete system
"""

import asyncio
import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.main import main

if __name__ == "__main__":
    asyncio.run(main())
