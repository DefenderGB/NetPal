"""
Main entry point when running as module: python -m netpal
"""
import sys

from .cli import main

if __name__ == '__main__':
    sys.exit(main())
