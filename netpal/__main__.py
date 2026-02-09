"""
Main entry point when running as module: python -m netpal
"""
from .cli import main
import sys

if __name__ == '__main__':
    sys.exit(main())