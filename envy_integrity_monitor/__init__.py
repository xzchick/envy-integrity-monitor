"""ENVY Integrity Monitor: encrypted file-integrity baselines with change detection."""

__version__ = "0.2.1"
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
