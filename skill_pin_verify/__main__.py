"""Entry point so `python -m skill_pin_verify` works too."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
