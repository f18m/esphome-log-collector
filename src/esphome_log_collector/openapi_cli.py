"""Generate (or verify) the committed ``openapi.json`` from the FastAPI application.

    python -m esphome_log_collector.openapi_cli            # write ./openapi.json
    python -m esphome_log_collector.openapi_cli --check    # exit 1 when the file is out of date
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .web import create_app


def render_openapi() -> str:
    """Deterministic serialization of the application's schema (the single source of truth)."""
    return json.dumps(create_app().openapi(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m esphome_log_collector.openapi_cli", description=__doc__)
    parser.add_argument("-o", "--output", type=Path, default=Path("openapi.json"),
                        help="target file (default: ./openapi.json; run from the repository root)")
    parser.add_argument("--check", action="store_true", help="do not write; fail if the file differs")
    args = parser.parse_args(argv)
    expected = render_openapi()
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else None
        if current != expected:
            print(f"{args.output} is out of date; regenerate it with: python -m esphome_log_collector.openapi_cli",
                  file=sys.stderr)
            return 1
        return 0
    args.output.write_text(expected, encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
