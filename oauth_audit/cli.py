from __future__ import annotations

import argparse
from pathlib import Path

from .engine import assess_clients
from .io import load_clients
from .report import render_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess OAuth/OIDC client configuration exports.")
    parser.add_argument("input", help="Path to JSON client inventory")
    parser.add_argument("--output", default="oauth-assessment.md", help="Markdown report path")
    args = parser.parse_args()
    clients = load_clients(args.input)
    findings = assess_clients(clients)
    Path(args.output).write_text(render_markdown(findings), encoding="utf-8")
    print(f"Assessed {len(clients)} clients; generated {len(findings)} findings -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
