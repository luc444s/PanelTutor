#!/usr/bin/env python3
"""Issue an Apps API token for one user (run inside the app container).

    docker compose exec -T app python /app/scripts/create_apps_token.py \
        --email operator@example.com --output /tmp/apps_token

The token honours ``SYSTUTOR_JWT_ACCESS_TOKEN_TTL_MINUTES``; regenerate it when
an operation returns 401. The file is written with mode 0600.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="create_apps_token.py", description=__doc__)
    parser.add_argument(
        "--email",
        default=os.environ.get("SPANEL_TOKEN_EMAIL"),
        help="User email (default: SPANEL_TOKEN_EMAIL).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/tmp/apps_token"),
        help="Where to write the token (default: /tmp/apps_token).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.email:
        print("--email is required (or set SPANEL_TOKEN_EMAIL)", file=sys.stderr)
        return 2

    from app.main import app
    from sqlalchemy import select
    from systutor.core.config import get_settings
    from systutor.kernel.auth.models import User
    from systutor.kernel.auth.service import issue_access_token

    with app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.email == args.email))
        if user is None:
            print(f"usuario no encontrado: {args.email}", file=sys.stderr)
            return 1
        token = issue_access_token(get_settings(), user)

    args.output.write_text(token + "\n", encoding="utf-8")
    args.output.chmod(0o600)
    print(f"token escrito en {args.output} ({len(token)} chars)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
