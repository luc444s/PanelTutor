from __future__ import annotations

from pathlib import Path

from scripts import create_apps_token as mod


def test_email_is_required(monkeypatch, capsys) -> None:
    monkeypatch.delenv("SPANEL_TOKEN_EMAIL", raising=False)
    assert mod.main([]) == 2
    assert "--email is required" in capsys.readouterr().err


def test_email_can_come_from_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("SPANEL_TOKEN_EMAIL", "operator@example.com")
    args = mod._parser().parse_args([])
    assert args.email == "operator@example.com"
    assert args.output == Path("/tmp/apps_token")
