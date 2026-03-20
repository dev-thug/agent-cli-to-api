#!/usr/bin/env python3
"""
Composer 2 (Cursor) routing: built-in model aliases and optional CLI smoke check.

Request `model: "composer-2"` resolves via built-in aliases to `cursor:composer-2`,
which selects cursor-agent with `--model composer-2` (ids from `agent --list-models`).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))


def test_builtin_alias_maps_to_cursor_prefix() -> None:
    from codex_gateway.config import settings
    from codex_gateway.server import _parse_provider_model

    assert settings.model_aliases.get("composer-2") == "cursor:composer-2"
    assert settings.model_aliases.get("composer-2-fast") == "cursor:composer-2-fast"
    resolved = settings.model_aliases.get("composer-2", "composer-2")
    provider, inner = _parse_provider_model(resolved)
    assert provider == "cursor-agent", (provider, inner)
    assert inner == "composer-2", (provider, inner)


def test_env_codex_model_aliases_overrides_builtin() -> None:
    from codex_gateway.config import _model_aliases_with_builtins

    old = os.environ.get("CODEX_MODEL_ALIASES")
    try:
        os.environ["CODEX_MODEL_ALIASES"] = '{"composer-2": "cursor:sonnet-4.6-thinking"}'
        m = _model_aliases_with_builtins()
        assert m["composer-2"] == "cursor:sonnet-4.6-thinking"
    finally:
        if old is None:
            os.environ.pop("CODEX_MODEL_ALIASES", None)
        else:
            os.environ["CODEX_MODEL_ALIASES"] = old


def test_cursor_cli_lists_composer2() -> None:
    """Optional: requires Cursor Agent CLI on PATH."""
    for name in ("agent", "cursor-agent"):
        path = shutil.which(name)
        if not path:
            continue
        proc = subprocess.run(
            [path, "--list-models"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode == 0 and "composer-2" in proc.stdout:
            return
    raise AssertionError(
        "Neither `agent` nor `cursor-agent` listed composer-2 (install Cursor CLI or skip this check)"
    )


def main() -> int:
    test_builtin_alias_maps_to_cursor_prefix()
    print("OK: builtin alias -> cursor:composer-2")
    test_env_codex_model_aliases_overrides_builtin()
    print("OK: CODEX_MODEL_ALIASES overrides builtin")
    try:
        test_cursor_cli_lists_composer2()
        print("OK: Cursor CLI lists composer-2")
    except AssertionError as e:
        print(f"SKIP (integration): {e}")
    print("\nAll required tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
