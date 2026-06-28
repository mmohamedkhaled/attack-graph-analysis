# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Mohamed Khaled <mohamedabdelfatah572@aucegypt.edu>
# SPDX-License-Identifier: MIT

"""Smoke tests for the ``aga`` command-line interface.

These are intentionally shallow: they prove that the package imports, that
``argparse`` builds without errors, and that the canonical entry points
(``--version``, ``--help``) exit cleanly. This is the contract Kali/Debian's
``autopkgtest`` pipeline relies on for a freshly built package.
"""
from __future__ import annotations

import subprocess
import sys

import pytest

from attack_graph import __version__
from attack_graph.cli import build_parser


# --------------------------------------------------------------------------- #
# In-process: parser construction.
# --------------------------------------------------------------------------- #
def test_version_is_pep440_like() -> None:
    assert isinstance(__version__, str)
    # At least major.minor, and starts with a digit.
    assert __version__.count(".") >= 1
    assert __version__[0].isdigit()


def test_build_parser_returns_argument_parser() -> None:
    parser = build_parser()
    assert parser.prog == "aga"


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_parser_advertises_help(flag: str) -> None:
    # build_parser() must succeed and the formatted help must mention the tool.
    text = build_parser().format_help()
    assert "usage:" in text.lower()
    assert "attack graph" in text.lower()


def test_parser_has_documented_flags() -> None:
    """Every flag advertised in the README must be registered on the parser."""
    parser = build_parser()
    declared = {
        token
        for action in parser._actions
        for token in action.option_strings
    }
    required = {
        "-V", "--version",
        "--dir", "--no-plot", "--list", "--graphs-dir",
        "--explain-cvss", "--export",
    }
    missing = required - declared
    assert not missing, f"missing documented flags: {missing}"


# --------------------------------------------------------------------------- #
# Subprocess: the actual installed entry point (what Debian ships).
# --------------------------------------------------------------------------- #
def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "attack_graph.cli", *args],
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_cli_version_flag() -> None:
    result = _run(["--version"])
    assert result.returncode == 0, result.stderr
    assert __version__ in result.stdout
    assert result.stdout.strip().startswith("aga ")


def test_cli_version_short_flag() -> None:
    result = _run(["-V"])
    assert result.returncode == 0, result.stderr
    assert __version__ in result.stdout


def test_cli_help_flag() -> None:
    result = _run(["--help"])
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()


def test_cli_explain_cvss_smoke() -> None:
    """``--explain-cvss`` must not crash on a canonical CVSS vector."""
    result = _run(["--explain-cvss", "AV:N/AC:L/PR:N/UI:N"])
    assert result.returncode == 0, result.stderr
    assert "weight" in result.stdout.lower()
