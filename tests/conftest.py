# -*- coding: utf-8 -*-
"""Shared pytest fixtures for the aga test-suite.

These fixtures are deliberately cheap so that Debian's ``autopkgtest`` and
Kali's CI can run the suite against an *installed* copy of the package
without needing the full source tree beyond ``graphs/``.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure the in-repo package is importable when tests run from a source
# checkout (belt-and-braces; pybuild tests against the installed copy).
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Absolute path to the repository root."""
    return ROOT


@pytest.fixture(scope="session")
def graphs_dir(repo_root: Path) -> Path:
    """Directory of shipped JSON graph presets."""
    return repo_root / "graphs"


@pytest.fixture(scope="session")
def sample_graph(graphs_dir: Path) -> Path:
    """The paper's campus network -- the default preset."""
    return graphs_dir / "campus_paper.json"
