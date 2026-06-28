#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Mohamed Khaled <mohamedabdelfatah572@aucegypt.edu>
# SPDX-License-Identifier: MIT

"""
Backward-compatible entry point.

This is a thin shim that delegates to :mod:`attack_graph.cli`. It exists so
``python3 analyze.py ...`` keeps working in a source checkout; the canonical
entry point after installation is the ``aga`` command (see ``pyproject.toml``).
"""

import sys

from attack_graph.cli import main

if __name__ == "__main__":
    sys.exit(main())
