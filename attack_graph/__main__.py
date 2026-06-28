#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Mohamed Khaled <mohamedabdelfatah572@aucegypt.edu>
# SPDX-License-Identifier: MIT

"""Enable ``python -m attack_graph`` as an alias for the ``aga`` command."""

import sys

from attack_graph.cli import main

if __name__ == "__main__":
    sys.exit(main())
