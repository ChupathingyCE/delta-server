# SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
# SPDX-License-Identifier: GPL-3.0-or-later
"""The node's tests: python3 -m unittest discover -s tests -t ."""

import sys
from pathlib import Path

NODE = Path(__file__).resolve().parent.parent / "node"
TESTS = Path(__file__).resolve().parent
for folder in (NODE, TESTS):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))
