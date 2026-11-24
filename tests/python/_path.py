"""Make the repo's python/ packages importable from the test suite."""

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PYTHON_DIR = REPO_ROOT / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

# Add the repository root so imports from `scripts/` and `python/` work from
# any test invocation directory. `scripts/` is not a package.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
