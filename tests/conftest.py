"""sys.path bootstrap: `from core...` / `from agents...` work when
pytest is invoked from any directory in the repo."""
import sys
import os
import uuid
from pathlib import Path

import pytest

# Fresh namespace per pytest invocation; inherited by multiprocessing children.
os.environ.setdefault("VULNRADAR_TEST_RUN_ID", uuid.uuid4().hex)

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(scope="session", autouse=True)
def _drop_test_schemas():
    yield
    from core.db import drop_test_schemas

    drop_test_schemas()
