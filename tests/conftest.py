"""Bootstrap de sys.path: `from core...` / `from agents...` funcionan con
pytest invocado desde cualquier directorio del repo."""
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(scope="session", autouse=True)
def _drop_test_schemas():
    yield
    from core.db import drop_test_schemas

    drop_test_schemas()
