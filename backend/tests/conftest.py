import io
import shutil
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "test-fixtures"

SEMGREP_AVAILABLE = shutil.which("semgrep") is not None

requires_semgrep = pytest.mark.skipif(
    not SEMGREP_AVAILABLE,
    reason="the semgrep CLI is not installed; fixture integration tests need it",
)


def zip_directory(source: Path) -> bytes:
    """Zip a fixture directory in memory, preserving relative paths."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())
    return buffer.getvalue()


@pytest.fixture
def make_zip():
    def _make(name: str) -> bytes:
        return zip_directory(FIXTURES / name)

    return _make


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import main
    import store

    # One throwaway history database per test: the store reads DB_PATH on
    # every call, so patching the module attribute is enough.
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "history.db")

    with TestClient(main.app) as test_client:
        yield test_client
