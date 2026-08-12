import pytest


@pytest.fixture(autouse=True)
def isolate_scan_database(tmp_path, monkeypatch):
    """Keep test scans out of the user's persistent scan history."""
    database_directory = tmp_path / "scan-databases"
    monkeypatch.setenv("DR_SOURCE_DB_DIRECTORY", str(database_directory))
