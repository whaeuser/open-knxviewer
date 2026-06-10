"""Shared fixtures for all tests."""
import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

# Add project root to path so we can import server modules
sys.path.insert(0, str(Path(__file__).parent.parent))

import core
import server
import server_public


@pytest.fixture(autouse=True)
def reset_server_state():
    """Reset module-level state between tests to avoid cross-test pollution."""
    core.state.clear()
    core.state.update(core.initial_state())
    yield


@pytest.fixture
def patched_paths(tmp_path, monkeypatch):
    """Redirect all file I/O in core.py to a temporary directory."""
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(core, "ANNOTATIONS_PATH", tmp_path / "annotations.json")
    monkeypatch.setattr(core, "LOG_PATH", tmp_path / "knx_bus.log")
    monkeypatch.setattr(core, "LAST_PROJECT_PATH", tmp_path / "last_project.json")
    monkeypatch.setattr(core, "RECENT_PROJECTS_PATH", tmp_path / "recent_projects.json")
    monkeypatch.setattr(core, "PROJECTS_DIR", tmp_path / "projects")
    return tmp_path


@pytest.fixture
async def server_client(patched_paths):
    """Async HTTP client wired to the private server app (no lifespan / KNX)."""
    async with AsyncClient(
        transport=ASGITransport(app=server.app), base_url="http://test"
    ) as client:
        yield client


@pytest.fixture
async def public_client():
    """Async HTTP client wired to the public server app."""
    async with AsyncClient(
        transport=ASGITransport(app=server_public.app), base_url="http://test"
    ) as client:
        yield client


# Path to real .knxproj test files (checked out sibling repository)
KNXPROJ_DIR = Path(__file__).parent.parent.parent / "xknxproject" / "test" / "resources"
KNXPROJ_ETS6 = KNXPROJ_DIR / "ets6_free.knxproj"
KNXPROJ_ETS6_FUNCS = KNXPROJ_DIR / "testprojekt-ets6-functions.knxproj"
KNXPROJ_NOPASS = KNXPROJ_DIR / "xknx_test_project_no_password.knxproj"
