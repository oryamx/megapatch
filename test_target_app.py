"""Functional tests: normal behavior of ALL routes, which a patch must NOT break.

Run against another folder with:  $env:APP_DIR = "reference_patch"
"""
import os
import tempfile

import pytest

from harness import load_app


@pytest.fixture
def client():
    return load_app(os.environ.get("APP_DIR", "target_app")).test_client()


def test_finds_existing_user(client):
    resp = client.get("/users/search", query_string={"name": "alice"})
    assert resp.status_code == 200
    assert [u["username"] for u in resp.get_json()["users"]] == ["alice"]


def test_unknown_user_returns_empty_list(client):
    resp = client.get("/users/search", query_string={"name": "nobody"})
    assert resp.status_code == 200
    assert resp.get_json()["users"] == []


def test_lookup_echoes_the_host(client):
    resp = client.get("/lookup", query_string={"host": "example.test"})
    assert resp.status_code == 200
    assert resp.get_json()["output"].strip() == "example.test"


def test_files_serves_a_public_file(client):
    resp = client.get("/files", query_string={"name": "readme.txt"})
    assert resp.status_code == 200
    assert "Welcome" in resp.get_json()["content"]


def test_files_work_when_the_data_dir_is_reached_through_a_symlink(tmp_path, monkeypatch):
    """Patches that compare a resolved path with an unresolved one break when the temp
    dir is a symlink (the default on macOS). Linux judges must catch that too."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        os.symlink(real, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this machine")
    monkeypatch.setattr(tempfile, "tempdir", str(link))
    client = load_app(os.environ.get("APP_DIR", "target_app")).test_client()
    resp = client.get("/files", query_string={"name": "readme.txt"})
    assert resp.status_code == 200
    assert "Welcome" in resp.get_json()["content"]


def test_files_missing_file_is_404(client):
    resp = client.get("/files", query_string={"name": "nope.txt"})
    assert resp.status_code == 404
