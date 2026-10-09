"""Functional tests: normal behavior of ALL routes, which a patch must NOT break.

Run against another folder with:  $env:APP_DIR = "reference_patch"
"""
import os

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


def test_files_missing_file_is_404(client):
    resp = client.get("/files", query_string={"name": "nope.txt"})
    assert resp.status_code == 404
