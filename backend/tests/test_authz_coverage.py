"""Every API operation must require authentication unless it is explicitly public.

Routes are enumerated from the OpenAPI schema, so a newly added endpoint is covered
automatically and fails this test if it forgets its auth dependency.
"""

import re

from tests.conftest import csrf_headers

PUBLIC = {
    ("GET", "/api/health"),
    ("GET", "/api/ready"),
    ("POST", "/api/auth/login"),
}
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def _operations(client) -> list[tuple[str, str]]:
    paths = client.get("/api/openapi.json").json()["paths"]
    ops = []
    for path, methods in paths.items():
        concrete = re.sub(r"\{[^}]+\}", "1", path)
        for method in methods:
            ops.append((method.upper(), path, concrete))
    return ops


def test_schema_lists_expected_number_of_operations(client):
    # Guards against the enumeration silently returning nothing.
    assert len(_operations(client)) >= 10


def test_all_non_public_operations_require_authentication(client):
    failures = []
    for method, path, concrete in _operations(client):
        if (method, path) in PUBLIC:
            continue
        resp = client.request(method, concrete, json={})
        if resp.status_code != 401:
            failures.append(f"{method} {path} -> {resp.status_code}")
    assert not failures, "Unauthenticated access allowed:\n" + "\n".join(failures)


def test_all_unsafe_operations_require_csrf(logged_in):
    c, _ = logged_in("admin")
    failures = []
    for method, path, concrete in _operations(c):
        if method not in UNSAFE or (method, path) in PUBLIC:
            continue
        resp = c.request(method, concrete, json={})
        if resp.status_code != 403:
            failures.append(f"{method} {path} -> {resp.status_code}")
    assert not failures, "State change accepted without CSRF token:\n" + "\n".join(failures)
    # Sanity: the session itself is still valid.
    assert c.get("/api/auth/me", headers=csrf_headers(c)).status_code == 200
