# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`auth-checker` is a small PyPI library (`auth_checker`) that provides a FastAPI dependency, `AuthChecker`, for authorizing requests based on permissions embedded in a JWT. Routes declare required permission strings (e.g. `"personnel:read"`); `AuthChecker` decodes the `Authorization` header's JWT and raises `HTTPException` if the token is missing/expired/invalid or the user's `permissions` claim doesn't contain all required permissions.

The entire implementation is `auth_checker/auth_checker.py` (one class). `auth_checker/__init__.py` just re-exports `AuthChecker`.

## Commands

Install dev dependencies (uses `pip-tools`, requires an active virtualenv):
```
make setup          # upgrade pip, then install-dev
make install-dev     # pip-sync requirements/base/base.txt requirements/dev/dev.txt
```

Regenerate pinned requirements after changing dependencies in `pyproject.toml`:
```
make update-requirements
```

Run the test suite (pytest config lives in `pytest.ini`; coverage config in `.coveragerc`):
```
pytest
```
Note: `pytest.ini` sets `--cov-fail-under=95`, so the suite fails if coverage drops below 95%. `JWT_SECRET=jwt_secret` is injected automatically via `pytest-env` (see `[tool.pytest_env]` in `pyproject.toml`), but the test file also sets its own `JWT_SECRET=TEST_SECRET` at import time — tests rely on that value, not the pytest-env one.

Run a single test:
```
pytest auth_checker/tests/test_authchecker.py::test_expired_token
```

Lint/format (also run automatically via pre-commit):
```
black auth_checker
ruff check auth_checker
bandit -c pyproject.toml -r auth_checker
```

Install pre-commit hooks (end-of-file-fixer, trailing-whitespace, check-yaml/toml, pyupgrade, black, bandit, ruff):
```
pre-commit install
```

Clean pycache artifacts:
```
make clean
```

## Environment

`JWT_SECRET` must be set in the environment for `AuthChecker` to decode tokens (see `envrc_sample` for the `direnv` layout used locally). Tokens are decoded with `HS256` only.

## Testing pattern

Tests in `auth_checker/tests/test_authchecker.py` spin up a real FastAPI app with routes guarded by `AuthChecker`, then drive it with `fastapi.testclient.TestClient` rather than unit-testing `AuthChecker` in isolation. `generate_token(permissions=..., exp=..., secret=...)` builds JWTs for each scenario (valid, expired, wrong signature, malformed, missing). Follow this pattern when adding new authorization scenarios: add a guarded route, then assert on the resulting status code (`200`, `401`, `400`, or `403`) and response body.

## Versioning

Package version is set in `pyproject.toml` (`[project].version`) and built/published via `flit_core`.
