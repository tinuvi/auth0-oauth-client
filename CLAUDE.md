# SDLC rules

Imperative guidance for working on `auth0-oauth-client`. Follow these end-to-end on every change.

## Code style

- Write a test for every implementation change. No exception for "trivial" fixes.
- Use parameterized logging only: `_logger.info("Message %s", value)`. Do **not** pre-format log strings with f-strings, `%`, or `.format()`.
- When you see `getLogger(__name__)`, change it to `getLogger("auth0_oauth_client")`.

## Updating poetry settings

- Update `poetry.lock` when `pyproject.toml` changes:
    ```bash
    docker compose run --rm --remove-orphans integration-tests poetry update
    ```
- Build the Docker images to reflect the changes:
    ```bash
    docker compose build integration-tests lint-formatter
    ```

## Testing

- Only use `unittest` for tests. 
- When creating a test class, use `django.test.TestCase` (or `TransactionTestCase` for DB-focused tests)
- Add `__init__.py` for every folder you create.
- Coverage for selective testing: Sample commands to check coverage for a specific file:
    ```python
    # Run tests for specific module, generate coverage, and view coverage report for specific file
    docker compose run --rm --remove-orphans integration-tests coverage run -m unittest tests.test_client && coverage report --include=client.py
    ```
- Run the full library suite before declaring a change complete:
    ```bash
    docker compose run --remove-orphans --rm integration-tests
    ```

## Lint & format

- Run after the implementation is complete (no need to re-run tests after):
    ```bash
    docker compose run --remove-orphans --rm lint-formatter
    ```

## Documentation

- Update `README.md` when public API, install steps, or supported Python/Django versions change.
- Do **not** create new top-level docs (`*.md`) unless explicitly asked.

## Commits

- Use Conventional Commits.

## Deployment

- Releases are tag-driven via `.github/workflows/publish-package.yml`. Pushing an annotated tag matching the version number publishes to PyPI.
- Never edit `pyproject.toml`'s `version` by hand — the publish workflow runs `poetry version $TAG_NAME` from the tag.