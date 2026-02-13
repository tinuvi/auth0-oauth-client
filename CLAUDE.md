# Golden rules

- Only use `unittest` for tests. 
- When creating a test class, use `django.test.TestCase` (or `TransactionTestCase` for DB-focused tests)
- Add `__init__.py` for every folder you create.

# Running tests

- Running all tests: `docker compose run --rm --remove-orphans integration-tests`
- Coverage for selective testing: Sample commands to check coverage for a specific file:
    ```python
    # Run tests for specific module, generate coverage, and view coverage report for specific file
    docker compose run --rm --remove-orphans integration-tests coverage run -m unittest tests.test_client && coverage report --include=client.py
    ```