#!/usr/bin/env bash

# https://www.gnu.org/software/bash/manual/bash.html#The-Set-Builtin
# -e  Exit immediately if a command exits with a non-zero status.
# -x Print commands and their arguments as they are executed.
set -e

REPORTS_FOLDER_PATH=tests-reports

# JUnit XML is written to $REPORTS_FOLDER_PATH/junit.xml via TEST_OUTPUT_DIR / TEST_OUTPUT_FILE_NAME in tests/settings.py.
coverage run --source='.' -m django test --durations 10 --testrunner=xmlrunner.extra.djangotestrunner.XMLTestRunner tests
coverage report -m --fail-under=90
coverage html -d $REPORTS_FOLDER_PATH/html
coverage xml -o $REPORTS_FOLDER_PATH/coverage.xml
