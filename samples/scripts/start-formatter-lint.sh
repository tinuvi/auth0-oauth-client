#!/usr/bin/env bash

set -e

git init && git config --global --add safe.directory /app && \
 git add . && \
 git config --global user.email "you@example.com" && git config --global user.name "Your Name" \
 git commit -m "Initial commit"

pre-commit run --all-files

#rm -rf .git
