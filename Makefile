.PHONY: test lint demo docs sample check
PY ?= python3

test:
	$(PY) -m pytest -q

lint:
	ruff check .
	shellcheck aws-posture-check

demo:
	./aws-posture-check --demo --fail-on none

docs:
	$(PY) tools/gen_docs.py

sample:
	rm -rf .sample && ./aws-posture-check --demo --format md,html --output-dir .sample --fail-on none
	cp .sample/*.md docs/sample-report.md && cp .sample/*.html docs/sample-report.html && rm -rf .sample

check: lint test docs
