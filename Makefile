VIRTUAL_ENV ?= venv
PYTHON_MAJOR_VERSION=2
PYTHON_MINOR_VERSION=7
PYTHON_VERSION=$(PYTHON_MAJOR_VERSION).$(PYTHON_MINOR_VERSION)
PYTHON_WITH_VERSION=python$(PYTHON_VERSION)
PYTHON=$(VIRTUAL_ENV)/bin/python
PIP=$(VIRTUAL_ENV)/bin/pip
FLAKE8=$(VIRTUAL_ENV)/bin/flake8
PYTEST=$(VIRTUAL_ENV)/bin/pytest
PYCODESTYLE=$(VIRTUAL_ENV)/bin/pycodestyle
COVERAGE=$(VIRTUAL_ENV)/bin/coverage
COVERAGE_CONFIG=tests/coverage.rc
PEP8_CONFIG=tests/pep8.rc
MAIN_SOURCE=src/onelogin/saml2
DEMOS=demo-django demo-flask
TESTS=tests/src/OneLogin/saml2_test
SOURCES=$(MAIN_SOURCE) $(DEMO) $(TESTS)

$(VIRTUAL_ENV):
	$(PYTHON_WITH_VERSION) -m venv $(VIRTUAL_ENV)
	$(PIP) install .
	$(PIP) install -e ".[test]"

virtualenv: $(VIRTUAL_ENV)

pytest: virtualenv
	$(COVERAGE) run --source $(MAIN_SOURCE) --rcfile=$(COVERAGE_CONFIG) -m pytest
	$(COVERAGE) report -m --rcfile=$(COVERAGE_CONFIG)

pycodestyle: virtualenv
	$(PYCODESTYLE) $(SOURCES) --config=$(PEP8_CONFIG)

flake8: virtualenv
	$(FLAKE8) --ignore=E501,E731 $(SOURCES)

clean: 
	rm -rf .pytest_cache/
	rm -rf .eggs/
	find . -type d -name "__pycache__" -exec rm -r {} +
	find . -type d -name "*.egg-info" -exec rm -r {} +
	rm .coverage

