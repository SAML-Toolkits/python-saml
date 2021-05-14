VIRTUAL_ENV ?= venv
PYTHON_MAJOR_VERSION=2
PYTHON_MINOR_VERSION=7
PYTHON_VERSION=$(PYTHON_MAJOR_VERSION).$(PYTHON_MINOR_VERSION)
PYTHON_WITH_VERSION=python$(PYTHON_VERSION)
PYTHON=python
PIP=pip
FLAKE8=flake8
PYTEST=pytest
PYCODESTYLE=pycodestyle
COVERAGE=coverage
COVERAGE_CONFIG=tests/coverage.rc
PEP8_CONFIG=tests/pep8.rc
MAIN_SOURCE=src/onelogin/saml2
DEMOS=demo-django demo-flask
TESTS=tests/src/OneLogin/saml2_tests
SOURCES=$(MAIN_SOURCE) $(DEMO) $(TESTS)

$(VIRTUAL_ENV):
	virtualenv $(VIRTUAL_ENV) --python=$(PYTHON_WITH_VERSION)

virtualenv: $(VIRTUAL_ENV)

install-req:
	$(PIP) install --upgrade 'setuptools<45.0.0'
	$(PIP) install .

install-test:
	$(PIP) install -e ".[test]" 

pytest:
	$(COVERAGE) run --source $(MAIN_SOURCE) --rcfile=$(COVERAGE_CONFIG) -m pytest
	$(COVERAGE) report -m --rcfile=$(COVERAGE_CONFIG)

pycodestyle:
	$(PYCODESTYLE) $(SOURCES) --config=$(PEP8_CONFIG)

flake8:
	$(FLAKE8) --ignore=E501,E731 $(SOURCES)

clean: 
	rm -rf .pytest_cache/
	rm -rf .eggs/
	find . -type d -name "__pycache__" -exec rm -r {} +
	find . -type d -name "*.egg-info" -exec rm -r {} +
	rm .coverage

