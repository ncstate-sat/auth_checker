clean:
	@find . -name "*.pyc" -exec rm -rf {} \;
	@find . -name "__pycache__" -delete

update-requirements:
	pip install -U -q "pip-tools<7.6.0"
	pip-compile --resolver=backtracking -o requirements/base/base.txt pyproject.toml
	pip-compile --resolver=backtracking --extra dev -o requirements/dev/dev.txt pyproject.toml

install-dev:
	@echo 'Installing pip-tools...'
	export PIP_REQUIRE_VIRTUALENV=true; \
	pip install --upgrade "pip<26.2"
	pip install -U -q "pip-tools<7.6.0"
	@echo 'Installing requirements...'
	pip-sync requirements/base/base.txt requirements/dev/dev.txt

setup:
	@echo 'Setting up the environment...'
	pip install --upgrade "pip<26.2"
	make install-dev
