clean:
	@find . -name "*.pyc" -exec rm -rf {} \;
	@find . -name "__pycache__" -delete

update-requirements:
	pip install -U -q pip-tools
	pip-compile --resolver=backtracking -o requirements/base/base.txt pyproject.toml
	pip-compile --resolver=backtracking --extra dev -o requirements/dev/dev.txt pyproject.toml
	pip-compile --resolver=backtracking --extra casbinsql -o requirements/casbin_extra/casbin.txt pyproject.toml

install-dev:
	@echo 'Installing pip-tools...'
	export PIP_REQUIRE_VIRTUALENV=true; \
	pip install --upgrade pip
	pip install -U -q pip-tools
	@echo 'Installing requirements...'
	pip-sync requirements/base/base.txt requirements/dev/dev.txt

lab:
	@echo 'Starting Jupyter Lab...'
	jupyter lab

setup:
	@echo 'Setting up the environment...'
	pip install --upgrade pip
	make install-dev
