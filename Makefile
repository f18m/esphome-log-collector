.DEFAULT_GOAL := help

PYTHON ?= python3
CONFIG ?= config.yaml
IMAGE ?= esphome-log-collector:latest
VENV_PYTHON := .venv/bin/python

.PHONY: help install test openapi check-config run docker-build compose-build compose-check-config compose-up compose-down compose-logs

help:
	@printf '%s\n' \
		'install              Create .venv and install development dependencies' \
		'test                 Run the full pytest suite' \
		'openapi              Regenerate openapi.json' \
		'check-config         Validate CONFIG (default: config.yaml)' \
		'run                  Run the collector with CONFIG' \
		'docker-build         Build IMAGE (default: esphome-log-collector:latest)' \
		'compose-build        Build the Docker Compose service' \
		'compose-check-config Validate config using Docker Compose' \
		'compose-up           Start services in the background' \
		'compose-down         Stop services' \
		'compose-logs         Follow service logs'

install:
	$(PYTHON) -m venv .venv
	$(VENV_PYTHON) -m pip install -r requirements-dev.txt
	$(VENV_PYTHON) -m pip install --no-deps -e .

test:
	$(VENV_PYTHON) -m pytest

openapi:
	$(VENV_PYTHON) -m esphome_log_collector.openapi_cli

check-config:
	.venv/bin/esphome-log-collector check-config -c "$(CONFIG)"

run:
	.venv/bin/esphome-log-collector run -c "$(CONFIG)"

docker-build:
	docker build -t "$(IMAGE)" .

compose-build:
	docker compose build

compose-check-config:
	docker compose run --rm esphome-log-collector check-config

compose-up:
	docker compose up -d

compose-down:
	docker compose down

compose-logs:
	docker compose logs -f
