# Project overview

`esphome-log-collector` is a Docker-friendly Python service that continuously
collects and retains firmware logs from multiple ESPHome devices. It reconnects
after device or network outages and stores events in SQLite so logs remain
available across collector restarts.

The collector can use the ESPHome CLI or the native ESPHome API. Optional mDNS
discovery is provided by `python-zeroconf`. An optional, read-only web UI supports
status monitoring, searching historical logs, streaming a live tail, and
creating sanitized log/configuration exports.

## Repository layout

- `src/esphome_log_collector/`: application source, including configuration,
  collection backends, storage, exports, and web server.
- `src/esphome_log_collector/web_assets/`: HTML templates and static assets for
  the web UI; these are included in Python package builds.
- `tests/`: pytest test suite, including collector, storage, export, config, and
  web UI tests.
- `examples/`: example collector configuration.
- `Dockerfile` and `docker-compose.example.yml`: container build and deployment
  examples.

## Development

Runtime dependencies and the supported ESPHome version are pinned in
`requirements.txt`; development dependencies are in `requirements-dev.txt`.
Install the package in editable mode and run the test suite with:

```bash
python -m pip install -r requirements-dev.txt
python -m pip install --no-deps -e .
python -m pytest
```

See `README.md` for configuration, operation, web UI security considerations,
and deployment details.
