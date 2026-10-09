"""Docker-friendly collector that retains ESPHome firmware logs."""

try:
    from ._version import __version__
except ModuleNotFoundError as exc:
    if exc.name != f"{__package__}._version":
        raise
    __version__ = "0.1.0"

SUPPORTED_ESPHOME_VERSION = "2026.9.1"
