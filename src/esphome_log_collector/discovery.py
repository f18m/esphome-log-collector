"""Optional mDNS discovery of ESPHome devices (`_esphomelib._tcp.local.`).

The ESPHome CLI in the pinned version has no reliable discovery command, so discovery
uses zeroconf directly, which is what ESPHome itself advertises over. Discovery is
always restricted by explicit filters (names / name_prefixes) unless `allow_all` is set.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .config import DEVICE_NAME_RE, Config, ConfigError, DeviceConfig, DiscoveryConfig, make_discovered_device

log = logging.getLogger("discovery")
SERVICE_TYPE = "_esphomelib._tcp.local."


@dataclass(frozen=True)
class Discovered:
    name: str
    address: str | None


def matches_filter(name: str, cfg: DiscoveryConfig) -> bool:
    lowered = name.lower()
    if lowered in {n.lower() for n in cfg.exclude_names}:
        return False
    if cfg.allow_all:
        return True
    return lowered in {n.lower() for n in cfg.names} or any(lowered.startswith(p.lower()) for p in cfg.name_prefixes)


def new_targets(
    found: Iterable[Discovered], cfg: DiscoveryConfig, existing: Iterable[DeviceConfig]
) -> list[Discovered]:
    """Apply filters and drop devices that are already configured/collected (deduplication)."""
    taken_names: set[str] = set()
    taken_addresses: set[str] = set()
    for dev in existing:
        taken_names.add(dev.name.lower())
        if dev.esphome_name:
            taken_names.add(dev.esphome_name.lower())
        if dev.address:
            taken_addresses.add(dev.address.lower())
    result: list[Discovered] = []
    for item in sorted(found, key=lambda d: d.name.lower()):
        if not matches_filter(item.name, cfg):
            log.debug("discovered %s ignored: does not match discovery filters", item.name)
            continue
        if item.name.lower() in taken_names or (item.address and item.address.lower() in taken_addresses):
            log.debug("discovered %s is already configured; not duplicating", item.name)
            continue
        if not item.address:
            log.warning("discovered %s has no usable address; skipping", item.name)
            continue
        if not DEVICE_NAME_RE.match(item.name):
            log.warning("discovered device name %r is not a valid collector device name; skipping", item.name)
            continue
        taken_names.add(item.name.lower())
        taken_addresses.add(item.address.lower())
        result.append(item)
    return result


async def scan(timeout: float) -> list[Discovered]:
    """Browse mDNS for `timeout` seconds and resolve IPv4 addresses."""
    from zeroconf import IPVersion, ServiceStateChange
    from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

    names: set[str] = set()

    def on_change(zeroconf, service_type, name, state_change) -> None:
        if state_change in (ServiceStateChange.Added, ServiceStateChange.Updated):
            names.add(name)

    azc = AsyncZeroconf(ip_version=IPVersion.V4Only)
    try:
        browser = AsyncServiceBrowser(azc.zeroconf, SERVICE_TYPE, handlers=[on_change])
        await asyncio.sleep(timeout)
        await browser.async_cancel()
        found: list[Discovered] = []
        for service in sorted(names):
            info = AsyncServiceInfo(SERVICE_TYPE, service)
            if not await info.async_request(azc.zeroconf, 3000):
                log.warning("could not resolve mDNS service %s", service)
                continue
            addrs = info.parsed_addresses(IPVersion.V4Only)
            found.append(Discovered(service[: -len("." + SERVICE_TYPE)], addrs[0] if addrs else None))
        return found
    finally:
        await azc.async_close()


def config_for(config: Config, name: str) -> str | None:
    if not config.discovery.config_dir:
        return None
    candidate = Path(config.discovery.config_dir) / f"{name}.yaml"
    return str(candidate) if candidate.is_file() else None


async def discovery_loop(
    config: Config, stop: asyncio.Event, current: Callable[[], list[DeviceConfig]],
    add_device: Callable[[DeviceConfig], bool],
    scanner: Callable[[float], "asyncio.Future[list[Discovered]]"] = scan,
) -> None:
    cfg = config.discovery
    while not stop.is_set():
        try:
            found = await scanner(cfg.scan_timeout)
        except OSError as err:
            log.error("mDNS discovery failed: %s (is multicast reachable? see README, 'Discovery')", err)
            found = []
        log.info("discovery: %d ESPHome device(s) found", len(found))
        for item in new_targets(found, cfg, [*config.devices, *current()]):
            try:
                device = make_discovered_device(config, item.name, item.address or "", config_for(config, item.name))
            except ConfigError as err:
                log.error("discovered device %s cannot be collected: %s", item.name, err)
                continue
            add_device(device)
        if not cfg.interval_seconds:
            return
        try:
            await asyncio.wait_for(stop.wait(), timeout=cfg.interval_seconds)
        except asyncio.TimeoutError:
            pass
