"""Scan orchestrator: controlled concurrency, rate limiting, timeouts, retries.

Replaces ShadowPortX 1.0's fixed 100-thread pool with an asyncio worker model that is
faster, backpressure-aware, and technique-agnostic. Open ports are optionally enriched
with a banner grab and protocol-first service detection.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from shadowportx.core import enums
from shadowportx.core.config import settings
from shadowportx.engines.results import PortResult
from shadowportx.engines.scanner import (
    banner as banner_mod,
)
from shadowportx.engines.scanner import (
    service_detector,
    syn_scanner,
    tcp_scanner,
    udp_scanner,
)

ProgressCb = Callable[[int, int], Awaitable[None] | None]


@dataclass
class ScanConfig:
    ports: list[int]
    technique: enums.ScanType = enums.ScanType.TCP_CONNECT
    concurrency: int = settings.scan_max_concurrency
    connect_timeout: float = settings.scan_connect_timeout
    banner_timeout: float = settings.scan_banner_timeout
    rate_limit_per_sec: int = settings.scan_rate_limit_per_sec
    retries: int = settings.scan_retries
    grab_banners: bool = True
    detect_services: bool = True
    notes: list[str] = field(default_factory=list)


class RateLimiter:
    """Simple async token bucket. ``rate<=0`` disables limiting."""

    def __init__(self, rate_per_sec: int):
        self.rate = rate_per_sec
        self._tokens = float(rate_per_sec)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.rate <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(self.rate, self._tokens + (now - self._last) * self.rate)
            self._last = now
            if self._tokens < 1:
                await asyncio.sleep((1 - self._tokens) / self.rate)
                self._tokens = 0.0
            else:
                self._tokens -= 1


class ScanOrchestrator:
    def __init__(self, config: ScanConfig):
        self.config = config
        self._resolve_technique()

    def _resolve_technique(self) -> None:
        """Pick the probe function, falling back from SYN to connect if needed."""
        t = self.config.technique
        if t == enums.ScanType.UDP:
            self._probe = udp_scanner.probe
        elif t == enums.ScanType.TCP_SYN:
            available, err = syn_scanner.is_available()
            if available:
                self._probe = syn_scanner.probe
            else:
                self.config.technique = enums.ScanType.TCP_CONNECT
                self._probe = tcp_scanner.probe
                self.config.notes.append(
                    f"SYN scan unavailable ({err}); fell back to TCP connect scan."
                )
        else:
            self._probe = tcp_scanner.probe

    async def _probe_port(self, host: str, port: int) -> PortResult | None:
        timeout = self.config.connect_timeout
        last_exc: Exception | None = None
        for attempt in range(self.config.retries + 1):
            try:
                result = await self._probe(host, port, timeout)
                if result is not None:
                    return result
                if attempt < self.config.retries:
                    continue
                return None
            except syn_scanner.SynScanUnavailable:
                raise
            except Exception as exc:  # noqa: BLE001 - retry transient probe errors
                last_exc = exc
                await asyncio.sleep(0.05)
        if last_exc:
            return None
        return None

    async def _enrich(self, result: PortResult) -> None:
        if result.protocol != enums.Protocol.TCP:
            return
        if self.config.grab_banners or self.config.detect_services:
            banner = await banner_mod.grab_banner(
                result.host, result.port, self.config.banner_timeout
            )
            result.banner = banner
            if self.config.detect_services:
                result.service = service_detector.detect(result.port, banner)

    async def run(self, host: str, progress_cb: ProgressCb | None = None) -> list[PortResult]:
        limiter = RateLimiter(self.config.rate_limit_per_sec)
        sem = asyncio.Semaphore(max(1, self.config.concurrency))
        total = len(self.config.ports)
        completed = 0
        results: list[PortResult] = []
        lock = asyncio.Lock()

        async def worker(port: int) -> None:
            nonlocal completed
            async with sem:
                await limiter.acquire()
                res = await self._probe_port(host, port)
                if res is not None:
                    await self._enrich(res)
                    async with lock:
                        results.append(res)
            async with lock:
                completed += 1
                if progress_cb and (completed % 25 == 0 or completed == total):
                    maybe = progress_cb(completed, total)
                    if asyncio.iscoroutine(maybe):
                        await maybe

        await asyncio.gather(*(worker(p) for p in self.config.ports))
        results.sort(key=lambda r: r.port)
        return results
