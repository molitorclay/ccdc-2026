from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from time import perf_counter

from vikings_ssh.models import ReachabilityResult, Target


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_target_reachability(target: Target, timeout: float = 1.5) -> ReachabilityResult:
    started = perf_counter()
    checked_at = _utc_now_iso()
    try:
        with socket.create_connection((target.host, target.port), timeout=timeout):
            latency_ms = (perf_counter() - started) * 1000
            return ReachabilityResult(
                target=target,
                reachable=True,
                checked_at=checked_at,
                latency_ms=round(latency_ms, 2),
            )
    except OSError as exc:
        return ReachabilityResult(
            target=target,
            reachable=False,
            checked_at=checked_at,
            error=str(exc),
        )


def scan_targets(targets: list[Target], timeout: float = 1.5, workers: int = 16) -> list[ReachabilityResult]:
    if not targets:
        return []

    worker_count = max(1, min(workers, len(targets)))
    indexed_targets = list(enumerate(targets))
    results_by_index: dict[int, ReachabilityResult] = {}

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(check_target_reachability, target, timeout): index
            for index, target in indexed_targets
        }
        for future, index in future_map.items():
            results_by_index[index] = future.result()

    return [results_by_index[index] for index in range(len(targets))]

