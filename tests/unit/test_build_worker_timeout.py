import time

import pytest

from agents.build_validation_agent import (
    _run_build_worker_process,
    _write_worker_payload,
)


def _worker_success(result_path, value):
    _write_worker_payload(result_path, {"ok": True, "value": value})


def _worker_hangs(result_path):
    time.sleep(30)


def test_build_worker_process_returns_payload():
    payload = _run_build_worker_process(_worker_success, ("done",), timeout_s=5)

    assert payload == {"ok": True, "value": "done"}


def test_build_worker_process_hard_times_out():
    start = time.monotonic()

    with pytest.raises(TimeoutError, match="timed out"):
        _run_build_worker_process(_worker_hangs, tuple(), timeout_s=1)

    assert time.monotonic() - start < 10
