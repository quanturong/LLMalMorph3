import importlib.util
import sys
import types
from pathlib import Path


def _load_exec_monitor_agent():
    root = Path(__file__).resolve().parents[2]

    agents_pkg = types.ModuleType("agents")
    agents_pkg.__path__ = [str(root / "agents")]
    sys.modules.setdefault("agents", agents_pkg)

    base_agent = types.ModuleType("agents.base_agent")
    base_agent.BaseAgent = object
    sys.modules.setdefault("agents.base_agent", base_agent)

    broker_topics = types.ModuleType("broker.topics")
    broker_topics.Topic = types.SimpleNamespace(
        CMD_EXEC_MONITOR="cmd_exec_monitor",
        CG_EXEC_MONITOR="cg_exec_monitor",
        CG_EVENTS_EXEC_MONITOR="cg_events_exec_monitor",
        EVENTS_ALL="events_all",
    )
    sys.modules.setdefault("broker", types.ModuleType("broker"))
    sys.modules.setdefault("broker.topics", broker_topics)

    contracts_job = types.ModuleType("contracts.job")
    contracts_job.JobStatus = types.SimpleNamespace(
        SANDBOX_SUBMITTED="SANDBOX_SUBMITTED",
        EXECUTION_MONITORING="EXECUTION_MONITORING",
        EXECUTION_COMPLETE="EXECUTION_COMPLETE",
        EXECUTION_FAILED="EXECUTION_FAILED",
    )
    sys.modules.setdefault("contracts", types.ModuleType("contracts"))
    sys.modules.setdefault("contracts.job", contracts_job)

    contracts_messages = types.ModuleType("contracts.messages")

    class _Event:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    contracts_messages.ExecutionCompletedEvent = _Event
    contracts_messages.ExecutionFailedEvent = _Event
    sys.modules.setdefault("contracts.messages", contracts_messages)

    spec = importlib.util.spec_from_file_location(
        "agents.exec_monitor_agent",
        root / "agents" / "exec_monitor_agent.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["agents.exec_monitor_agent"] = module
    spec.loader.exec_module(module)
    return module


_is_cape_report_ready = _load_exec_monitor_agent()._is_cape_report_ready


def test_cape_not_ready_error_payload_is_not_report():
    raw = {
        "error": True,
        "error_value": "Task is still being analyzed",
    }

    assert _is_cape_report_ready(raw) is False


def test_sparse_cape_report_with_metadata_is_ready():
    raw = {
        "info": {"id": 123},
        "target": {"file": {"name": "sample.exe"}},
        "behavior": {"processes": [], "summary": {}},
    }

    assert _is_cape_report_ready(raw) is True


def test_behavioral_cape_report_is_ready():
    raw = {
        "behavior": {
            "processes": [
                {"process_name": "sample.exe", "calls": [{"api": "CreateFileW"}]}
            ],
            "summary": {},
        }
    }

    assert _is_cape_report_ready(raw) is True
