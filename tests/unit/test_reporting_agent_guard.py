"""
Regression tests for ReportingAgent.activates_on guard.

Guard rules:
  - ReportingAgent claims: continue_to_report, escalate_to_analyst, close_no_behavior, close_failed
  - ReportingAgent MUST NOT claim: retry_with_mutation (→ MutationAgent), retry_sandbox (→ SandboxSubmitAgent)

Without the guard, ReportingAgent would claim retry_with_mutation events via CAS before
MutationAgent could, closing the job instead of retrying mutation.
"""

from agents.reporting_agent import ReportingAgent
from agents.sandbox_submit_agent import SandboxSubmitAgent
from contracts.job import JobStatus
from contracts.messages import DecisionIssuedEvent


def _make_event(action: str) -> dict:
    return DecisionIssuedEvent(
        job_id="j1",
        sample_id="s1",
        correlation_id="c1",
        decision_id="d1",
        action=action,
        source="policy_override",
        confidence=0.9,
    ).model_dump(mode="python")


class _StubReportingAgent(ReportingAgent):
    """Minimal concrete subclass so we can instantiate without a real ctx."""
    def __init__(self):
        pass

    async def handle(self, data):
        pass


class _StubSandboxAgent(SandboxSubmitAgent):
    """Minimal concrete subclass so we can instantiate without a real ctx."""
    def __init__(self):
        pass

    async def handle(self, data):
        pass


_reporting = _StubReportingAgent()
_sandbox = _StubSandboxAgent()


# ── ReportingAgent: should activate ────────────────────────────────────────

def test_reporting_agent_activates_on_continue_to_report():
    result = _reporting._match_activation(_make_event("continue_to_report"))
    assert result == (JobStatus.DECISION_ISSUED, JobStatus.REPORTING)


def test_reporting_agent_activates_on_escalate_to_analyst():
    """Terminal escalation — ReportingAgent closes the job and submits VT."""
    result = _reporting._match_activation(_make_event("escalate_to_analyst"))
    assert result == (JobStatus.DECISION_ISSUED, JobStatus.REPORTING)


def test_reporting_agent_activates_on_close_failed():
    result = _reporting._match_activation(_make_event("close_failed"))
    assert result == (JobStatus.DECISION_ISSUED, JobStatus.REPORTING)


def test_reporting_agent_activates_on_close_no_behavior():
    result = _reporting._match_activation(_make_event("close_no_behavior"))
    assert result == (JobStatus.DECISION_ISSUED, JobStatus.REPORTING)


# ── ReportingAgent: must NOT activate ─────────────────────────────────────

def test_reporting_agent_does_not_activate_on_retry_with_mutation():
    """Must not claim — MutationAgent owns this path."""
    result = _reporting._match_activation(_make_event("retry_with_mutation"))
    assert result is None, (
        "ReportingAgent must NOT self-activate on retry_with_mutation "
        "(race condition: would close the job before MutationAgent can claim it)"
    )


def test_reporting_agent_does_not_activate_on_retry_sandbox():
    """Must not claim — SandboxSubmitAgent owns this path."""
    result = _reporting._match_activation(_make_event("retry_sandbox"))
    assert result is None


# ── SandboxSubmitAgent: retry_sandbox path ─────────────────────────────────

def test_sandbox_agent_activates_on_retry_sandbox():
    """SandboxSubmitAgent must self-activate on retry_sandbox in production."""
    result = _sandbox._match_activation(_make_event("retry_sandbox"))
    assert result == (JobStatus.DECISION_ISSUED, JobStatus.SANDBOX_SUBMITTING)


def test_sandbox_agent_does_not_activate_on_continue_to_report():
    result = _sandbox._match_activation(_make_event("continue_to_report"))
    # Only matches if decision_id/action/confidence/source keys are present — they are,
    # but guard lambda blocks non-retry_sandbox actions.
    assert result is None


def test_sandbox_agent_does_not_activate_on_retry_with_mutation():
    result = _sandbox._match_activation(_make_event("retry_with_mutation"))
    assert result is None
