"""
Job state machine — defines valid transitions and guards.

The Coordinator calls `transition()` for every event received.
Invalid transitions raise `InvalidTransitionError` rather than silently
corrupting state.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Optional, Set, Tuple

from contracts.job import JobState, JobStatus


class InvalidTransitionError(Exception):
    def __init__(self, from_state: JobStatus, to_state: JobStatus, reason: str = ""):
        super().__init__(
            f"Invalid transition: {from_state.value} → {to_state.value}"
            + (f" ({reason})" if reason else "")
        )
        self.from_state = from_state
        self.to_state = to_state


# ──────────────────────────────────────────────────────────────────────────────
# Valid transition map
# Format: from_state → set of allowed to_states
# ──────────────────────────────────────────────────────────────────────────────

VALID_TRANSITIONS: Dict[JobStatus, FrozenSet[JobStatus]] = {
    JobStatus.CREATED: frozenset({
        JobStatus.SAMPLE_PREPARING,
        JobStatus.FAILED,
    }),
    JobStatus.SAMPLE_PREPARING: frozenset({
        JobStatus.SAMPLE_READY,
        JobStatus.RETRY_PENDING,
        JobStatus.FAILED,
    }),
    JobStatus.SAMPLE_READY: frozenset({
        JobStatus.MUTATING,
        JobStatus.BUILD_VALIDATING,   # bypass mutation when no strategies
        JobStatus.FAILED,
    }),
    JobStatus.MUTATING: frozenset({
        JobStatus.MUTATION_READY,
        JobStatus.RETRY_PENDING,
        JobStatus.FAILED,
    }),
    JobStatus.MUTATION_READY: frozenset({
        JobStatus.VARIANT_GENERATING,
        JobStatus.FAILED,
    }),
    JobStatus.VARIANT_GENERATING: frozenset({
        JobStatus.VARIANT_READY,
        JobStatus.RETRY_PENDING,
        JobStatus.FAILED,
    }),
    JobStatus.VARIANT_READY: frozenset({
        JobStatus.BUILD_VALIDATING,
        JobStatus.FAILED,
    }),
    JobStatus.BUILD_VALIDATING: frozenset({
        JobStatus.BUILD_READY,
        JobStatus.BUILD_FAILED,
        JobStatus.RETRY_PENDING,
        JobStatus.FAILED,
    }),
    JobStatus.BUILD_FAILED: frozenset({
        JobStatus.BUILD_VALIDATING,   # retry
        JobStatus.FAILED,
        JobStatus.ESCALATED,
    }),
    JobStatus.BUILD_READY: frozenset({
        JobStatus.SANDBOX_SUBMITTING,
        JobStatus.FAILED,
    }),
    JobStatus.SANDBOX_SUBMITTING: frozenset({
        JobStatus.SANDBOX_SUBMITTED,
        JobStatus.RETRY_PENDING,
        JobStatus.FAILED,
    }),
    JobStatus.SANDBOX_SUBMITTED: frozenset({
        JobStatus.EXECUTION_MONITORING,
        JobStatus.FAILED,
    }),
    JobStatus.EXECUTION_MONITORING: frozenset({
        JobStatus.EXECUTION_COMPLETE,
        JobStatus.EXECUTION_FAILED,
        JobStatus.FAILED,
    }),
    JobStatus.EXECUTION_FAILED: frozenset({
        JobStatus.SANDBOX_SUBMITTING,  # retry sandbox
        JobStatus.FAILED,
        JobStatus.ESCALATED,
    }),
    JobStatus.EXECUTION_COMPLETE: frozenset({
        JobStatus.BEHAVIOR_ANALYZING,
        JobStatus.FAILED,
    }),
    JobStatus.BEHAVIOR_ANALYZING: frozenset({
        JobStatus.BEHAVIOR_ANALYZED,
        JobStatus.RETRY_PENDING,
        JobStatus.FAILED,
    }),
    JobStatus.BEHAVIOR_ANALYZED: frozenset({
        JobStatus.DECIDING,
        JobStatus.FAILED,
    }),
    JobStatus.DECIDING: frozenset({
        JobStatus.DECISION_ISSUED,
        JobStatus.FAILED,
    }),
    JobStatus.DECISION_ISSUED: frozenset({
        JobStatus.REPORTING,
        JobStatus.SANDBOX_SUBMITTING,  # decision = retry_sandbox
        JobStatus.BUILD_VALIDATING,    # decision = retry_with_mutation (legacy)
        JobStatus.MUTATING,            # decision = retry_with_mutation (new flow)
        JobStatus.ESCALATED,           # decision = escalate
        JobStatus.CLOSED,              # decision = close_no_behavior / close_failed
        JobStatus.FAILED,
    }),
    JobStatus.REPORTING: frozenset({
        JobStatus.REPORT_READY,
        JobStatus.RETRY_PENDING,
        JobStatus.FAILED,
    }),
    JobStatus.REPORT_READY: frozenset({
        JobStatus.CLOSED,
    }),
    JobStatus.RETRY_PENDING: frozenset({
        # Re-entry points after a delay
        JobStatus.SAMPLE_PREPARING,
        JobStatus.MUTATING,
        JobStatus.VARIANT_GENERATING,
        JobStatus.BUILD_VALIDATING,
        JobStatus.SANDBOX_SUBMITTING,
        JobStatus.BEHAVIOR_ANALYZING,
        JobStatus.REPORTING,
        JobStatus.FAILED,
    }),
    # Terminal states — no outbound transitions
    JobStatus.CLOSED:    frozenset(),
    JobStatus.FAILED:    frozenset(),
    JobStatus.ESCALATED: frozenset(),
}


# ──────────────────────────────────────────────────────────────────────────────
# State machine
# ──────────────────────────────────────────────────────────────────────────────

class JobStateMachine:
    """
    Validates and applies state transitions for a JobState.

    Usage:
        sm = JobStateMachine()
        sm.transition(job_state, JobStatus.SAMPLE_PREPARING, triggered_by="coordinator")
    """

    def __init__(self, transitions: Optional[Dict] = None) -> None:
        self._transitions = transitions or VALID_TRANSITIONS

    def can_transition(self, from_status: JobStatus, to_status: JobStatus) -> bool:
        allowed = self._transitions.get(from_status, frozenset())
        return to_status in allowed

    def transition(
        self,
        state: JobState,
        to_status: JobStatus,
        triggered_by: str,
        event_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> None:
        """
        Apply a transition to a JobState in place.
        Raises InvalidTransitionError if the transition is not allowed.
        """
        if not self.can_transition(state.current_status, to_status):
            raise InvalidTransitionError(
                state.current_status, to_status,
                f"triggered_by={triggered_by}"
            )
        state.transition_to(to_status, triggered_by, event_id, reason)

    def allowed_next_states(self, from_status: JobStatus) -> FrozenSet[JobStatus]:
        return self._transitions.get(from_status, frozenset())
