from contracts.job import JobState, JobStatus
from workflows.state_machine import JobStateMachine, InvalidTransitionError


def test_valid_transition_created_to_sample_preparing():
    sm = JobStateMachine()
    s = JobState(job_id="j1", sample_id="s1", correlation_id="c1")
    sm.transition(s, JobStatus.SAMPLE_PREPARING, triggered_by="test")
    assert s.current_status == JobStatus.SAMPLE_PREPARING


def test_invalid_transition_raises():
    sm = JobStateMachine()
    s = JobState(job_id="j1", sample_id="s1", correlation_id="c1")
    try:
        sm.transition(s, JobStatus.REPORT_READY, triggered_by="test")
        assert False, "expected InvalidTransitionError"
    except InvalidTransitionError:
        assert True


def test_valid_transition_decision_issued_to_build_validating():
    sm = JobStateMachine()
    s = JobState(job_id="j1", sample_id="s1", correlation_id="c1")
    sm.transition(s, JobStatus.SAMPLE_PREPARING, triggered_by="test")
    sm.transition(s, JobStatus.SAMPLE_READY, triggered_by="test")
    sm.transition(s, JobStatus.BUILD_VALIDATING, triggered_by="test")
    sm.transition(s, JobStatus.BUILD_READY, triggered_by="test")
    sm.transition(s, JobStatus.SANDBOX_SUBMITTING, triggered_by="test")
    sm.transition(s, JobStatus.SANDBOX_SUBMITTED, triggered_by="test")
    sm.transition(s, JobStatus.EXECUTION_MONITORING, triggered_by="test")
    sm.transition(s, JobStatus.EXECUTION_COMPLETE, triggered_by="test")
    sm.transition(s, JobStatus.BEHAVIOR_ANALYZING, triggered_by="test")
    sm.transition(s, JobStatus.BEHAVIOR_ANALYZED, triggered_by="test")
    sm.transition(s, JobStatus.DECIDING, triggered_by="test")
    sm.transition(s, JobStatus.DECISION_ISSUED, triggered_by="test")
    sm.transition(s, JobStatus.BUILD_VALIDATING, triggered_by="test")
    assert s.current_status == JobStatus.BUILD_VALIDATING
