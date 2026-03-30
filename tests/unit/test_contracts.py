from contracts.messages import SamplePrepCommand, BehaviorAnalyzedEvent
from contracts.job import JobEnvelope, JobStatus
from contracts.decisions import DecisionAction
from contracts.messages import DecisionIssuedEvent


def test_job_envelope_defaults():
    env = JobEnvelope(sample_id="s1", source_path="src", project_name="p", language="c")
    assert env.job_id
    assert env.num_functions == 3


def test_sample_prep_command_fields():
    cmd = SamplePrepCommand(
        job_id="j1",
        sample_id="s1",
        correlation_id="c1",
        source_path="/tmp/src",
        project_name="proj",
        language="c",
    )
    assert cmd.project_name == "proj"


def test_behavior_event_fields():
    ev = BehaviorAnalyzedEvent(
        job_id="j1",
        sample_id="s1",
        correlation_id="c1",
        analysis_result_id="a1",
        score=1.0,
        detection_count=2,
        ioc_count=3,
        ttp_count=1,
        analysis_method="rule_only",
    )
    assert ev.analysis_method == "rule_only"


def test_decision_action_retry_with_mutation_exists():
    assert DecisionAction.RETRY_WITH_MUTATION.value == "retry_with_mutation"


def test_decision_issued_event_autonomy_fields_default():
    ev = DecisionIssuedEvent(
        job_id="j1",
        sample_id="s1",
        correlation_id="c1",
        decision_id="d1",
        action="retry_with_mutation",
        source="policy_override",
        confidence=0.9,
    )
    assert ev.autonomous_dispatched is False
    assert ev.next_mutation_strategy == ""
