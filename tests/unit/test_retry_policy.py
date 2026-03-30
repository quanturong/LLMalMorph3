from workflows.retry_policy import classify_error, get_retry_decision, ErrorClass


def test_classify_error_known():
    assert classify_error("SANDBOX_TIMEOUT") == ErrorClass.SANDBOX_TIMEOUT


def test_retry_decision_retries_then_stops():
    d1 = get_retry_decision("SANDBOX_TIMEOUT", current_retry_count=0, job_total_retries=0)
    assert d1.should_retry is True
    d2 = get_retry_decision("SANDBOX_TIMEOUT", current_retry_count=3, job_total_retries=0)
    assert d2.should_retry is False


def test_retry_budget_exhausted():
    d = get_retry_decision("NETWORK_TIMEOUT", current_retry_count=0, job_total_retries=10)
    assert d.should_retry is False
