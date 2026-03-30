#!/usr/bin/env python
"""Test SandboxSubmittedEvent serialization/deserialization."""

import json
from datetime import datetime, timezone
from contracts.messages import SandboxSubmittedEvent

# Create an event like SandboxSubmitAgent does
event = SandboxSubmittedEvent(
    job_id="test-job-id",
    sample_id="test-sample",
    correlation_id="test-corr-id",
    sandbox_task_id="98",
    sandbox_backend="cape",
    submit_time=datetime.now(tz=timezone.utc).isoformat(),
)

print("Original event:")
print(f"  Fields: {event.model_fields_set}")
print(f"  Dict: {event.model_dump()}")
print()

# Simulate what happens in MemoryBroker.publish()
json_str = event.model_dump_json()
data_dict = json.loads(json_str)

print("After JSON serialize/deserialize:")
print(f"  Keys: {sorted(data_dict.keys())}")
print(f"  Dict: {data_dict}")
print()

# Check if the required fields are present
required_keys = frozenset({"sandbox_task_id", "sandbox_backend", "submit_time"})
present_keys = frozenset(data_dict.keys())

print(f"Required keys: {sorted(required_keys)}")
print(f"Present keys: {sorted(present_keys)}")
print(f"Required subset of present: {required_keys.issubset(present_keys)}")
