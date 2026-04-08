"""
Coordinator Agent — workflow lifecycle and state machine manager.

This agent:
  - Listens to the events stream (all agent outputs)
  - Maintains JobState for each active job
  - Applies state transitions via JobStateMachine
  - Emits the next command to the appropriate agent
  - Handles retry scheduling and escalation

The Coordinator does NOT contain business logic (parsing, compiling, analyzing).
It knows ONLY the workflow map: which event triggers which next step.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

import structlog

from broker.interface import AcknowledgeableMessage
from broker.topics import Topic
from contracts.job import JobEnvelope, JobState, JobStatus
from contracts.messages import (
    AnalyzeBehaviorCommand,
    BehaviorAnalyzedEvent,
    BuildFailedEvent,
    BuildValidateCommand,
    BuildValidatedEvent,
    DecideCommand,
    DecisionIssuedEvent,
    ErrorEvent,
    EscalationEvent,
    ExecutionCompletedEvent,
    ExecutionFailedEvent,
    GenerateVariantCommand,
    JobClosedEvent,
    JobCreatedEvent,
    JobFailedEvent,
    MutateCommand,
    MutationCompletedEvent,
    ReportCommand,
    ReportGeneratedEvent,
    SamplePrepCommand,
    SamplePreparedEvent,
    SandboxSubmitCommand,
    SandboxSubmittedEvent,
    VariantGeneratedEvent,
)
from workflows.policy import PolicyEngine
from workflows.retry_policy import ErrorClass, classify_error, get_retry_decision
from workflows.state_machine import InvalidTransitionError, JobStateMachine

from .base_agent import AgentContext, BaseAgent

logger = structlog.get_logger(__name__)


class CoordinatorAgent(BaseAgent):
    """
    Single-instance agent responsible for job lifecycle management.

    Rule: The Coordinator routes messages, it does NOT process them.
    """

    agent_name = "CoordinatorAgent"
    command_stream = Topic.EVENTS_ALL
    consumer_group = Topic.CG_COORDINATOR

    def __init__(self, ctx: AgentContext, output_base_dir: str = "") -> None:
        super().__init__(ctx)
        self._sm = JobStateMachine()
        self._policy = PolicyEngine()
        self._output_base_dir = output_base_dir or ctx.work_dir

    # ──────────────────────────────────────────────────────────────────────
    # Public: submit a new job
    # ──────────────────────────────────────────────────────────────────────

    async def submit_job(self, envelope: JobEnvelope) -> str:
        """
        Entry point for creating a new job.
        Creates initial JobState and emits JobCreatedEvent.
        Returns job_id.
        """
        state = JobState(
            job_id=envelope.job_id,
            sample_id=envelope.sample_id,
            correlation_id=envelope.correlation_id,
            project_name=envelope.project_name,
            language=envelope.language,
            requested_strategies=envelope.requested_strategies,
        )
        await self._save_state(state)

        event = JobCreatedEvent(
            job_id=envelope.job_id,
            sample_id=envelope.sample_id,
            correlation_id=envelope.correlation_id,
            source_path=envelope.source_path,
            project_name=envelope.project_name,
            language=envelope.language,
            requested_strategies=envelope.requested_strategies,
            num_functions=envelope.num_functions,
            sandbox_backend=envelope.sandbox_backend,
            priority=envelope.priority,
        )
        await self._ctx.broker.publish(Topic.EVENTS_ALL, event)
        logger.info("job_submitted", job_id=envelope.job_id, project=envelope.project_name)
        return envelope.job_id

    # ──────────────────────────────────────────────────────────────────────
    # Main event handler
    # ──────────────────────────────────────────────────────────────────────

    async def handle(self, data: dict) -> None:
        event_type = data.get("event_type") or data.get("__class__")
        job_id = data.get("job_id", "")

        # Determine event type from field presence (duck-typing)
        if "source_path" in data and "language" in data:
            await self._on_job_created(data)
        elif "source_artifact_id" in data and "num_source_files" in data:
            await self._on_sample_prepared(data)
        elif "mutation_artifact_id" in data and "num_functions_mutated" in data:
            await self._on_mutation_completed(data)
        elif "variant_artifact_id" in data and "num_files_generated" in data:
            await self._on_variant_generated(data)
        elif "compiled_artifact_id" in data and "binary_sha256" in data:
            await self._on_build_validated(data)
        elif "compiled_artifact_id" not in data and "auto_fix_attempts" in data:
            await self._on_build_failed(data)
        elif "sandbox_task_id" in data and "submit_time" in data:
            await self._on_sandbox_submitted(data)
        elif "raw_report_artifact_id" in data and "analysis_duration_s" in data:
            await self._on_execution_completed(data)
        elif "failure_reason" in data and "sandbox_task_id" in data:
            await self._on_execution_failed(data)
        elif "analysis_result_id" in data and "ioc_count" in data:
            await self._on_behavior_analyzed(data)
        elif "decision_id" in data and "action" in data:
            await self._on_decision_issued(data)
        elif "report_id" in data and "report_path" in data:
            await self._on_report_generated(data)
        elif "error_code" in data and "agent" in data:
            await self._on_error(data)
        else:
            logger.debug("coordinator_unknown_event", data_keys=list(data.keys()))

    # ──────────────────────────────────────────────────────────────────────
    # Event handlers
    # ──────────────────────────────────────────────────────────────────────

    async def _on_job_created(self, data: dict) -> None:
        state = await self._load_or_create_state(data)
        state.project_name = data.get("project_name", state.project_name)
        state.language = data.get("language", state.language)
        state.requested_strategies = data.get("requested_strategies", state.requested_strategies)
        state.num_functions = data.get("num_functions", state.num_functions)
        self._sm.transition(state, JobStatus.SAMPLE_PREPARING, "coordinator")
        await self._save_state(state)

        cmd = SamplePrepCommand(
            job_id=data["job_id"],
            sample_id=data["sample_id"],
            correlation_id=data["correlation_id"],
            source_path=data["source_path"],
            project_name=data["project_name"],
            language=data["language"],
            num_functions=data.get("num_functions", 3),
            requested_strategies=data.get("requested_strategies", []),
        )
        await self._ctx.broker.publish(Topic.CMD_SAMPLE_PREP, cmd)
        logger.info("dispatched_sample_prep", job_id=data["job_id"])

    async def _on_sample_prepared(self, data: dict) -> None:
        state = await self._get_state(data["job_id"])
        if state is None:
            return
        state.source_artifact_id = data["source_artifact_id"]
        if data.get("requested_strategies"):
            state.requested_strategies = data.get("requested_strategies", [])
        self._sm.transition(state, JobStatus.SAMPLE_READY, "coordinator",
                            event_id=data.get("message_id"))

        # Route to Mutation stage (new multi-agent flow)
        self._sm.transition(state, JobStatus.MUTATING, "coordinator")
        await self._save_state(state)

        strategy = self._pick_next_mutation_strategy(state)
        cmd = MutateCommand(
            job_id=data["job_id"],
            sample_id=data["sample_id"],
            correlation_id=data["correlation_id"],
            source_artifact_id=data["source_artifact_id"],
            project_name=data["project_name"],
            language=data["language"],
            mutation_strategy=strategy,
            requested_strategies=data.get("requested_strategies", []),
            num_functions=state.num_functions,
            target_functions=state.target_functions,
        )
        await self._ctx.broker.publish(Topic.CMD_MUTATE, cmd)
        logger.info("dispatched_mutate", job_id=data["job_id"], strategy=strategy)

    async def _on_mutation_completed(self, data: dict) -> None:
        state = await self._get_state(data["job_id"])
        if state is None:
            return
        state.mutation_artifact_id = data["mutation_artifact_id"]
        self._sm.transition(state, JobStatus.MUTATION_READY, "coordinator",
                            event_id=data.get("message_id"))
        self._sm.transition(state, JobStatus.VARIANT_GENERATING, "coordinator")
        await self._save_state(state)

        cmd = GenerateVariantCommand(
            job_id=data["job_id"],
            sample_id=data["sample_id"],
            correlation_id=data["correlation_id"],
            source_artifact_id=state.source_artifact_id or data.get("source_artifact_id", ""),
            mutation_artifact_id=data["mutation_artifact_id"],
            project_name=data.get("project_name", state.project_name),
            language=data.get("language", state.language),
        )
        await self._ctx.broker.publish(Topic.CMD_GENERATE_VARIANT, cmd)
        logger.info("dispatched_generate_variant", job_id=data["job_id"])

    async def _on_variant_generated(self, data: dict) -> None:
        state = await self._get_state(data["job_id"])
        if state is None:
            return
        state.variant_artifact_id = data["variant_artifact_id"]
        self._sm.transition(state, JobStatus.VARIANT_READY, "coordinator",
                            event_id=data.get("message_id"))
        self._sm.transition(state, JobStatus.BUILD_VALIDATING, "coordinator")
        await self._save_state(state)

        # Now proceed to build using variant source
        cmd = BuildValidateCommand(
            job_id=data["job_id"],
            sample_id=data["sample_id"],
            correlation_id=data["correlation_id"],
            source_artifact_id=data["variant_artifact_id"],
            project_name=data.get("project_name", state.project_name),
            language=data.get("language", state.language),
            mutation_strategy=state.requested_strategies[0] if state.requested_strategies else "",
        )
        await self._ctx.broker.publish(Topic.CMD_BUILD_VALIDATE, cmd)
        logger.info("dispatched_build_validate_variant", job_id=data["job_id"])

    async def _on_build_validated(self, data: dict) -> None:
        state = await self._get_state(data["job_id"])
        if state is None:
            return
        state.compiled_artifact_id = data["compiled_artifact_id"]
        self._sm.transition(state, JobStatus.BUILD_READY, "coordinator",
                            event_id=data.get("message_id"))
        self._sm.transition(state, JobStatus.SANDBOX_SUBMITTING, "coordinator")
        await self._save_state(state)

        cmd = SandboxSubmitCommand(
            job_id=data["job_id"],
            sample_id=data["sample_id"],
            correlation_id=data["correlation_id"],
            compiled_artifact_id=data["compiled_artifact_id"],
        )
        await self._ctx.broker.publish(Topic.CMD_SANDBOX_SUBMIT, cmd)

    async def _on_build_failed(self, data: dict) -> None:
        state = await self._get_state(data["job_id"])
        if state is None:
            return
        state.add_error("BuildValidationAgent", "BUILD_FAILED", data.get("error_message", ""), False)
        self._sm.transition(state, JobStatus.BUILD_FAILED, "coordinator")
        state.retry_count += 1
        await self._save_state(state)
        await self._fail_job(state, "Build failed after auto-fix attempts exhausted")

    async def _on_sandbox_submitted(self, data: dict) -> None:
        state = await self._get_state(data["job_id"])
        if state is None:
            return
        state.sandbox_task_id = data["sandbox_task_id"]
        state.sandbox_backend = data["sandbox_backend"]
        self._sm.transition(state, JobStatus.SANDBOX_SUBMITTED, "coordinator",
                            event_id=data.get("message_id"))
        self._sm.transition(state, JobStatus.EXECUTION_MONITORING, "coordinator")
        await self._save_state(state)

        from contracts.messages import ExecMonitorCommand
        cmd = ExecMonitorCommand(
            job_id=data["job_id"],
            sample_id=data["sample_id"],
            correlation_id=data["correlation_id"],
            sandbox_task_id=data["sandbox_task_id"],
            sandbox_backend=data["sandbox_backend"],
        )
        await self._ctx.broker.publish(Topic.CMD_EXEC_MONITOR, cmd)

    async def _on_execution_completed(self, data: dict) -> None:
        state = await self._get_state(data["job_id"])
        if state is None:
            return
        state.raw_report_artifact_id = data["raw_report_artifact_id"]
        self._sm.transition(state, JobStatus.EXECUTION_COMPLETE, "coordinator",
                            event_id=data.get("message_id"))
        self._sm.transition(state, JobStatus.BEHAVIOR_ANALYZING, "coordinator")
        await self._save_state(state)

        cmd = AnalyzeBehaviorCommand(
            job_id=data["job_id"],
            sample_id=data["sample_id"],
            correlation_id=data["correlation_id"],
            raw_report_artifact_id=data["raw_report_artifact_id"],
            sandbox_backend=data.get("sandbox_backend", "cape"),
        )
        await self._ctx.broker.publish(Topic.CMD_ANALYZE_BEHAVIOR, cmd)

    async def _on_execution_failed(self, data: dict) -> None:
        state = await self._get_state(data["job_id"])
        if state is None:
            return
        state.add_error("ExecMonitorAgent", "SANDBOX_TIMEOUT", data.get("failure_reason", ""), True)
        self._sm.transition(state, JobStatus.EXECUTION_FAILED, "coordinator")

        decision = get_retry_decision(
            error_code="SANDBOX_TIMEOUT",
            current_retry_count=state.sandbox_retry_count,
            job_total_retries=state.retry_count,
        )
        if decision.should_retry:
            state.sandbox_retry_count += 1
            state.retry_count += 1
            self._sm.transition(state, JobStatus.SANDBOX_SUBMITTING, "coordinator",
                                reason="retry after execution failure")
            await self._save_state(state)
            # Re-queue sandbox submit after delay
            await asyncio.sleep(decision.delay_s)
            cmd = SandboxSubmitCommand(
                job_id=state.job_id,
                sample_id=state.sample_id,
                correlation_id=state.correlation_id,
                compiled_artifact_id=state.compiled_artifact_id or "",
                retry_count=state.sandbox_retry_count,
            )
            await self._ctx.broker.publish(Topic.CMD_SANDBOX_SUBMIT, cmd)
        else:
            await self._save_state(state)
            await self._escalate(state, f"Sandbox execution failed: {data.get('failure_reason')}")

    async def _on_behavior_analyzed(self, data: dict) -> None:
        state = await self._get_state(data["job_id"])
        if state is None:
            return
        state.analysis_result_id = data["analysis_result_id"]
        self._sm.transition(state, JobStatus.BEHAVIOR_ANALYZED, "coordinator",
                            event_id=data.get("message_id"))
        self._sm.transition(state, JobStatus.DECIDING, "coordinator")
        await self._save_state(state)

        cmd = DecideCommand(
            job_id=data["job_id"],
            sample_id=data["sample_id"],
            correlation_id=data["correlation_id"],
            analysis_result_id=data["analysis_result_id"],
            job_retry_count=state.retry_count,
        )
        await self._ctx.broker.publish(Topic.CMD_DECIDE, cmd)

    async def _on_decision_issued(self, data: dict) -> None:
        state = await self._get_state(data["job_id"])
        if state is None:
            return
        state.decision_id = data["decision_id"]
        self._sm.transition(state, JobStatus.DECISION_ISSUED, "coordinator",
                            event_id=data.get("message_id"))
        await self._save_state(state)

        action = data.get("action", "")
        job_id = data["job_id"]

        if action == "continue_to_report":
            self._sm.transition(state, JobStatus.REPORTING, "coordinator")
            await self._save_state(state)
            output_dir = f"{self._output_base_dir}/run_{state.job_id[:8]}"
            cmd = ReportCommand(
                job_id=job_id,
                sample_id=data["sample_id"],
                correlation_id=data["correlation_id"],
                analysis_result_id=state.analysis_result_id or "",
                decision_id=data["decision_id"],
                output_dir=output_dir,
            )
            await self._ctx.broker.publish(Topic.CMD_REPORT, cmd)

        elif action == "retry_sandbox":
            state.sandbox_retry_count += 1
            state.retry_count += 1
            self._sm.transition(state, JobStatus.SANDBOX_SUBMITTING, "coordinator",
                                reason="decision: retry_sandbox")
            await self._save_state(state)
            cmd = SandboxSubmitCommand(
                job_id=job_id,
                sample_id=data["sample_id"],
                correlation_id=data["correlation_id"],
                compiled_artifact_id=state.compiled_artifact_id or "",
                retry_count=state.sandbox_retry_count,
            )
            await self._ctx.broker.publish(Topic.CMD_SANDBOX_SUBMIT, cmd)

        elif action == "retry_with_mutation":
            if state.feedback_loop_count >= state.max_feedback_loops:
                await self._close_job(state, "close_failed")
                return

            strategy = (data.get("next_mutation_strategy") or "").strip()
            if not strategy:
                strategy = self._pick_next_mutation_strategy(state)

            state.feedback_loop_count += 1
            state.mutation_cycle_count += 1
            state.retry_count += 1

            # Route back to Mutation stage (adaptive feedback loop)
            self._sm.transition(state, JobStatus.MUTATING, "coordinator",
                                reason=f"decision: retry_with_mutation [{strategy}]")
            await self._save_state(state)

            if data.get("autonomous_dispatched", False):
                logger.info(
                    "mutation_retry_autonomous_dispatch_accepted",
                    job_id=state.job_id,
                    strategy=strategy,
                    loop_count=state.feedback_loop_count,
                )
                return

            cmd = MutateCommand(
                job_id=job_id,
                sample_id=data["sample_id"],
                correlation_id=data["correlation_id"],
                source_artifact_id=state.source_artifact_id or "",
                project_name=state.project_name,
                language=state.language,
                mutation_strategy=strategy,
                requested_strategies=state.requested_strategies,
                num_functions=3,
                target_functions=state.target_functions,
                retry_count=state.mutation_cycle_count,
            )
            await self._ctx.broker.publish(Topic.CMD_MUTATE, cmd)
            logger.info("dispatched_mutation_retry", job_id=job_id,
                        strategy=strategy, cycle=state.mutation_cycle_count)

        elif action == "escalate_to_analyst":
            await self._escalate(state, "Decision agent recommended escalation")

        elif action in ("close_no_behavior", "close_failed"):
            await self._close_job(state, action)

    async def _on_report_generated(self, data: dict) -> None:
        state = await self._get_state(data["job_id"])
        if state is None:
            return
        state.report_id = data["report_id"]
        self._sm.transition(state, JobStatus.REPORT_READY, "coordinator",
                            event_id=data.get("message_id"))
        await self._close_job(state, "CLOSED")

    async def _on_error(self, data: dict) -> None:
        state = await self._get_state(data["job_id"])
        if state is None:
            return

        error_code = data.get("error_code", "UNKNOWN")
        agent = data.get("agent", "unknown")
        is_retryable = data.get("is_retryable", False)
        retry_count = data.get("retry_count", 0)

        state.add_error(agent, error_code, data.get("error_message", ""), is_retryable)

        if is_retryable:
            decision = get_retry_decision(
                error_code=error_code,
                current_retry_count=retry_count,
                job_total_retries=state.retry_count,
            )
            if decision.should_retry:
                state.retry_count += 1
                await self._save_state(state)
                logger.info("scheduling_retry", job_id=state.job_id,
                            delay_s=decision.delay_s, error_code=error_code)
                # Delay retry without blocking event loop
                asyncio.create_task(self._delayed_retry(state, data, decision.delay_s))
                return

        await self._save_state(state)
        await self._fail_job(state, f"Non-retryable error from {agent}: {error_code}")

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    async def _delayed_retry(self, state: JobState, orig_data: dict, delay_s: float) -> None:
        await asyncio.sleep(delay_s)
        # Re-emit the original event to restart from current state
        await self._ctx.broker.publish_raw(Topic.EVENTS_ALL, orig_data)

    async def _fail_job(self, state: JobState, reason: str) -> None:
        try:
            self._sm.transition(state, JobStatus.FAILED, "coordinator", reason=reason)
        except InvalidTransitionError:
            pass
        await self._save_state(state)
        event = JobFailedEvent(
            job_id=state.job_id,
            sample_id=state.sample_id,
            correlation_id=state.correlation_id,
            failure_stage=state.current_status.value,
            error_message=reason,
            total_retries=state.retry_count,
        )
        await self._ctx.broker.publish(Topic.EVENTS_ALL, event)
        logger.warning("job_failed", job_id=state.job_id, reason=reason)

    async def _escalate(self, state: JobState, reason: str) -> None:
        try:
            self._sm.transition(state, JobStatus.ESCALATED, "coordinator", reason=reason)
        except InvalidTransitionError:
            pass
        await self._save_state(state)
        event = EscalationEvent(
            job_id=state.job_id,
            sample_id=state.sample_id,
            correlation_id=state.correlation_id,
            reason=reason,
            triggered_by_agent="CoordinatorAgent",
        )
        await self._ctx.broker.publish(Topic.ESCALATION_ANALYST, event)
        logger.warning("job_escalated", job_id=state.job_id, reason=reason)

    async def _close_job(self, state: JobState, reason: str) -> None:
        try:
            self._sm.transition(state, JobStatus.CLOSED, "coordinator", reason=reason)
        except InvalidTransitionError:
            pass
        await self._save_state(state)
        event = JobClosedEvent(
            job_id=state.job_id,
            sample_id=state.sample_id,
            correlation_id=state.correlation_id,
            final_status=state.current_status.value,
            report_id=state.report_id,
        )
        await self._ctx.broker.publish(Topic.EVENTS_ALL, event)
        logger.info("job_closed", job_id=state.job_id)

    async def _load_or_create_state(self, data: dict) -> JobState:
        existing = await self._get_state(data["job_id"])
        if existing:
            return existing
        return JobState(
            job_id=data["job_id"],
            sample_id=data.get("sample_id", ""),
            correlation_id=data.get("correlation_id", ""),
            project_name=data.get("project_name", ""),
            language=data.get("language", ""),
            requested_strategies=data.get("requested_strategies", []),
        )

    def _pick_next_mutation_strategy(self, state: JobState) -> str:
        strategies = state.requested_strategies or ["variant_source_generator"]
        idx = state.mutation_cycle_count % len(strategies)
        return str(strategies[idx]).strip() or "variant_source_generator"

    async def _get_state(self, job_id: str) -> Optional[JobState]:
        if self._ctx.state_store:
            return await self._ctx.state_store.get(job_id)
        return None

    async def _save_state(self, state: JobState) -> None:
        if self._ctx.state_store:
            await self._ctx.state_store.save(state)
