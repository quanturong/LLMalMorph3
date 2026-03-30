"""
All stream/queue name constants in one place.

Command streams  → point-to-point (direct request to specific agent)
Event streams    → broadcast (agent → all interested agents)
Retry streams    → messages being retried (with delay)
DLQ              → dead letter, exhausted retry budget
Escalation       → human analyst queue
Heartbeat        → agent liveness / health checks
Negotiation      → peer-to-peer agent negotiation (request/reply)
"""


class Topic:
    # ── Commands (direct agent-to-agent or job submission) ─────────────────
    CMD_SAMPLE_PREP      = "stream:cmd:sample_prep"
    CMD_MUTATE           = "stream:cmd:mutate"
    CMD_GENERATE_VARIANT = "stream:cmd:generate_variant"
    CMD_BUILD_VALIDATE   = "stream:cmd:build_validate"
    CMD_SANDBOX_SUBMIT   = "stream:cmd:sandbox_submit"
    CMD_EXEC_MONITOR     = "stream:cmd:exec_monitor"
    CMD_ANALYZE_BEHAVIOR = "stream:cmd:analyze_behavior"
    CMD_DECIDE           = "stream:cmd:decide"
    CMD_REPORT           = "stream:cmd:report"

    # ── Events (broadcast to all agents) ───────────────────────────────────
    EVENTS_ALL           = "stream:events:all"

    # ── Heartbeat (agent liveness) ─────────────────────────────────────────
    HEARTBEAT            = "stream:heartbeat"

    # ── Negotiation (peer-to-peer) ─────────────────────────────────────────
    NEGOTIATE            = "stream:negotiate"

    # ── Retry queues (with delay processing) ───────────────────────────────
    RETRY_SANDBOX        = "stream:retry:sandbox"
    RETRY_ANALYSIS       = "stream:retry:analysis"
    RETRY_BUILD          = "stream:retry:build"

    # ── Dead Letter Queue ───────────────────────────────────────────────────
    DLQ                  = "stream:dlq:all"

    # ── Escalation (human-in-the-loop) ──────────────────────────────────────
    ESCALATION_ANALYST   = "stream:escalation:analyst"

    # ── Consumer group names ────────────────────────────────────────────────
    # Monitor (formerly coordinator)
    CG_MONITOR           = "cg_monitor"

    # Per-agent consumer groups on EVENTS_ALL (for self-activation)
    CG_EVENTS_SAMPLE_PREP    = "cg_events_sample_prep"
    CG_EVENTS_MUTATE         = "cg_events_mutate"
    CG_EVENTS_GENERATE_VARIANT = "cg_events_generate_variant"
    CG_EVENTS_BUILD_VALIDATE = "cg_events_build_validate"
    CG_EVENTS_SANDBOX_SUBMIT = "cg_events_sandbox_submit"
    CG_EVENTS_EXEC_MONITOR   = "cg_events_exec_monitor"
    CG_EVENTS_ANALYZE_BEHAVIOR = "cg_events_analyze_behavior"
    CG_EVENTS_DECIDE         = "cg_events_decide"
    CG_EVENTS_REPORT         = "cg_events_report"

    # Legacy command-stream consumer groups (still used for direct commands)
    CG_COORDINATOR       = "cg_coordinator"
    CG_SAMPLE_PREP       = "cg_sample_prep"
    CG_MUTATE            = "cg_mutate"
    CG_GENERATE_VARIANT  = "cg_generate_variant"
    CG_BUILD_VALIDATE    = "cg_build_validate"
    CG_SANDBOX_SUBMIT    = "cg_sandbox_submit"
    CG_EXEC_MONITOR      = "cg_exec_monitor"
    CG_ANALYZE_BEHAVIOR  = "cg_analyze_behavior"
    CG_DECIDE            = "cg_decide"
    CG_REPORT            = "cg_report"
    CG_DLQ_PROCESSOR     = "cg_dlq_processor"

    # Heartbeat / negotiation consumer groups
    CG_HEARTBEAT_MONITOR = "cg_heartbeat_monitor"
    CG_NEGOTIATE_ALL     = "cg_negotiate_all"
