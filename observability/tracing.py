"""
OpenTelemetry tracing configuration.

Provides a tracer factory and span helpers.
In MVP mode, traces are exported to the console.
For production, configure an OTLP exporter to Jaeger/Tempo.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

_tracer_provider = None


def configure_tracing(
    service_name: str = "llmalmorph",
    otlp_endpoint: Optional[str] = None,
    console_export: bool = False,
) -> None:
    """
    Initialize OpenTelemetry tracing.

    Args:
        service_name:    Resource service.name attribute.
        otlp_endpoint:   e.g. "http://localhost:4317" for Jaeger gRPC.
                         If None, no remote export is configured.
        console_export:  If True, print traces to stdout (dev/debug only).
    """
    global _tracer_provider

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    except ImportError:
        logger.warning("opentelemetry-sdk not installed; tracing disabled.")
        return

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    if console_export:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    if otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            logger.info("OTel tracing → %s", otlp_endpoint)
        except ImportError:
            logger.warning(
                "opentelemetry-exporter-otlp not installed; "
                "install it with: pip install opentelemetry-exporter-otlp-proto-grpc"
            )

    trace.set_tracer_provider(provider)
    _tracer_provider = provider
    logger.info("OpenTelemetry tracing configured for service '%s'", service_name)


def get_tracer(name: str = "llmalmorph.agents"):
    """Return an OpenTelemetry Tracer, or a no-op tracer if OTel is unavailable."""
    try:
        from opentelemetry import trace
        return trace.get_tracer(name)
    except ImportError:
        return _NoOpTracer()


class _NoOpTracer:
    """Minimal no-op tracer used when opentelemetry is not installed."""

    def start_as_current_span(self, name: str, **kwargs):
        from contextlib import nullcontext
        return nullcontext()
