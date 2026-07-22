"""Prometheus metrics for the SecurePrompt ML sidecar.

All metric names are namespaced ``secureprompt_ml_*`` and registered on the
default `prometheus_client` registry so a single ASGI app
(``metrics_asgi_app``, mounted at ``/metrics`` in ``app/main.py``) can expose
them for scraping.

Label cardinality is intentionally bounded:
- ``endpoint`` is always a route TEMPLATE (e.g.
  ``/v1/scan-file/tasks/{task_id}``) or a fixed known path — never a path
  containing a live ID/UUID.
- ``entity_type`` comes from the NER model's fixed label set (PERSON, EMAIL,
  SSN, ...).
- ``status`` is one of ``ok`` / ``error``.

No request text, PII, workspace ID, or user ID is ever used as a label
value.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable, Optional

from prometheus_client import REGISTRY, Counter, Gauge, Histogram, make_asgi_app

_log = logging.getLogger("secureprompt.ml.metrics")


def _metric(cls, name: str, documentation: str, labelnames=(), **kwargs):
    """Idempotent metric constructor.

    ``app.main`` (and therefore this module) can be re-imported more than
    once within the same process — e.g. tests/test_internal_model_key.py
    deliberately purges ``sys.modules['app.*']`` and re-imports
    ``app.main`` fresh per test for hermetic env-var coverage. The
    ``prometheus_client`` default registry is a process-wide singleton that
    is NOT purged alongside it, so a naive second construction of the same
    metric name raises "Duplicated timeseries in CollectorRegistry" and
    breaks every subsequent test file's ``import app.main``. Reuse the
    already-registered collector instead of re-registering.
    """
    try:
        return cls(name, documentation, labelnames, **kwargs)
    except ValueError:
        existing = REGISTRY._names_to_collectors.get(name)
        if existing is not None:
            return existing
        raise


requests_total = _metric(
    Counter,
    "secureprompt_ml_requests_total",
    "Total HTTP requests handled by the ML sidecar.",
    ["endpoint", "status"],
)

request_duration_seconds = _metric(
    Histogram,
    "secureprompt_ml_request_duration_seconds",
    "HTTP request latency in seconds, by endpoint.",
    ["endpoint"],
)

ner_entities_detected_total = _metric(
    Counter,
    "secureprompt_ml_ner_entities_detected_total",
    "Total NER entities detected, by entity type.",
    ["entity_type"],
)

# Confidence scores are always in [0, 1]; prometheus_client appends a final
# +Inf bucket automatically.
ner_confidence = _metric(
    Histogram,
    "secureprompt_ml_ner_confidence",
    "Confidence score distribution of detected NER entities, by entity type.",
    ["entity_type"],
    buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
)

# Static info metric (Prometheus "info" pattern): value is always 1, the
# label set itself carries the (model, backend) currently active.
model_info = _metric(
    Gauge,
    "secureprompt_ml_model_info",
    "Static info metric identifying the active NER model(s) and backend; value is always 1.",
    ["model", "backend"],
)

ready = _metric(
    Gauge,
    "secureprompt_ml_ready",
    "Whether the ML sidecar has finished loading its models (1) or not (0).",
)

# Mounted at /metrics in app/main.py.
metrics_asgi_app = make_asgi_app()


def observe_request(endpoint: str, status: str, seconds: float) -> None:
    """Record one HTTP request.

    ``endpoint`` MUST be a route template or other fixed, known path (never
    a path containing a live ID) and ``status`` should be ``"ok"`` or
    ``"error"`` to keep label cardinality bounded.
    """
    requests_total.labels(endpoint=endpoint, status=status).inc()
    request_duration_seconds.labels(endpoint=endpoint).observe(seconds)


def _entity_type(detection: Any) -> Optional[str]:
    if isinstance(detection, dict):
        return detection.get("entity_type")
    return getattr(detection, "entity_type", None)


def _score(detection: Any) -> Optional[float]:
    if isinstance(detection, dict):
        return detection.get("score")
    return getattr(detection, "score", None)


def record_ner(detections: Iterable[Any]) -> None:
    """Record one entity-count increment + one confidence observation per
    detected entity.

    Accepts either ``NerEntity`` model instances (attribute access) or plain
    dicts (``{"entity_type": ..., "score": ...}``, the raw detection wire
    format used elsewhere in the sidecar) — both shapes appear across the
    detection pipeline. Entries missing an entity_type/score are skipped
    rather than raising, so a metrics hiccup never breaks detection.
    """
    for det in detections:
        entity_type = _entity_type(det)
        score = _score(det)
        if not entity_type or score is None:
            continue
        ner_entities_detected_total.labels(entity_type=entity_type).inc()
        ner_confidence.labels(entity_type=entity_type).observe(float(score))


def set_model_info(model: str, backend: str) -> None:
    """Publish the active NER model/backend as a static info gauge."""
    model_info.labels(model=model, backend=backend).set(1)


def set_ready(is_ready: bool) -> None:
    """Mirror the sidecar's readiness state (see ``/ready`` and the
    ``_ready`` asyncio.Event in app/main.py) as a gauge."""
    ready.set(1 if is_ready else 0)
