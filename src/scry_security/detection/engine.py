"""Bounded event-time correlation. Native event IDs never appear in engine logic."""

import heapq
from collections import Counter, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from itertools import count
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from scry_security.core.event_schema import SecurityEvent
from scry_security.detection.policy import DetectionPolicy, PolicyEvaluator
from scry_security.detection.rules import Rule, Severity


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: UUID
    rule_id: str
    name: str
    description: str
    severity: Severity
    timestamp: datetime
    operating_system: str
    hostname: str
    username: str | None
    source_ip: str | None
    event_ids: list[UUID]
    evidence_count: int
    mitre_techniques: list[str]
    false_positives: str
    investigation: str
    defensive_actions: str
    synthetic: bool
    context: dict[str, JsonValue] = Field(default_factory=dict)
    assessment: str = "Suspicious activity requiring investigation; compromise is not confirmed."


def field_value(event: SecurityEvent, field: str):
    if field.startswith("details."):
        value = event.details.get(field.split(".", 1)[1])
    elif field.startswith("context."):
        value = event.context.get(field.split(".", 1)[1])
    else:
        value = getattr(event, field)
    if value is not None and field in {"source_ip", "destination_ip"}:
        return str(value)
    return value


def matches(event: SecurityEvent, rule: Rule) -> bool:
    return (
        event.operating_system in rule.operating_systems
        and all(field_value(event, key) in values for key, values in rule.conditions.items())
        and not any(field_value(event, key) in values for key, values in rule.exclude.items())
    )


@dataclass
class _Context:
    events: deque[SecurityEvent] = field(default_factory=deque)
    distinct_counts: Counter = field(default_factory=Counter)

    def remove_first(self, distinct_field: str | None) -> None:
        event = self.events.popleft()
        if distinct_field:
            value = field_value(event, distinct_field)
            if value is not None and isinstance(value, (str, int)):
                self.distinct_counts[value] -= 1
                if not self.distinct_counts[value]:
                    del self.distinct_counts[value]


class DetectionEngine:
    """Bounded, indexed correlation over time-ordered canonical events.

    Each rule/group has its own context. Counts do not scan unrelated hosts or
    repeatedly recount every previous event. Replay sorts input before feeding.
    """

    def __init__(
        self, rules: list[Rule], *, max_events: int = 10_000, policy: DetectionPolicy | None = None
    ):
        if not rules or len({rule.rule_id for rule in rules}) != len(rules):
            raise ValueError("Rules must be nonempty with unique IDs")
        if not 1 <= max_events <= 100_000:
            raise ValueError("max_events must be between 1 and 100000")
        self.rules = tuple(rules)
        self._policy = PolicyEvaluator(policy or DetectionPolicy())
        self.max_events = max_events
        self._window = timedelta(seconds=max(rule.window_seconds for rule in rules))
        self._events: deque[SecurityEvent] = deque()
        self._ids: set[UUID] = set()
        self._last_time: datetime | None = None
        self._contexts: dict[tuple, _Context] = {}
        self._memberships: dict[UUID, list[tuple[tuple, Rule]]] = {}
        self._context_entries = 0
        self._emitted: dict[tuple, datetime] = {}
        self._emission_expiry: list[tuple] = []
        self._serial = count()

    def process(self, event: SecurityEvent) -> list[Finding]:
        if event.event_id in self._ids:
            return []
        event = self._policy.enrich(event)
        if self._last_time is not None and event.timestamp < self._last_time:
            raise ValueError("Out-of-order event; replay in event-time order")
        cutoff = event.timestamp - self._window
        while self._events and self._events[0].timestamp < cutoff:
            expired = self._events.popleft()
            self._ids.remove(expired.event_id)
            memberships = self._memberships.pop(expired.event_id, [])
            self._context_entries -= len(memberships)
            for key, rule in memberships:
                context = self._contexts.get(key)
                if context and not context.events:
                    del self._contexts[key]
                    continue
                if context and context.events and context.events[0].event_id == expired.event_id:
                    context.remove_first(rule.distinct_field if rule.mode == "distinct" else None)
                    if not context.events:
                        del self._contexts[key]
        while self._emission_expiry and self._emission_expiry[0][0] <= event.timestamp:
            expiry, _, key = heapq.heappop(self._emission_expiry)
            if self._emitted.get(key) == expiry:
                del self._emitted[key]
        if len(self._events) >= self.max_events:
            raise BufferError("Detection context capacity exceeded; no event was ingested")
        plans = []
        for rule in self.rules:
            preceding = rule.mode == "sequence" and event.event_type == rule.preceding_event_type
            if not preceding and event.event_type not in rule.event_types:
                continue
            if not matches(event, rule):
                continue
            group = tuple(field_value(event, name) for name in rule.group_by)
            if any(value is None or isinstance(value, (dict, list)) for value in group):
                continue
            key = (rule.rule_id, event.synthetic, *group)
            store_context = rule.mode != "sequence" or preceding
            plans.append((rule, key, preceding, store_context))
        additions = sum(store_context for _, _, _, store_context in plans)
        if self._context_entries + additions > 500_000:
            raise BufferError("Rule context reference capacity exceeded")
        self._events.append(event)
        self._ids.add(event.event_id)
        self._last_time = event.timestamp
        self._memberships[event.event_id] = []
        findings = []
        for rule, key, preceding, store_context in plans:
            context = self._contexts.get(key)
            if context is None:
                if not store_context:
                    continue
                context = self._contexts[key] = _Context()
            start = event.timestamp - timedelta(seconds=rule.window_seconds)
            while context.events and context.events[0].timestamp < start:
                context.remove_first(rule.distinct_field if rule.mode == "distinct" else None)
            if store_context:
                context.events.append(event)
                self._memberships[event.event_id].append((key, rule))
                self._context_entries += 1
                if rule.mode == "distinct":
                    value = field_value(event, rule.distinct_field)
                    if value is not None and isinstance(value, (str, int)):
                        context.distinct_counts[value] += 1
            if preceding or key in self._emitted:
                continue
            matched_count = (
                len(context.distinct_counts) if rule.mode == "distinct" else len(context.events)
            )
            if matched_count < rule.threshold:
                continue
            expiry = event.timestamp + timedelta(seconds=rule.window_seconds)
            self._emitted[key] = expiry
            heapq.heappush(self._emission_expiry, (expiry, next(self._serial), key))
            evidence_ids = [item.event_id for item in context.events]
            if rule.mode == "sequence":
                evidence_ids.append(event.event_id)
            findings.append(
                Finding(
                    finding_id=uuid5(
                        NAMESPACE_URL, f"scry:{rule.rule_id}:{','.join(map(str, evidence_ids))}"
                    ),
                    rule_id=rule.rule_id,
                    name=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    timestamp=event.timestamp,
                    operating_system=event.operating_system.value,
                    hostname=event.hostname,
                    username=event.username,
                    source_ip=str(event.source_ip) if event.source_ip else None,
                    event_ids=evidence_ids,
                    evidence_count=len(evidence_ids),
                    mitre_techniques=rule.mitre_techniques,
                    false_positives=rule.false_positives,
                    investigation=rule.investigation,
                    defensive_actions=rule.defensive_actions,
                    synthetic=event.synthetic,
                    context=event.context,
                )
            )
        return findings

    def analyse(self, events: Iterable[SecurityEvent]) -> list[Finding]:
        batch = []
        for event in events:
            if len(batch) >= self.max_events:
                raise BufferError("Replay batch capacity exceeded")
            batch.append(event)
        findings = []
        for event in sorted(batch, key=lambda item: item.timestamp):
            findings.extend(self.process(event))
        return findings
