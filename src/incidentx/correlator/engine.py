from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..changes.tracker import ChangeMatch, find_related_change
from ..config import DEFAULT_CONFIG_DIR, load_config
from ..models import (
    ChangeEvent,
    ErrorEvent,
    IncidentCluster,
    PatternType,
    RootCauseAnalysis,
)
from ..service_graph import ServiceGraph


class CorrelationEngine:
    """Temporal clustering + causal rules + change linking."""

    def __init__(
        self,
        config_dir: Optional[Path] = None,
        service_graph: Optional[ServiceGraph] = None,
    ):
        self.config_dir = Path(config_dir) if config_dir else DEFAULT_CONFIG_DIR
        self.graph = service_graph or ServiceGraph()
        raw = load_config("causal_rules.yaml", self.config_dir)
        self.chains: List[dict] = raw.get("causal_chains", []) or []

    def correlate_errors(
        self,
        errors: List[ErrorEvent],
        window_minutes: int = 5,
    ) -> List[IncidentCluster]:
        if not errors:
            return []
        ordered = sorted(
            [error for error in errors if error.timestamp is not None],
            key=lambda error: error.timestamp,
        )
        if not ordered:
            return []

        groups: List[List[ErrorEvent]] = [[ordered[0]]]
        window = timedelta(minutes=window_minutes)
        for event in ordered[1:]:
            previous = groups[-1][-1]
            gap = event.timestamp - previous.timestamp
            if gap <= window and self._trace_compatible(groups[-1], event):
                groups[-1].append(event)
            else:
                groups.append([event])

        clusters = [self._build_cluster(group) for group in groups]
        return self._merge_adjacent(clusters, window_minutes)

    def _trace_compatible(self, group: List[ErrorEvent], event: ErrorEvent) -> bool:
        trace = event.log_entry.metadata.get("trace_id") or event.log_entry.metadata.get(
            "traceId"
        )
        if not trace:
            return True
        group_traces = {
            item.log_entry.metadata.get("trace_id")
            or item.log_entry.metadata.get("traceId")
            for item in group
        }
        group_traces.discard(None)
        return not group_traces or trace in group_traces

    def _merge_adjacent(
        self, clusters: List[IncidentCluster], window_minutes: int
    ) -> List[IncidentCluster]:
        if len(clusters) < 2:
            return clusters
        merged: List[IncidentCluster] = [clusters[0]]
        for cluster in clusters[1:]:
            previous = merged[-1]
            gap = cluster.start - previous.end
            overlap = set(previous.affected_services) & set(cluster.affected_services)
            if gap <= timedelta(minutes=window_minutes) and overlap:
                previous.errors.extend(cluster.errors)
                previous.affected_services = sorted(
                    set(previous.affected_services) | set(cluster.affected_services)
                )
                previous.end = max(previous.end, cluster.end)
                previous.pattern_type = PatternType.SERVICE.value
            else:
                merged.append(cluster)
        for cluster in merged:
            cluster.id = self._incident_id(cluster)
        return merged

    def _build_cluster(self, errors: List[ErrorEvent]) -> IncidentCluster:
        start = min(error.timestamp for error in errors)
        end = max(error.timestamp for error in errors)
        services = sorted({error.service for error in errors})
        cluster = IncidentCluster(
            id="",
            errors=errors,
            start=start,
            end=end,
            affected_services=services,
            pattern_type=PatternType.TEMPORAL.value,
        )
        cluster.id = self._incident_id(cluster)
        return cluster

    @staticmethod
    def _incident_id(cluster: IncidentCluster) -> str:
        key = (
            f"{cluster.start.isoformat()}|{','.join(cluster.affected_services)}|"
            f"{','.join(sorted({error.category for error in cluster.errors}))}"
        )
        digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:4].upper()
        return f"INC-{cluster.start:%Y%m%d-%H%M}-{digest}"

    def identify_root_cause(
        self,
        cluster: IncidentCluster,
        change_matches: Optional[List[ChangeMatch]] = None,
    ) -> RootCauseAnalysis:
        categories = {error.category for error in cluster.errors}
        chain = self._best_chain(cluster, categories)
        top_change: Optional[ChangeMatch] = (
            change_matches[0] if change_matches else None
        )

        first_by_category: Dict[str, datetime] = {}
        weighted: Dict[str, float] = {}
        service_weighted: Dict[str, float] = {}
        for error in cluster.errors:
            timestamp = error.timestamp or cluster.start
            if error.category not in first_by_category:
                first_by_category[error.category] = timestamp
            weighted[error.category] = weighted.get(error.category, 0.0) + max(
                error.confidence, 0.3
            )
            service_weighted[error.service] = service_weighted.get(error.service, 0.0) + 1.0

        if chain is not None:
            primary = chain["primary"]
            cluster.pattern_type = PatternType.CAUSAL.value
        else:
            primary = max(weighted, key=lambda category: weighted[category])

        primary_service = max(service_weighted, key=lambda service: service_weighted[service])
        if top_change is not None and top_change.confidence >= 0.6:
            primary_service = top_change.change.service

        secondary_present = [
            category
            for category in chain.get("secondary", []) if category in categories and category != primary
        ] if chain else []
        contributing = [
            category
            for category in sorted(
                categories, key=lambda category: first_by_category.get(category, cluster.start)
            )
            if category != primary
        ]
        contributing_services = [
            service for service in cluster.affected_services if service != primary_service
        ]

        confidence_parts: List[float] = []
        reasons: List[str] = []

        if chain is not None:
            confidence_parts.append(float(chain.get("confidence", 0.8)))
            if secondary_present:
                reasons.append(
                    f"causal chain '{chain.get('name', primary)}' explains "
                    f"{', '.join(secondary_present)}"
                )
            else:
                reasons.append(f"known failure pattern '{chain.get('name', primary)}'")
        else:
            confidence_parts.append(0.5)
            reasons.append(f"'{primary}' is the most frequent error category")

        if top_change is not None:
            confidence_parts.append(top_change.confidence)
            reasons.append(
                f"the first error began after {top_change.change.type} change "
                f"'{top_change.change.description}' ({top_change.change.id})"
            )
            if top_change.change.rollback:
                reasons.append(f"the change has a rollback path: {top_change.change.rollback}")

        first_primary_time = first_by_category.get(primary)
        if chain is not None and first_primary_time is not None:
            secondary_times = [
                first_by_category[category]
                for category in secondary_present
                if category in first_by_category
            ]
            if secondary_times and first_primary_time <= min(secondary_times):
                reasons.append("the primary error occurred before the downstream errors")

        confidence = sum(confidence_parts) / max(len(confidence_parts), 1)
        confidence = round(min(max(confidence, 0.0), 0.97), 3)
        cluster.suspected_change = top_change.change if top_change else None

        return RootCauseAnalysis(
            primary_category=primary,
            primary_service=primary_service,
            confidence=confidence,
            reasoning=" ".join(reason.capitalize() for reason in reasons) + ".",
            suspected_change_id=top_change.change.id if top_change else None,
            change_confidence=top_change.confidence if top_change else 0.0,
            change_reason=top_change.reason if top_change else "",
            contributing_categories=contributing,
            contributing_services=contributing_services,
        )

    def _best_chain(self, cluster: IncidentCluster, categories: set) -> Optional[dict]:
        candidates: List[Tuple[float, dict]] = []
        first_seen: Dict[str, datetime] = {}
        for error in cluster.errors:
            first_seen.setdefault(error.category, error.timestamp or cluster.start)

        for chain in self.chains:
            primary = chain.get("primary")
            if primary not in categories:
                continue
            secondary = [
                category for category in chain.get("secondary", []) if category in categories
            ]
            score = float(chain.get("confidence", 0.8))
            score += 0.04 * min(len(secondary), 3)
            primary_time = first_seen.get(primary)
            if primary_time is not None and secondary:
                secondary_times = [
                    first_seen[category]
                    for category in secondary
                    if category in first_seen
                ]
                if secondary_times and primary_time <= min(secondary_times):
                    score += 0.08
                elif secondary_times:
                    score -= 0.08
                window = timedelta(minutes=int(chain.get("time_window_minutes", 10)))
                if max(secondary_times) - primary_time <= window:
                    score += 0.04
            candidates.append((score, chain))
        if not candidates:
            return None
        candidates.sort(key=lambda item: (-item[0], item[1].get("name", "")))
        return candidates[0][1]

    def link_changes(
        self,
        cluster: IncidentCluster,
        changes: Iterable[ChangeEvent],
        lookback_minutes: int = 45,
    ) -> List[ChangeMatch]:
        return find_related_change(
            cluster,
            changes,
            service_graph=self.graph,
            lookback_minutes=lookback_minutes,
        )
