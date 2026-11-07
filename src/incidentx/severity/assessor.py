from __future__ import annotations

from datetime import date, datetime, time, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import DEFAULT_CONFIG_DIR, load_config
from ..models import IncidentCluster, SeverityAssessment, SEVERITY_ORDER
from ..service_graph import ServiceGraph


DAY_NAMES = {
    "mon": 0,
    "tue": 1,
    "wed": 2,
    "thu": 3,
    "fri": 4,
    "sat": 5,
    "sun": 6,
}

TIER_SCORES = {
    "revenue-critical": 100.0,
    "revenue": 100.0,
    "critical": 85.0,
    "important": 60.0,
    "standard": 30.0,
    "internal": 10.0,
}


class SeverityAssessor:
    """Business-aware severity: the same failure is worse during a sale."""

    def __init__(
        self,
        config_dir: Optional[Path] = None,
        service_graph: Optional[ServiceGraph] = None,
        business_context: Optional[Dict[str, Any]] = None,
    ):
        self.config_dir = Path(config_dir) if config_dir else DEFAULT_CONFIG_DIR
        self.context = business_context or load_config(
            "business_context.yaml", self.config_dir
        )
        self.graph = service_graph or ServiceGraph()
        self.weights = self.context.get("weights", {})
        self.thresholds = self.context.get("severity_thresholds", {})
        self.revenue_services = {
            service.lower() for service in self.context.get("revenue_services", [])
        }
        self.critical_services = {
            service.lower() for service in self.context.get("critical_services", [])
        }
        self.user_facing_services = {
            service.lower() for service in self.context.get("user_facing_services", [])
        }
        self.data_loss_services = {
            service.lower() for service in self.context.get("data_loss_risk_services", [])
        }

    def assess(
        self,
        cluster: IncidentCluster,
        ignore_windows: bool = False,
    ) -> SeverityAssessment:
        active_window = None if ignore_windows else self._active_window(cluster)
        factors = self._factors(cluster, active_window)
        score = sum(
            factors[name] * float(self.weights.get(name, 0.0))
            for name in factors
        )

        floor, floor_reason = self._floor_reason(cluster, active_window)
        boosted = False
        if floor is not None and score < floor:
            score = float(floor)
            boosted = True

        score = round(min(score, 100.0), 1)
        level = self._level_for(score)

        baseline_factors = self._factors(cluster, None)
        baseline_score = sum(
            baseline_factors[name] * float(self.weights.get(name, 0.0))
            for name in baseline_factors
        )
        baseline_floor, _ = self._floor_reason(cluster, None)
        if baseline_floor is not None:
            baseline_score = max(baseline_score, float(baseline_floor))
        baseline_score = round(min(baseline_score, 100.0), 1)
        baseline_level = self._level_for(baseline_score)

        justification = self._justification(
            cluster, factors, score, level, active_window, floor_reason, boosted
        )
        business_summary = self._business_summary(
            cluster,
            level,
            active_window,
            baseline_level,
            baseline_score,
            floor_reason,
        )

        return SeverityAssessment(
            level=level,
            score=score,
            factors={name: round(value, 1) for name, value in factors.items()},
            justification=justification,
            business_summary=business_summary,
            revenue_window=active_window["name"] if active_window else None,
            baseline_level=baseline_level,
            baseline_score=baseline_score,
            boosted=boosted,
        )

    def _factors(
        self,
        cluster: IncidentCluster,
        active_window: Optional[Dict[str, Any]],
    ) -> Dict[str, float]:
        affected = [service.lower() for service in cluster.affected_services]
        revenue_affected = [service for service in affected if service in self.revenue_services]
        critical_affected = [service for service in affected if service in self.critical_services]

        scope = self._scope_score(len(affected))
        error_rate = self._error_rate_score(cluster.error_rate_per_minute)
        criticality = self._criticality_score(affected, revenue_affected, critical_affected)

        if active_window and revenue_affected:
            revenue_window = 100.0
        elif active_window and critical_affected:
            revenue_window = 70.0
        elif revenue_affected:
            revenue_window = 55.0
        elif critical_affected:
            revenue_window = 40.0
        else:
            revenue_window = 5.0

        blast = self._blast_radius_score(cluster)
        data_loss = self._data_loss_score(cluster, affected)
        return {
            "scope": scope,
            "error_rate": error_rate,
            "business_criticality": criticality,
            "revenue_window": revenue_window,
            "blast_radius": blast,
            "data_loss": data_loss,
        }

    @staticmethod
    def _scope_score(count: int) -> float:
        if count >= 7:
            return 100.0
        if count >= 4:
            return 80.0
        if count >= 2:
            return 55.0
        if count == 1:
            return 15.0
        return 0.0

    @staticmethod
    def _error_rate_score(rate: float) -> float:
        if rate >= 50:
            return 95.0
        if rate >= 20:
            return 75.0
        if rate >= 5:
            return 45.0
        if rate > 0:
            return 15.0
        return 0.0

    def _criticality_score(
        self,
        affected: List[str],
        revenue_affected: List[str],
        critical_affected: List[str],
    ) -> float:
        score = 0.0
        for service in affected:
            service_score = TIER_SCORES.get(self.graph.tier(service), 30.0)
            if service in revenue_affected:
                service_score = max(service_score, 100.0)
            elif service in critical_affected:
                service_score = max(service_score, 85.0)
            if service in self.user_facing_services:
                service_score = max(service_score, 60.0)
            score = max(score, service_score)
        return score

    def _blast_radius_score(self, cluster: IncidentCluster) -> float:
        root_service = (
            cluster.root_cause.primary_service
            if cluster.root_cause
            else (cluster.affected_services[0] if cluster.affected_services else "")
        )
        downstream = self.graph.blast_radius(root_service, cluster.affected_services)
        extra = downstream - set(cluster.affected_services)
        count = len(extra)
        if count >= 5:
            return 90.0
        if count >= 2:
            return 60.0
        if count == 1:
            return 30.0
        return 10.0

    def _data_loss_score(self, cluster: IncidentCluster, affected: List[str]) -> float:
        data_services_hit = [service for service in affected if service in self.data_loss_services]
        categories = set(cluster.categories)
        if data_services_hit and categories & {
            "DATABASE_CONNECTION",
            "QUERY_FAILED",
            "DISK_FULL",
            "MEMORY_EXHAUSTION",
        }:
            return 80.0
        if categories & {"DISK_FULL", "MEMORY_EXHAUSTION", "SERVICE_CRASH"}:
            return 35.0
        if data_services_hit:
            return 45.0
        return 0.0

    def _active_window(
        self, cluster: IncidentCluster
    ) -> Optional[Dict[str, Any]]:
        windows = self.context.get("revenue_windows", []) or []
        matches: List[Dict[str, Any]] = []
        for window in windows:
            if self._overlaps(cluster.start, cluster.end, window):
                matches.append(window)
        if not matches:
            return None
        matches.sort(
            key=lambda window: float(window.get("severity_floor", 0)), reverse=True
        )
        return matches[0]

    @staticmethod
    def _overlaps(
        start: datetime, end: datetime, window: Dict[str, Any]
    ) -> bool:
        days = [DAY_NAMES[day.lower()[:3]] for day in window.get("days", []) if day]
        if not days:
            days = list(range(7))
        try:
            start_time = time.fromisoformat(str(window.get("start", "00:00")))
            end_time = time.fromisoformat(str(window.get("end", "23:59")))
        except ValueError:
            return False

        current: date = start.date()
        last: date = end.date()
        while current <= last:
            if current.weekday() in days:
                window_start = datetime.combine(current, start_time)
                window_end = datetime.combine(current, end_time)
                if end_time <= start_time:
                    window_end += timedelta(days=1)
                if start <= window_end and end >= window_start:
                    return True
            current += timedelta(days=1)
        return False

    def _floor_reason(
        self,
        cluster: IncidentCluster,
        active_window: Optional[Dict[str, Any]],
    ) -> Tuple[Optional[float], str]:
        affected = {service.lower() for service in cluster.affected_services}
        revenue_affected = affected & self.revenue_services
        data_services_hit = affected & self.data_loss_services
        categories = set(cluster.categories)

        if active_window and revenue_affected:
            floor = float(active_window.get("severity_floor", 82))
            return floor, (
                f"revenue service {', '.join(sorted(revenue_affected))} failed during "
                f"'{active_window.get('name')}'"
            )
        if revenue_affected:
            rules = self.context.get("rules", {})
            level = str(rules.get("revenue_service_outside_window", "MEDIUM")).upper()
            return self._level_floor(level), "a revenue service was affected"
        if data_services_hit and categories & {
            "DATABASE_CONNECTION",
            "QUERY_FAILED",
            "DISK_FULL",
            "MEMORY_EXHAUSTION",
        }:
            rules = self.context.get("rules", {})
            level = str(rules.get("data_loss_risk", "HIGH")).upper()
            return self._level_floor(level), (
                f"data-loss-risk service {', '.join(sorted(data_services_hit))} was affected"
            )
        return None, ""

    def _level_floor(self, level: str) -> float:
        floors = {"LOW": 0.0, "MEDIUM": 35.0, "HIGH": 65.0, "CRITICAL": 82.0}
        return floors.get(level.upper(), 0.0)

    def _level_for(self, score: float) -> str:
        level = "LOW"
        for candidate in ("MEDIUM", "HIGH", "CRITICAL"):
            threshold = float(self.thresholds.get(candidate, {"MEDIUM": 30, "HIGH": 60, "CRITICAL": 80}[candidate]))
            if score >= threshold:
                level = candidate
        return level

    def _justification(
        self,
        cluster: IncidentCluster,
        factors: Dict[str, float],
        score: float,
        level: str,
        active_window: Optional[Dict[str, Any]],
        floor_reason: str,
        boosted: bool,
    ) -> str:
        revenue_affected = [
            service
            for service in cluster.affected_services
            if service.lower() in self.revenue_services
        ]
        parts = [
            f"{len(cluster.affected_services)} service(s) affected "
            f"({', '.join(cluster.affected_services)}).",
            f"Error rate {cluster.error_rate_per_minute:.1f}/min over "
            f"{cluster.duration_minutes:.1f} min.",
        ]
        if revenue_affected:
            parts.append(
                f"Revenue service(s) affected: {', '.join(revenue_affected)}."
            )
        if active_window:
            parts.append(
                f"Incident overlaps business window '{active_window.get('name')}' "
                f"({active_window.get('start')}-{active_window.get('end')})."
            )
        parts.append(
            "Factor scores: "
            + ", ".join(f"{name.replace('_', ' ')} {value:.0f}" for name, value in factors.items())
            + "."
        )
        parts.append(f"Final score {score:.1f} -> {level}.")
        if boosted and floor_reason:
            parts.append(f"Raised to the {level} floor because {floor_reason}.")
        return " ".join(parts)

    def _business_summary(
        self,
        cluster: IncidentCluster,
        level: str,
        active_window: Optional[Dict[str, Any]],
        baseline_level: str,
        baseline_score: float,
        floor_reason: str,
    ) -> str:
        if active_window:
            return (
                f"{level} because {floor_reason}. The same failure outside this window "
                f"would score {baseline_score:.0f} ({baseline_level})."
            )
        if baseline_level != level:
            return (
                f"{level} based on the current business profile. "
                f"Baseline score {baseline_score:.0f}."
            )
        return (
            f"{level} at {cluster.start:%Y-%m-%d %H:%M} local time. "
            f"Scope: {len(cluster.affected_services)} service(s)."
        )
