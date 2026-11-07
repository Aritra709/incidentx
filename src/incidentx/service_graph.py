from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set

import networkx as nx

from .config import DEFAULT_CONFIG_DIR, load_config


class ServiceGraph:
    """Dependency graph from the service catalog.

    Edges point from a service to the services it depends on. ``dependents``
    therefore answers "who breaks if this service breaks?".
    """

    def __init__(self, catalog: Optional[Dict[str, dict]] = None):
        if catalog is None:
            raw = load_config("service_catalog.yaml", DEFAULT_CONFIG_DIR)
            catalog = raw.get("services", {})
        self.catalog = catalog or {}
        self.graph = nx.DiGraph()
        for service, spec in self.catalog.items():
            self.graph.add_node(service, **spec)
            for dependency in spec.get("depends_on", []) or []:
                self.graph.add_node(dependency)
                self.graph.add_edge(service, dependency)

    def ensure(self, service: str) -> None:
        if service and service not in self.graph:
            self.graph.add_node(service)

    def dependencies(self, service: str) -> Set[str]:
        if service not in self.graph:
            return set()
        return set(nx.descendants(self.graph, service))

    def dependents(self, service: str) -> Set[str]:
        if service not in self.graph:
            return set()
        return set(nx.ancestors(self.graph, service))

    def blast_radius(self, service: str, observed: Iterable[str] = ()) -> Set[str]:
        radius = self.dependents(service)
        for observed_service in observed:
            radius |= self.dependents(observed_service)
        return radius

    def change_relevance(self, change_service: str, affected_services: Iterable[str]) -> float:
        affected = [service for service in affected_services if service]
        if not affected:
            return 0.1
        if change_service in affected:
            return 1.0
        for service in affected:
            if change_service in self.dependencies(service):
                return 0.65
            if change_service in self.dependents(service):
                return 0.4
        return 0.1

    def tier(self, service: str) -> str:
        return str(self.catalog.get(service, {}).get("tier", "standard")).lower()

    def is_user_facing(self, service: str) -> bool:
        return bool(self.catalog.get(service, {}).get("user_facing", False))

    def display_name(self, service: str) -> str:
        return str(self.catalog.get(service, {}).get("name", service))

    def label(self, service: str) -> str:
        meta = self.catalog.get(service, {})
        name = meta.get("name") or service
        tier = meta.get("tier")
        return f"{name}\n({tier})" if tier else name

    def cascade_edges(
        self, root: str, affected: Iterable[str]
    ) -> List[tuple]:
        """Edges to draw for the cascade, oriented dependency -> dependent."""
        relevant: Set[str] = {root}
        relevant.update(affected)
        relevant.update(self.dependents(root))
        for service in list(relevant):
            relevant.update(self.dependencies(service))
        edges: List[tuple] = []
        for service in relevant:
            if service not in self.graph:
                continue
            for dependency in self.graph.successors(service):
                if dependency in relevant and service in relevant:
                    edges.append((dependency, service))
        return sorted(set(edges))

    def to_dot(
        self,
        root: str,
        affected: Iterable[str],
        severity: str,
        change_service: Optional[str] = None,
        revenue_services: Iterable[str] = (),
    ) -> str:
        affected_set = {service for service in affected if service}
        revenue_set = {service for service in revenue_services if service}
        colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#d97706",
            "LOW": "#2563eb",
        }
        root_color = colors.get(severity.upper(), "#dc2626")
        nodes = {root} | affected_set | self.dependents(root)
        if change_service:
            nodes.add(change_service)
        for service in list(nodes):
            nodes.update(self.dependencies(service))
        lines = [
            "digraph cascade {",
            '  rankdir="LR";',
            '  graph [bgcolor="transparent", pad="0.2"];',
            '  node [shape=box, style="rounded,filled", fontname="Segoe UI", fontsize=11, margin="0.18,0.10"];',
            '  edge [color="#94a3b8", arrowsize=0.7];',
        ]
        for service in sorted(nodes):
            if service not in self.graph and service != root:
                continue
            fill = "#e2e8f0"
            font = "#0f172a"
            if service == root:
                fill = root_color
                font = "#ffffff"
            elif service in affected_set:
                fill = "#fecaca"
            elif service in revenue_set:
                fill = "#fde68a"
            label = self.label(service)
            if change_service and service == change_service:
                label = f"{label}\nchanged"
            style = 'style="rounded,filled,filled"'
            if service == root:
                style = 'style="rounded,filled,bold"'
            lines.append(
                f'  "{service}" [label="{label}", fillcolor="{fill}", fontcolor="{font}", {style}];'
            )
        for dependency, service in self.cascade_edges(root, affected_set):
            label = "depends on"
            lines.append(
                f'  "{dependency}" -> "{service}" [label="{label}", color="#64748b"];'
            )
        lines.append("}")
        return "\n".join(lines)
