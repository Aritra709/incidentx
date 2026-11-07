from __future__ import annotations

import hashlib
from typing import List, Optional

from ..models import (
    ChangeEvent,
    IncidentCluster,
    IncidentReport,
    RemediationAction,
    RemediationPlan,
    RootCauseAnalysis,
    SeverityAssessment,
)
from .loader import KnowledgeBase

PHASE_ORDER = ("immediate", "investigation", "resolution")


class RemediationEngine:
    """Builds approval-gated plans. Commands are never executed."""

    def __init__(self, knowledge_base: Optional[KnowledgeBase] = None):
        self.kb = knowledge_base or KnowledgeBase()

    @staticmethod
    def _action_id(prefix: str, text: str) -> str:
        digest = hashlib.sha1(text.encode("utf-8")).hexdigest()[:6]
        return f"{prefix}-{digest}"

    def _normalize_action(
        self,
        raw: object,
        phase: str,
        index: int,
    ) -> RemediationAction:
        if isinstance(raw, str):
            text = raw
            command = None
            automated = False
            requires_approval = False
        else:
            data = dict(raw)  # type: ignore[arg-type]
            text = str(data.get("action", ""))
            command = data.get("command")
            automated = bool(data.get("automated", False))
            requires_approval = bool(data.get("requires_approval", False))
        action_id = self._action_id(phase, f"{index}-{text}")
        return RemediationAction(
            id=action_id,
            action=text,
            phase=phase,
            automated=automated,
            requires_approval=requires_approval,
            command=str(command) if command else None,
        )

    def build_plan(
        self,
        cluster: IncidentCluster,
        severity: SeverityAssessment,
        root_cause: RootCauseAnalysis,
    ) -> RemediationPlan:
        categories: List[str] = [root_cause.primary_category]
        for category in root_cause.contributing_categories + cluster.categories:
            if category not in categories:
                categories.append(category)

        actions: List[RemediationAction] = []
        prevention: List[str] = []
        runbook = ""
        escalation = ""

        suspected: Optional[ChangeEvent] = cluster.suspected_change
        if suspected and suspected.rollback:
            rollback_text = (
                f"Roll back {suspected.type} change {suspected.id} on "
                f"{suspected.service}: {suspected.rollback}"
            )
            actions.append(
                RemediationAction(
                    id=self._action_id("rollback", suspected.id),
                    action=rollback_text,
                    phase="immediate",
                    automated=False,
                    requires_approval=True,
                    command=suspected.rollback,
                    note="Dry-run first. Requires human approval before execution.",
                )
            )

        for category in categories:
            rule = self.kb.get_remediation(category)
            if not runbook:
                runbook = str(rule.get("runbook", ""))
            if not escalation:
                escalation = str(rule.get("escalation", ""))
            for phase in PHASE_ORDER:
                for index, raw in enumerate(rule.get(phase, []) or []):
                    action = self._normalize_action(raw, phase, index)
                    if not action.action:
                        continue
                    if not any(
                        existing.action == action.action
                        and existing.phase == action.phase
                        for existing in actions
                    ):
                        actions.append(action)
            for item in rule.get("prevention", []) or []:
                if item not in prevention:
                    prevention.append(str(item))

        if escalated_severity(severity) and escalation:
            note = f"Escalate to: {escalation}."
            if not any(action.action == note for action in actions):
                actions.append(
                    RemediationAction(
                        id=self._action_id("escalate", escalation),
                        action=note,
                        phase="immediate",
                        automated=True,
                        requires_approval=False,
                    )
                )

        return RemediationPlan(
            actions=actions,
            prevention=prevention,
            runbook=runbook,
            escalation=escalation,
            proposed_rollback=suspected.rollback if suspected else None,
        )

    def dry_run(
        self, plan: RemediationPlan, action_id: str
    ) -> Optional[RemediationAction]:
        for action in plan.actions:
            if action.id != action_id:
                continue
            if action.command:
                output = (
                    f"DRY RUN: would execute `{action.command}`.\n"
                    "No command was run. No production state was changed."
                )
            else:
                output = (
                    f"DRY RUN: would perform '{action.action}'.\n"
                    "No production state was changed."
                )
            action.status = "dry_run"
            action.dry_run_output = output
            return action
        return None

    def approve(
        self,
        plan: RemediationPlan,
        action_id: str,
        approved_by: str = "human",
    ) -> Optional[RemediationAction]:
        for action in plan.actions:
            if action.id != action_id:
                continue
            if not action.requires_approval:
                action.status = "ready"
                return action
            action.status = "approved_simulated"
            action.approved_by = approved_by
            action.note = (
                (action.note + " " if action.note else "")
                + f"Approved by {approved_by}. Simulated execution only; no shell command was run."
            )
            return action
        return None


def escalated_severity(severity: SeverityAssessment) -> bool:
    return severity.level in {"HIGH", "CRITICAL"}


def report_resolution_steps(report: IncidentReport) -> List[str]:
    steps = [
        action.action
        for action in report.remediation.by_phase("resolution")
        if action.status in {"approved_simulated", "ready", "proposed"}
    ]
    if not steps:
        steps = [action.action for action in report.remediation.by_phase("resolution")]
    return steps
