"""Offline replay of real Google Antigravity (agy) session history through Semgate.

Evaluates historical agy tool calls and approval interruption points through
Semgate's judge in shadow mode (no execution, pure evaluation + ledger recording).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .adapters.antigravity import envelope_from_pre_tool_use, grant_from_config
from .extractor import AgySessionExtractor, ExtractedAction, default_agy_dir
from .gate import policy_dir
from .judge import Decision, judge
from .ledger import Ledger
from .policy import Policy
from .providers.base import JudgeProvider
from .providers.fake import FakeProvider
from .providers.typesafe import TypeSafeProvider


# --grant and --ledger not given: these paths inside --workspace (default: the current directory).
DEFAULT_GRANT = os.path.join(".antigravity", "semgate", "grant.json")
DEFAULT_LEDGER = os.path.join(".antigravity", "semgate", "replay_ledger.jsonl")
# --policy not given: the packaged dev policy.
DEFAULT_POLICY = str(policy_dir() / "router_policy_dev.json")


@dataclass
class ReplayItemResult:
    action: ExtractedAction
    decision: Decision

    def to_dict(self) -> Dict[str, Any]:
        return {
            "conversation_id": self.action.conversation_id,
            "session_title": self.action.session_title,
            "proposed_step_idx": self.action.proposed_step_idx,
            "execution_step_idx": self.action.execution_step_idx,
            "tool": self.action.tool,
            "arguments": self.action.arguments,
            "user_prompt": self.action.user_prompt,
            "was_agy_approval_point": self.action.was_agy_approval_point,
            "agy_approval_response": self.action.agy_approval_response,
            "semgate_decision": self.decision.decision,
            "semgate_stage": self.decision.stage,
            "semgate_reasons": self.decision.reasons,
            "semgate_gate_hits": self.decision.gate_hits,
            "latency_ms": self.decision.latency_ms,
        }


@dataclass
class ReplaySummary:
    total_actions: int = 0
    total_approval_points: int = 0
    auto_allow_count: int = 0
    ask_count: int = 0
    block_count: int = 0
    approval_auto_allow_count: int = 0
    approval_ask_count: int = 0
    approval_block_count: int = 0
    items: List[ReplayItemResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_actions": self.total_actions,
            "total_approval_points": self.total_approval_points,
            "all_actions_breakdown": {
                "auto_allow": self.auto_allow_count,
                "ask": self.ask_count,
                "block": self.block_count,
            },
            "approval_points_breakdown": {
                "total": self.total_approval_points,
                "auto_allow": self.approval_auto_allow_count,
                "ask": self.approval_ask_count,
                "block": self.approval_block_count,
            },
            "items": [item.to_dict() for item in self.items],
        }


def get_default_provider(provider_name: str = "typesafe") -> JudgeProvider:
    # No silent fallback: a TypeSafe provider that cannot start raises, so a
    # replay report never shows scripted FakeProvider verdicts as Jev's.
    if provider_name == "typesafe":
        return TypeSafeProvider()
    elif provider_name == "openrouter":
        from .providers.openrouter import OpenRouterDecisionsProvider
        return OpenRouterDecisionsProvider()
    elif provider_name == "fake":
        return FakeProvider()
    return None


def replay_actions(
    actions: List[ExtractedAction],
    policy: Policy,
    grant_data: Dict[str, Any],
    provider: Optional[JudgeProvider] = None,
    ledger: Optional[Ledger] = None,
    workspace_path: Optional[str] = None,
) -> ReplaySummary:
    """workspace_path not given: the current directory."""
    if workspace_path is None:
        workspace_path = os.getcwd()
    grant = grant_from_config(grant_data)
    summary = ReplaySummary()

    for action in actions:
        event = action.to_hook_event(workspace_path=workspace_path)
        envelope = envelope_from_pre_tool_use(event, grant)
        decision = judge(envelope, policy, provider=provider, ledger=ledger)

        item = ReplayItemResult(action=action, decision=decision)
        summary.items.append(item)
        summary.total_actions += 1

        if decision.decision == "allow":
            summary.auto_allow_count += 1
        elif decision.decision == "ask":
            summary.ask_count += 1
        elif decision.decision == "deny":
            summary.block_count += 1

        if action.was_agy_approval_point:
            summary.total_approval_points += 1
            if decision.decision == "allow":
                summary.approval_auto_allow_count += 1
            elif decision.decision == "ask":
                summary.approval_ask_count += 1
            elif decision.decision == "deny":
                summary.approval_block_count += 1

    return summary


def format_report(summary: ReplaySummary, title: str = "Semgate Offline Replay Report") -> str:
    lines = []
    lines.append(f"# {title}\n")
    lines.append(f"- **Total acciones evaluadas**: {summary.total_actions}")
    lines.append(f"- **Puntos de aprobación humana en agy**: {summary.total_approval_points}")
    lines.append("")
    lines.append("## Impacto de Semgate sobre las interrupciones de aprobación de agy")
    lines.append(f"- **Auto-Allow (permiso automático seguro)**: {summary.approval_auto_allow_count} / {summary.total_approval_points} "
                 f"({(summary.approval_auto_allow_count / summary.total_approval_points * 100):.1f}%)" if summary.total_approval_points else "- Auto-Allow: 0")
    lines.append(f"- **Ask (consulta necesaria al operador)**: {summary.approval_ask_count} / {summary.total_approval_points} "
                 f"({(summary.approval_ask_count / summary.total_approval_points * 100):.1f}%)" if summary.total_approval_points else "- Ask: 0")
    lines.append(f"- **Block (bloqueo por denegación/política)**: {summary.approval_block_count} / {summary.total_approval_points} "
                 f"({(summary.approval_block_count / summary.total_approval_points * 100):.1f}%)" if summary.total_approval_points else "- Block: 0")
    lines.append("")

    # Collect examples
    auto_allows = [it for it in summary.items if it.action.was_agy_approval_point and it.decision.decision == "allow"]
    asks = [it for it in summary.items if it.action.was_agy_approval_point and it.decision.decision == "ask"]
    blocks = [it for it in summary.items if it.action.was_agy_approval_point and it.decision.decision == "deny"]

    # Also check any block in all actions if none in approval points
    if not blocks:
        blocks = [it for it in summary.items if it.decision.decision == "deny"]

    lines.append("## Ejemplos por categoría\n")

    lines.append("### 1. Categoría AUTO-ALLOW (Semgate elimina la fricción innecesaria)")
    if auto_allows:
        for it in auto_allows[:3]:
            arg_str = str(it.action.arguments.get("CommandLine") or it.action.arguments.get("Url") or it.action.arguments)
            lines.append(f"- **Sesión**: `{it.action.conversation_id[:8]}...` (Paso propuesto: {it.action.proposed_step_idx}, Paso ejecución: {it.action.execution_step_idx})")
            lines.append(f"  - **Tool**: `{it.action.tool}`")
            lines.append(f"  - **Comando/Target**: `{arg_str[:160]}`")
            lines.append(f"  - **Comportamiento en agy**: Interrumpió al usuario pidiendo aprobación (`{it.action.agy_approval_response}`).")
            lines.append(f"  - **Veredicto Semgate**: `ALLOW` (Etapa: `{it.decision.stage}`)")
            lines.append(f"  - **Razón Semgate**: {'; '.join(it.decision.reasons)}")
            lines.append("")
    else:
        lines.append("Ninguna acción clasificada como auto-allow.\n")

    lines.append("### 2. Categoría ASK (Semgate mantiene la confirmación obligatoria)")
    if asks:
        for it in asks[:3]:
            arg_str = str(it.action.arguments.get("CommandLine") or it.action.arguments.get("Url") or it.action.arguments)
            lines.append(f"- **Sesión**: `{it.action.conversation_id[:8]}...` (Paso propuesto: {it.action.proposed_step_idx}, Paso ejecución: {it.action.execution_step_idx})")
            lines.append(f"  - **Tool**: `{it.action.tool}`")
            lines.append(f"  - **Comando/Target**: `{arg_str[:160]}`")
            lines.append(f"  - **Comportamiento en agy**: Interrumpió al usuario (`{it.action.agy_approval_response}`).")
            lines.append(f"  - **Veredicto Semgate**: `ASK` (Etapa: `{it.decision.stage}`)")
            lines.append(f"  - **Razón Semgate**: {'; '.join(it.decision.reasons)}")
            lines.append("")
    else:
        lines.append("Ninguna acción clasificada como ask.\n")

    lines.append("### 3. Categoría BLOCK (Semgate bloquea acciones fuera de alcance o prohibidas)")
    if blocks:
        for it in blocks[:3]:
            arg_str = str(it.action.arguments.get("CommandLine") or it.action.arguments.get("Url") or it.action.arguments)
            lines.append(f"- **Sesión**: `{it.action.conversation_id[:8]}...` (Paso propuesto: {it.action.proposed_step_idx})")
            lines.append(f"  - **Tool**: `{it.action.tool}`")
            lines.append(f"  - **Comando/Target**: `{arg_str[:160]}`")
            lines.append(f"  - **Veredicto Semgate**: `DENY` (Etapa: `{it.decision.stage}`)")
            lines.append(f"  - **Razón Semgate**: {'; '.join(it.decision.reasons)}")
            lines.append("")
    else:
        lines.append("No se detectaron acciones denegadas en este conjunto.\n")

    return "\n".join(lines)


def get_active_session_ids(agy_dir: Optional[Path] = None) -> set[str]:
    """Find currently active session IDs by inspecting presence lock files."""
    if agy_dir is None:
        agy_dir = Path(default_agy_dir())
    presence = agy_dir / "presence"
    if presence.exists():
        # Session with newest mtime or recent locks
        locks = sorted(presence.glob("*.lock"), key=lambda p: p.stat().st_mtime, reverse=True)
        if locks:
            # The newest lock is typically the current running agent session
            return {locks[0].stem}
    return set()


def get_most_recent_session(extractor: AgySessionExtractor, exclude: Optional[set[str]] = None) -> Optional[str]:
    """Find the most recently modified session with a transcript, excluding current/active."""
    exclude = exclude or set()
    sessions = [s for s in extractor.list_sessions() if s.get("has_transcript") and s.get("conversation_id") not in exclude]
    if not sessions:
        return None
    sessions.sort(key=lambda s: s.get("last_modified") or "", reverse=True)
    return sessions[0]["conversation_id"]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Semgate Offline Session Replay")
    parser.add_argument("--session", default=None, help="Specific conversation ID (defaults to most recent available session)")
    parser.add_argument("--all", action="store_true", help="Replay all discoverable historical sessions")
    parser.add_argument("--workspace", default=None,
                        help="Project folder the replayed calls ran in (default: the current directory)")
    parser.add_argument("--agy-dir", default=None, help="agy data folder (default: ~/.gemini/antigravity-cli)")
    parser.add_argument("--grant", default=None,
                        help="Path to operator grant JSON (default: <workspace>/.antigravity/semgate/grant.json)")
    parser.add_argument("--policy", default=DEFAULT_POLICY, help="Path to policy JSON (default: the packaged dev policy)")
    parser.add_argument("--ledger", default=None,
                        help="Path to write replay ledger (default: <workspace>/.antigravity/semgate/replay_ledger.jsonl)")
    parser.add_argument("--provider", default="typesafe", help="Provider to use: typesafe, openrouter, fake, or none")
    parser.add_argument("--output-json", default=None, help="Save summary report JSON")
    args = parser.parse_args(argv)

    workspace = os.path.abspath(args.workspace or os.getcwd())
    grant_path = args.grant or os.path.join(workspace, DEFAULT_GRANT)
    ledger_path = args.ledger or os.path.join(workspace, DEFAULT_LEDGER)

    extractor = AgySessionExtractor(agy_dir=args.agy_dir)
    extractor.load_index()

    with open(grant_path, "r", encoding="utf-8") as f:
        grant_data = json.load(f)

    policy = Policy.load(args.policy)
    provider = get_default_provider(args.provider)
    ledger = Ledger(ledger_path)

    active_sessions = get_active_session_ids(extractor.agy_dir)
    # Also exclude known current process conversation if in env
    current_env_cid = os.environ.get("CONVERSATION_ID")
    if current_env_cid:
        active_sessions.add(current_env_cid)

    if args.all:
        print("Extracting actions across ALL historical sessions...")
        all_actions = [a for a in extractor.extract_all() if a.conversation_id not in active_sessions]
        print(f"Total historical actions to evaluate: {len(all_actions)}")
        summary = replay_actions(all_actions, policy, grant_data, provider=provider, ledger=ledger,
                                 workspace_path=workspace)
        report = format_report(summary, title="Semgate Offline Replay - Todas las Sesiones Históricas")
    else:
        target_session = args.session or get_most_recent_session(extractor, exclude=active_sessions)
        if not target_session:
            print(f"error: no agy session with a transcript in {extractor.agy_dir}; pass --session or --agy-dir",
                  file=sys.stderr)
            return 2
        print(f"Target session: {target_session}" + ("" if args.session else " (most recent available)"))
        actions = extractor.extract_session(target_session)
        print(f"Total actions extracted: {len(actions)}")
        summary = replay_actions(actions, policy, grant_data, provider=provider, ledger=ledger,
                                 workspace_path=workspace)
        report = format_report(summary, title=f"Semgate Offline Replay - Sesión {target_session}")

    print("\n" + report)

    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(summary.to_dict(), f, indent=2)
        print(f"\nSaved JSON report to {args.output_json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

