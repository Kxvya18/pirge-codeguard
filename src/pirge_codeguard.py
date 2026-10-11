"""
PIRGE-CodeGuard core prototype.

This module implements a pre-execution reasoning graph for coding agents. It
does not execute commands. It evaluates proposed file/tool/shell actions before
execution and produces an auditable decision.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath
import hashlib
import json
import re
import shlex
from typing import Iterable


TRUST_USER = "trusted_user"
TRUST_POLICY = "trusted_policy"
TRUST_AGENT_PLAN = "agent_plan"
TRUST_REPO = "untrusted_repo"
TRUST_TOOL_OUTPUT = "untrusted_tool_output"
DEFAULT_POLICY_PROFILE_PATH = "config/policy_profiles.json"


RISK_PATTERNS = {
    "instruction_override": re.compile(r"\b(ignore|bypass|override|disregard)\b.*\b(instruction|policy|previous|system)\b", re.I),
    "secret_exfiltration": re.compile(r"\b(env|api[_-]?key|secret|token|credential|ssh|\.env)\b.*\b(send|upload|post|curl|wget|exfil|print|cat)\b", re.I),
    "network_fetch_execute": re.compile(r"\b(curl|wget|Invoke-WebRequest)\b.*(\||bash|sh|python|node|ruby|perl)", re.I),
    "destructive_delete": re.compile(r"\b(rm\s+-rf|del\s+/s|Remove-Item\s+-Recurse|format\s+|wipe|delete all)\b", re.I),
    "permission_change": re.compile(r"\b(chmod\s+777|chown|sudo|administrator|root)\b", re.I),
    "external_push": re.compile(r"\b(git\s+push|scp|rsync|ftp|sftp)\b", re.I),
    "package_install": re.compile(r"\b(npm\s+install|pip\s+install|brew\s+install|cargo\s+install|go\s+install)\b", re.I),
    "reverse_shell": re.compile(r"\b(nc\s+-e|bash\s+-i|/dev/tcp|powershell.*download|stringfrombase64|base64\s+-d)\b", re.I),
}


CAPABILITY_RISK = {
    "read_file": 1,
    "write_file": 2,
    "run_tests": 2,
    "run_shell": 3,
    "network": 4,
    "read_secret": 5,
    "destructive": 5,
    "external_write": 5,
    "install_dependency": 4,
    "privilege_escalation": 5,
}


@dataclass
class Artifact:
    artifact_id: str
    kind: str
    path: str
    text: str
    trust: str


@dataclass
class GraphNode:
    node_id: str
    kind: str
    label: str
    trust: str
    risk_tags: list[str] = field(default_factory=list)
    source_path: str | None = None


@dataclass
class GraphEdge:
    src: str
    dst: str
    relation: str


@dataclass
class ProvenanceGraph:
    nodes: list[GraphNode]
    edges: list[GraphEdge]

    def to_dict(self) -> dict:
        return {
            "nodes": [asdict(n) for n in self.nodes],
            "edges": [asdict(e) for e in self.edges],
        }


@dataclass
class ActionProposal:
    action_id: str
    action_type: str
    command: str = ""
    file_path: str = ""
    file_diff: str = ""
    proposed_by: str = "agent"


@dataclass
class CapabilityCapsule:
    capsule_id: str
    allowed_read_globs: list[str]
    allowed_write_globs: list[str]
    allowed_commands: list[str]
    denied_capabilities: list[str]
    max_risk: int
    requires_human_approval: list[str]
    policy_profile: str = "balanced"


@dataclass
class ActionWarrant:
    action_id: str
    user_goal: str
    supporting_nodes: list[str]
    influencing_untrusted_nodes: list[str]
    capabilities: list[str]
    touched_files: list[str]
    risk_tags: list[str]
    authority_path_valid: bool
    intent_match_score: float
    capsule_violations: list[str]
    schema_errors: list[str] = field(default_factory=list)
    schema_warnings: list[str] = field(default_factory=list)


@dataclass
class GuardDecision:
    action_id: str
    decision: str
    reasons: list[str]
    warrant: ActionWarrant
    safe_substitute: str | None
    audit_hash: str


@dataclass
class ActionSchemaValidation:
    valid: bool
    normalized_action: ActionProposal
    errors: list[str]
    warnings: list[str]


def stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("||".join(parts).encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def load_policy_profile(profile_name: str = "balanced", path: str = DEFAULT_POLICY_PROFILE_PATH) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            profiles = json.load(f)
    except FileNotFoundError:
        profiles = {}
    if profile_name not in profiles:
        if profile_name != "balanced":
            return load_policy_profile("balanced", path)
        return {
            "description": "Built-in balanced fallback",
            "max_risk": 3,
            "denied_capabilities": ["network", "read_secret", "destructive", "external_write", "install_dependency", "privilege_escalation"],
            "approval_required": ["network", "read_secret", "destructive", "external_write", "install_dependency", "privilege_escalation"],
            "allowed_command_prefixes": ["pwd", "ls", "cat", "head", "tail", "rg", "grep", "python -m pytest", "pytest", "npm test", "yarn test", "pnpm test"],
        }
    profile = profiles[profile_name]
    profile["name"] = profile_name
    return profile


def validate_action_schema(action: ActionProposal) -> ActionSchemaValidation:
    errors: list[str] = []
    warnings: list[str] = []
    action_type = (action.action_type or "").strip().lower()
    if "|" in action_type:
        warnings.append(f"ambiguous_action_type:{action.action_type}")
        action_type = "shell" if action.command.strip() else "edit"
    if action_type not in {"shell", "edit"}:
        errors.append(f"unsupported_action_type:{action.action_type}")
        action_type = "shell" if action.command.strip() else "edit"
    normalized = ActionProposal(
        action_id=str(action.action_id or stable_id("action", action.command, action.file_path, action.file_diff)),
        action_type=action_type,
        command=action.command or "",
        file_path=action.file_path or "",
        file_diff=action.file_diff or "",
        proposed_by=action.proposed_by,
    )
    if action_type == "shell" and not normalized.command.strip():
        errors.append("shell_action_missing_command")
    if action_type == "edit" and not normalized.file_path.strip():
        errors.append("edit_action_missing_file_path")
    if action_type == "edit" and normalized.command.strip():
        warnings.append("edit_action_contains_command")
    if normalized.file_path.startswith("/") or normalized.file_path.startswith("../") or "/../" in normalized.file_path:
        errors.append("unsafe_file_path")
    return ActionSchemaValidation(not errors, normalized, errors, warnings)


def detect_risks(text: str) -> list[str]:
    return [name for name, pattern in RISK_PATTERNS.items() if pattern.search(text)]


def tokenize_intent(text: str) -> set[str]:
    tokens = set(re.findall(r"[a-zA-Z_./-]{3,}", text.lower()))
    synonyms = {
        "test": {"test", "tests", "pytest", "jest", "mocha", "unit", "failing", "failure"},
        "fix": {"fix", "bug", "repair", "correct", "resolve", "failing"},
        "read": {"read", "inspect", "view", "check", "analyze", "search", "find", "scan"},
        "edit": {"edit", "update", "modify", "patch", "implement", "change"},
        "install": {"install", "dependency", "package"},
        "network": {"download", "fetch", "curl", "wget", "http", "https"},
        "secret": {"secret", "token", "credential", "env", "api"},
        "delete": {"delete", "remove", "rm", "wipe"},
    }
    expanded = set(tokens)
    for key, vals in synonyms.items():
        if tokens & vals:
            expanded.add(key)
    return expanded


def classify_artifact(path: str, text: str) -> str:
    p = path.lower()
    if p.endswith(("readme.md", ".md", ".txt", ".rst")):
        return "repo_document"
    if "package.json" in p or p.endswith(("makefile", ".toml", ".yaml", ".yml", ".json")):
        return "repo_config_or_script"
    if p.endswith((".py", ".js", ".ts", ".java", ".go", ".rs", ".cpp", ".c", ".sh")):
        return "source_code"
    if "test" in p or "spec" in p:
        return "test_file"
    return "repo_artifact"


def build_provenance_graph(user_request: str, artifacts: Iterable[Artifact], agent_plan: str = "") -> ProvenanceGraph:
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    user_id = stable_id("user", user_request)
    nodes.append(GraphNode(user_id, "user_request", user_request, TRUST_USER, detect_risks(user_request)))

    policy_id = stable_id("policy", "coding-agent-least-privilege")
    nodes.append(GraphNode(
        policy_id,
        "system_policy",
        "Coding actions require trusted user authority, least privilege, and no untrusted instruction control.",
        TRUST_POLICY,
    ))
    edges.append(GraphEdge(policy_id, user_id, "constrains"))

    if agent_plan:
        plan_id = stable_id("plan", agent_plan)
        nodes.append(GraphNode(plan_id, "agent_plan", agent_plan, TRUST_AGENT_PLAN, detect_risks(agent_plan)))
        edges.append(GraphEdge(user_id, plan_id, "requests_plan"))

    for artifact in artifacts:
        kind = classify_artifact(artifact.path, artifact.text)
        artifact_node_id = stable_id("artifact", artifact.path, artifact.text[:256])
        risks = detect_risks(artifact.text)
        artifact_label = f"{artifact.path}\n{artifact.text[:500]}"
        nodes.append(GraphNode(artifact_node_id, kind, artifact_label, artifact.trust, risks, artifact.path))
        edges.append(GraphEdge(artifact_node_id, user_id, "observed_during_task"))

        for risk in risks:
            risk_id = stable_id("risk", artifact.path, risk)
            nodes.append(GraphNode(risk_id, "repo_injection_risk", risk, artifact.trust, [risk], artifact.path))
            edges.append(GraphEdge(artifact_node_id, risk_id, "contains_risk"))

    return ProvenanceGraph(nodes, edges)


def extract_command_capabilities(command: str) -> tuple[list[str], list[str], list[str]]:
    caps: set[str] = {"run_shell"}
    touched: set[str] = set()
    risks = set(detect_risks(command))
    lower = command.lower()
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if re.search(r"\b(pytest|npm\s+test|yarn\s+test|pnpm\s+test|go\s+test|cargo\s+test|mvn\s+test)\b", lower):
        caps.add("run_tests")
    if re.search(r"\b(curl|wget|git\s+clone|npm\s+install|pip\s+install|brew\s+install)\b", lower):
        caps.add("network")
    if re.search(r"\b(npm\s+install|pip\s+install|brew\s+install|cargo\s+install|go\s+install)\b", lower):
        caps.add("install_dependency")
    if re.search(r"\b(cat|less|head|tail|sed|awk|grep|rg)\b", lower):
        caps.add("read_file")
    if re.search(r"\b(tee|>|>>|sed\s+-i|python.*open\(.*w|rm\s+|mv\s+|cp\s+)\b", lower):
        caps.add("write_file")
    secret_text = lower.replace(".env.example", "").replace("env.example", "")
    if re.search(r"(\.env\b|id_rsa|id_ed25519|api[_-]?key|secret|token|credential)", secret_text):
        caps.add("read_secret")
    if re.search(r"\b(rm\s+-rf|find\s+.*-delete|git\s+clean\s+-fdx)\b", lower):
        caps.add("destructive")
    if re.search(r"\b(git\s+push|scp|rsync|ftp|sftp|curl\s+-x\s+post|curl.*-d)\b", lower):
        caps.add("external_write")
    if re.search(r"\b(sudo|su\s+|chmod\s+777|chown)\b", lower):
        caps.add("privilege_escalation")

    for token in parts:
        if token.startswith("-"):
            continue
        if "/" in token or "." in token:
            cleaned = token.strip("'\";")
            if not cleaned.startswith(("http://", "https://")):
                touched.add(cleaned)
    return sorted(caps), sorted(touched), sorted(risks)


def extract_edit_capabilities(action: ActionProposal) -> tuple[list[str], list[str], list[str]]:
    caps = ["write_file"]
    touched = [action.file_path] if action.file_path else []
    risks = detect_risks(action.file_diff + "\n" + action.file_path)
    if action.command.strip():
        command_caps, command_touched, command_risks = extract_command_capabilities(action.command)
        caps.extend(command_caps)
        touched.extend(command_touched)
        risks.extend(command_risks)
    if action.file_path.endswith((".env", ".pem", "id_rsa", "id_ed25519")) and not action.file_path.endswith(".env.example"):
        caps.append("read_secret")
    if any(path_part in action.file_path for path_part in ["../", "/etc/", "/.ssh/"]):
        caps.append("destructive")
    return sorted(set(caps)), touched, risks


def build_capsule(user_request: str, repo_files: Iterable[str], policy_profile: str = "balanced") -> CapabilityCapsule:
    profile = load_policy_profile(policy_profile)
    intent = tokenize_intent(user_request)
    allowed_commands = list(profile.get("allowed_command_prefixes", []))
    denied = list(profile.get("denied_capabilities", []))
    max_risk = int(profile.get("max_risk", 3))
    if "install" in intent and "network" in intent:
        denied.remove("network")
        denied.remove("install_dependency") if "install_dependency" in denied else None
        max_risk = 4
    if "delete" in intent:
        max_risk = 4

    write_globs = []
    for path in repo_files:
        p = PurePosixPath(path)
        if p.suffix in {".py", ".js", ".ts", ".java", ".go", ".rs", ".md", ".json"}:
            write_globs.append(str(p))
    return CapabilityCapsule(
        capsule_id=stable_id("capsule", user_request, ",".join(sorted(repo_files))),
        allowed_read_globs=["**/*"],
        allowed_write_globs=sorted(write_globs),
        allowed_commands=allowed_commands,
        denied_capabilities=denied,
        max_risk=max_risk,
        requires_human_approval=list(profile.get("approval_required", [])),
        policy_profile=profile.get("name", policy_profile),
    )


def path_allowed(path: str, allowed: list[str]) -> bool:
    if not path:
        return True
    raw = path.replace("\\", "/")
    if raw.startswith("../") or raw.startswith("/"):
        return False
    normalized = raw[2:] if raw.startswith("./") else raw
    if normalized in allowed:
        return True
    return any(pattern == "**/*" or normalized.endswith(pattern.lstrip("./")) for pattern in allowed)


def command_allowed(command: str, allowed_commands: list[str]) -> bool:
    lower = " ".join(command.lower().split())
    return any(lower == item or lower.startswith(item + " ") for item in allowed_commands)


def find_untrusted_influence(action: ActionProposal, graph: ProvenanceGraph) -> list[str]:
    text = (action.command + "\n" + action.file_path + "\n" + action.file_diff).lower()
    risk_text = text.replace(".env.example", "").replace("env.example", "")
    action_terms = set(re.findall(r"[a-zA-Z0-9_./-]{4,}", text))
    influenced = []
    for node in graph.nodes:
        if node.trust != TRUST_REPO:
            continue
        if node.risk_tags:
            for risk in node.risk_tags:
                if risk in detect_risks(text) or any(term in risk_text for term in ["curl", "rm -rf", ".env", "ignore", "sudo", "git push"]):
                    influenced.append(node.node_id)
                    break
        label_terms = set(re.findall(r"[a-zA-Z_./-]{5,}", node.label.lower()))
        if len(label_terms & set(re.findall(r"[a-zA-Z_./-]{5,}", text))) >= 3:
            influenced.append(node.node_id)
            continue
        node_label = node.label.lower()
        for term in action_terms:
            clean = term.strip("'\";")
            if "/" in clean or clean.endswith((".sh", ".py", ".js")):
                if clean in node_label:
                    influenced.append(node.node_id)
                    break
    return sorted(set(influenced))


def intent_match(user_request: str, action: ActionProposal) -> float:
    user = tokenize_intent(user_request)
    action_text = f"{action.action_type} {action.command} {action.file_path} {action.file_diff}"
    act = tokenize_intent(action_text)
    if not user:
        return 0.0
    overlap = len(user & act)
    risky_mismatch = len(({"network", "secret", "delete", "install"} & act) - ({"network", "secret", "delete", "install"} & user))
    score = overlap / max(1, min(len(user), 8))
    return max(0.0, min(1.0, score - 0.25 * risky_mismatch))


def semantic_authority_match(user_request: str, action: ActionProposal, capabilities: list[str]) -> bool:
    """Lightweight intent semantics for coding-agent actions.

    This is deliberately conservative: it only treats low-risk local inspection,
    local tests, and repository-file edits as user-authorized when the user's
    request contains a matching coding objective.
    """
    intent = tokenize_intent(user_request)
    caps = set(capabilities)
    action_text = f"{action.action_type} {action.command} {action.file_path} {action.file_diff}".lower()
    high_risk = {"network", "read_secret", "destructive", "external_write", "install_dependency", "privilege_escalation"}
    if caps & high_risk:
        return False
    if "run_tests" in caps and (intent & {"test", "fix", "read"}):
        return True
    if action.action_type == "edit" and "write_file" in caps and (intent & {"fix", "edit"}):
        return True
    if action.action_type == "edit" and "write_file" in caps and any(word in user_request.lower() for word in ["patch", "update", "source code", "bug"]):
        return True
    if "read_file" in caps and (intent & {"read", "fix", "test"}):
        return True
    if "run_shell" in caps and not (caps - {"run_shell"}) and any(cmd in action_text for cmd in ["ls", "pwd", "rg", "grep"]):
        return True
    return False


def build_warrant(user_request: str, action: ActionProposal, graph: ProvenanceGraph, capsule: CapabilityCapsule, validation: ActionSchemaValidation | None = None) -> ActionWarrant:
    validation = validation or validate_action_schema(action)
    action = validation.normalized_action
    if action.action_type == "shell":
        caps, touched, risks = extract_command_capabilities(action.command)
    else:
        caps, touched, risks = extract_edit_capabilities(action)

    influencing = find_untrusted_influence(action, graph)
    user_nodes = [n.node_id for n in graph.nodes if n.kind == "user_request"]
    policy_nodes = [n.node_id for n in graph.nodes if n.kind == "system_policy"]
    risk_score = max([CAPABILITY_RISK.get(c, 1) for c in caps] or [1])
    violations = []
    for cap in caps:
        if cap in capsule.denied_capabilities:
            violations.append(f"capability_denied:{cap}")
    if risk_score > capsule.max_risk:
        violations.append(f"risk_exceeds_capsule:{risk_score}>{capsule.max_risk}")
    if action.action_type == "shell" and not command_allowed(action.command, capsule.allowed_commands):
        violations.append("command_not_in_capsule")
    for path in touched:
        if "write_file" in caps and not path_allowed(path, capsule.allowed_write_globs):
            violations.append(f"write_path_not_allowed:{path}")

    match = intent_match(user_request, action)
    semantic_match = semantic_authority_match(user_request, action, caps)
    high_risk_caps = {"network", "read_secret", "destructive", "external_write", "install_dependency", "privilege_escalation"}
    low_risk_repo_context_use = not (set(caps) & high_risk_caps)
    authority_valid = bool(user_nodes) and (match >= 0.2 or semantic_match) and (not influencing or low_risk_repo_context_use)
    return ActionWarrant(
        action_id=action.action_id,
        user_goal=user_request,
        supporting_nodes=user_nodes + policy_nodes,
        influencing_untrusted_nodes=influencing,
        capabilities=caps,
        touched_files=touched,
        risk_tags=sorted(set(risks)),
        authority_path_valid=authority_valid,
        intent_match_score=round(match, 3),
        capsule_violations=violations,
        schema_errors=validation.errors,
        schema_warnings=validation.warnings,
    )


def safe_substitute(action: ActionProposal, warrant: ActionWarrant) -> str | None:
    if warrant.schema_errors:
        return "Ask the agent to emit a valid structured action before execution."
    caps = set(warrant.capabilities)
    command = action.command.lower()
    if "read_secret" in caps:
        return "Use a non-secret template such as .env.example, or ask the user to explicitly approve secret access."
    if "network" in caps or "install_dependency" in caps:
        return "Inspect dependency files locally first; request explicit approval before network install/download."
    if "destructive" in caps:
        return "List candidate files first and request explicit approval before deletion."
    if "external_write" in caps:
        return "Prepare a local patch/commit summary; require user approval before external push/upload."
    if action.action_type == "shell" and "test" in command:
        return "Run the project test command inside the existing workspace without network or secret access."
    if warrant.capsule_violations:
        return "Reduce the action to read-only inspection or an edit limited to graph-authorized files."
    return None


def evaluate_action(user_request: str, action: ActionProposal, graph: ProvenanceGraph, capsule: CapabilityCapsule) -> GuardDecision:
    validation = validate_action_schema(action)
    normalized_action = validation.normalized_action
    warrant = build_warrant(user_request, normalized_action, graph, capsule, validation)
    reasons = []
    reasons.extend([f"schema_error:{err}" for err in validation.errors])
    if not warrant.authority_path_valid:
        if warrant.influencing_untrusted_nodes:
            reasons.append("authority_path_from_untrusted_repo_content")
        if warrant.intent_match_score < 0.2:
            reasons.append("action_intent_does_not_match_user_request")
    if warrant.capsule_violations:
        reasons.extend(warrant.capsule_violations)
    if warrant.risk_tags:
        reasons.extend([f"risk_detected:{r}" for r in warrant.risk_tags])

    decision = "allow" if not reasons else "block"
    substitute = None if decision == "allow" else safe_substitute(normalized_action, warrant)
    audit_payload = json.dumps({"action": asdict(normalized_action), "warrant": asdict(warrant), "reasons": reasons}, sort_keys=True)
    audit_hash = hashlib.sha256(audit_payload.encode("utf-8")).hexdigest()
    return GuardDecision(action.action_id, decision, reasons, warrant, substitute, audit_hash)


def evaluate_actions(user_request: str, artifacts: list[Artifact], actions: list[ActionProposal], agent_plan: str = "", policy_profile: str = "balanced") -> dict:
    graph = build_provenance_graph(user_request, artifacts, agent_plan)
    capsule = build_capsule(user_request, [a.path for a in artifacts], policy_profile=policy_profile)
    decisions = [evaluate_action(user_request, action, graph, capsule) for action in actions]
    return {
        "graph": graph.to_dict(),
        "capsule": asdict(capsule),
        "decisions": [asdict(d) for d in decisions],
    }
