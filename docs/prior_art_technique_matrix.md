# PIRGE-CodeGuard Prior-Art Technique Matrix

This file maps common prior-art techniques in LLM agent and coding-agent security
against the PIRGE-CodeGuard mechanism. It is not a legal freedom-to-operate
opinion. It is a technical novelty planning document.

## Techniques Already Used In Prior Work

1. Prompt filtering and pattern detection

   Existing systems scan prompts, retrieved documents, tool outputs, or generated
   commands for known attack phrases such as "ignore previous instructions",
   secret exfiltration requests, destructive shell commands, and suspicious URLs.
   This is useful but brittle because attackers can paraphrase, split, or hide
   instructions.

2. System-prompt guardrails

   Many systems tell the model not to obey untrusted text. This helps in simple
   cases but is not an enforcement boundary because the same model still sees
   instructions and data in one context.

3. Human approval gates

   Sensitive operations such as file deletion, network access, email sending,
   package installation, and shell execution can require user confirmation. This
   is practical but can produce approval fatigue and does not explain why an
   action is unsafe.

4. Sandboxing

   The agent can run in a restricted container or VM. This limits blast radius,
   but a sandbox alone may still permit harmful in-sandbox behavior, dependency
   poisoning, data exfiltration, or unauthorized repository changes.

5. Least-privilege access control

   Systems such as programmable privilege control and mandatory access control
   restrict tool calls based on policies. This is strong prior art, so
   PIRGE-CodeGuard must not claim generic least privilege for all LLM agents.

6. Policy DSLs

   Some defenses express allowed and denied tool calls through a domain-specific
   language. This is deterministic and auditable, but policy authoring and policy
   selection remain hard when each coding task has different files, commands,
   and repository context.

7. Attribute-based and mandatory access control

   Some systems assign attributes to agents, tools, users, and data, then enforce
   policies over agent-tool interactions. These systems are general and powerful,
   but they may not construct a codebase-specific reasoning graph for proposed
   edits and shell commands.

8. Information-flow graphs

   Some defenses monitor whether data or authority flows from untrusted sources
   to privileged actions. This overlaps with PIRGE-CodeGuard. The distinction we
   want is coding-agent specificity: repo artifact provenance, proposed edit
   warrants, command intent diffing, and safe substitute generation.

9. Causal attribution of tool calls

   Some systems test whether a tool call survives when untrusted observations
   are attenuated or removed. This is strong prior art. PIRGE-CodeGuard can use a
   lighter deterministic approximation: an action must carry a warrant showing a
   trusted user-intent path and must not be justified by untrusted repo text.

10. Dual-model or quarantined-reader architectures

   A privileged model plans actions while a quarantined model reads untrusted
   content without tool access. This is strong but expensive and may reduce
   task utility. PIRGE-CodeGuard can be implemented without requiring two LLMs.

11. Tool-output isolation and structured queries

   Defenses can separate instructions from data using schema boundaries and
   structured messages. This helps, but coding agents still need to reason over
   free-form repository artifacts, README files, comments, package scripts, and
   generated plans.

12. Security benchmarks

   Agent security benchmarks test prompt injection, data leakage, and tool-use
   integrity. They are useful for evaluation, but they are not themselves a
   defense mechanism.

## PIRGE-CodeGuard Differentiation Target

PIRGE-CodeGuard should be framed narrowly as a pre-execution guard for coding
agents, not a generic LLM security framework.

The candidate novelty is the combination of:

1. Codebase instruction provenance graph.
2. Action warrant for every proposed file edit, shell command, or tool call.
3. Graph-scoped capability capsule derived from the user's coding task.
4. Command intent diff between the proposed action and authorized graph intent.
5. Detection of untrusted repository text being used as authority.
6. Safe substitute planner that repairs the action instead of merely blocking.
7. Audit certificate tying each allow/block decision to graph nodes, risks,
   capabilities, and substitute actions.

## Claim Boundary

Avoid broad claims such as:

- "securing LLM agents";
- "least privilege for LLM agents";
- "detecting prompt injection";
- "sandboxing AI coding tools";
- "blocking malicious commands."

Prefer narrower claims such as:

- "constructing a codebase-specific authority-and-capability graph before a
  coding agent executes proposed actions";
- "requiring each proposed coding-agent action to have a trusted-user authority
  path and a graph-scoped capability warrant";
- "blocking actions whose warrant is supported by untrusted repository text";
- "generating safe substitute actions for blocked coding-agent commands or file
  edits while preserving the original coding objective."
