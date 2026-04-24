# Sub-Agent Prompt Template

Every audit sub-agent (deep-dive category, ASVS checklist, scanner wrapper,
STRIDE generator, etc.) invoked from the orchestrator uses this shape. Fill
the **{{placeholders}}** in the calling code; do not change the structure.

---

```
ROLE: Senior application security engineer.
TASK: {{phase-or-category}} audit for partition {{partition_id}}.

INPUTS (read from disk — do not ask the orchestrator for these):
  - .claude-audit/current/phase-00-profile.json      # Project Map
  - .claude-audit/current/phase-02-surface.json      # Attack Surface (when available)
  - .claude-audit/current/partitions.json            # Partition manifest
  - .claude-audit/ignore.txt                         # Ignore patterns
  - .claude-audit/baseline.json                      # Only in delta mode
  {{extra-inputs}}

SCOPE:
  Analyze only files under: {{partition.paths_included}}
  Honor excludes from: {{partition.paths_excluded}} and .claude-audit/ignore.txt
  Do not read files outside this scope.

METHOD:
  1. Load the inputs via the Read tool.
  2. {{phase-specific-method-body}}
     (See steps/phase-<NN>-<name>.md for the detailed procedure.)
  3. Write findings as newline-delimited JSON (JSONL) to:
       .claude-audit/current/phase-{{NN}}-{{category}}-{{partition_id}}.jsonl
     Schema per finding: see lib/finding-schema.json.
  4. **Validate your JSONL output before exit:**
       python3 scripts/validate-findings.py \
         --schema skills/security-audit/lib/finding-schema.json \
         .claude-audit/current/phase-{{NN}}-{{category}}-{{partition_id}}.jsonl
     If exit code is non-zero, you MUST fix the invalid rows (missing
     required fields, bad CWE format, etc.) and re-validate until clean.
     Do not emit the RETURN SHAPE with an un-validated artifact.
  5. Write the completion marker on success:
       .claude-audit/current/phase-{{NN}}-{{category}}-{{partition_id}}.done

RETURN SHAPE (stdout, strictly one JSON object, no prose):
  {
    "phase": "{{NN-name}}",
    "category": "{{category}}",
    "partition": "{{partition_id}}",
    "surface_checked": <integer>,
    "findings_count": <integer>,
    "by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 },
    "artifact_path": "<relative path to the JSONL you wrote>",
    "done_marker": "<relative path to the .done marker>",
    "notes": "<=200 chars, free text"
  }

CONSTRAINTS (read carefully, all apply):
  - NEVER echo file contents back to the orchestrator. Write to disk only.
  - NEVER spawn a nested sub-agent. Escalation mechanism is in RETURN SHAPE
    below (see `status: needs_recursion`).
  - Model: Claude Opus 4.7 (1M context). No downgrade to Sonnet/Haiku.
  - Token budget: 500K soft / 800K hard raw code in context. If the
    partition scope exceeds the soft target, RETURN:
      {
        "status": "needs_recursion",
        "reason": "<why>",
        "suggested_split": [ {"id": "...", "paths_included": [...]}, ... ]
      }
    and exit. The orchestrator will fan out sub-partitions.
  - maxTurns budget: 80.
  - Every finding MUST include:
      id (sub-agent-locally unique),
      severity (CRITICAL|HIGH|MEDIUM|LOW|INFO),
      confidence (CONFIRMED|LIKELY|POSSIBLE),
      category,
      partition,
      file,
      line,
      cwe   (required; fall back to "CWE-1007" if no better mapping),
      owasp_ids[]   (e.g., ["ASVS-V6.2.1", "API1:2023"]),
      title,
      description,
      sources[]   (how the finding was derived: grep_pattern_name, scanner_rule_id, manual)
    Optional but strongly encouraged:
      suggested_fix, code_owner, attack_scenario, remediation_effort.

EXIT:
  When finished, emit only the single JSON RETURN SHAPE object. Nothing
  before or after.
```

---

## Invocation from the orchestrator

Call pattern (pseudocode for the Agent tool):

```text
Agent({
  description: "<phase-or-category> audit for <partition_id>",
  subagent_type: "general-purpose",
  model: "opus",
  prompt: <the filled template above>
})
```

Concurrency: the orchestrator caps in-flight sub-agents at **8**. Rationale:
avoids rate-limit pressure while keeping Phase 5's partition×category fan-out
tractable (10 partitions × 9 categories = 90 — batched 8 at a time).

## Error handling

If a sub-agent's stdout is not parseable JSON matching the RETURN SHAPE,
the orchestrator treats it as a failure and:
1. Logs the raw output under `.claude-audit/current/audit.log`.
2. Retries **once** with an amended prompt appending: "Your previous response
   was not valid JSON matching the RETURN SHAPE. Return only the JSON."
3. If the retry also fails, records a placeholder finding:
   `{severity: "INFO", title: "Sub-agent <id> failed", ...}` and moves on.
