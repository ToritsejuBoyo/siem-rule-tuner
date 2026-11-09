# SIEM Detection Tuning Governance & Peer Review Rubric

This document specifies the four-gate review rubric required before applying any detection rule exclusion into production SIEM environments.

---

## The 4-Gate Tuning Approval Rubric

Every proposed false-positive tuning change must satisfy all four gates:

```text
[ Gate 1: Multi-Attribute ] -> [ Gate 2: LOLBin Safeguard ] -> [ Gate 3: Test Verification ] -> [ Gate 4: Peer Sign-Off ]
```

### Gate 1: Multi-Attribute Anchor Criteria
- An exclusion rule must anchor to at least **three independent telemetry fields**:
  1. Full binary path (`FolderPath` / `win.eventdata.image`).
  2. Parent process binary path (`InitiatingProcessFolderPath` / `win.eventdata.parentImage`).
  3. At least one of: Specific command-line substring, service account identity, or code-signing publisher.
- *Evaluation:* If $< 3$ anchors are present, the rule is **REJECTED** for excessive breadth.

### Gate 2: LOLBin & Living-Off-The-Land Verification
- If the target binary appears in `references/lolbin-blindspot-catalog.md`, verify that:
  1. The command line does not use wildcards on remote URLs or arbitrary script executions.
  2. The parent process is a verified enterprise service binary (e.g. `services.exe`, `AgentExecutor.exe`, `CcmExec.exe`).
- *Evaluation:* Any generic or wildcard exclusion for a LOLBin is **REJECTED**.

### Gate 3: Dual Validation Test Cases Mandatory
- The detection engineer must provide two reproducible validation cases:
  - **Negative Test Case (FP Suppression):** Re-runs the benign administrative command and confirms alert count $= 0$.
  - **Positive Test Case (TP Preservation):** Runs a simulated attack vector (e.g., executing the binary from `C:\Users\Public\` or using an unauthorized parent) and confirms an alert is successfully generated.

### Gate 4: Change Governance & Peer Sign-Off
- Exclusions must be submitted with:
  - Estimated weekly noise reduction percentage.
  - Justification linking to legitimate vendor documentation.
  - Review and sign-off by a Senior Detection Engineer or SOC Tier 3 Lead.
