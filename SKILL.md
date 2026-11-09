---
name: siem-rule-tuner
description: >
  Analyzes false-positive SIEM alert JSON telemetry from Wazuh, Microsoft Defender XDR, and Splunk,
  formulates surgical child exclusion rules (Wazuh XML and Defender KQL), and audits proposed exclusions
  for security blind spots and Living-Off-The-Land (LOLBin) vulnerabilities. Use whenever tuning SIEM
  false positives, analyzing noisy detection rules, formulating Wazuh XML child rules, drafting Defender
  KQL exclusions, or auditing detection rules for security blind spots.
---

# Wazuh & Defender SIEM False-Positive Rule Tuner (`siem-rule-tuner`)

## Purpose & Target Roles
Designed for **Detection Engineers, SOC Analysts (Tier 2/Tier 3), Blue Team Engineers, and Threat Detection Leads**.

In enterprise SOC environments, up to 70% of alert volume consists of benign false positives triggered by legitimate IT administration (e.g., Veeam backup agents, Intune Management Extension scripts, NinjaOne RMM monitoring daemons). Fatigued analysts frequently make catastrophic errors: disabling parent detection rules entirely or creating broad single-attribute exclusions (e.g., whitelisting `powershell.exe` by name or whitelisting `C:\Temp\*`), blinding the organization to real attacker tradecraft. This skill pairs an alert clustering analyzer (`scripts/analyze_siem_fp.py`) with a deterministic rule tuning and blind-spot audit engine (`scripts/tune_siem_rule.py`) to craft surgical, multi-attribute exclusions that eliminate noise while preserving detection integrity.

## Operating Rules & Safety Guardrails
1. **Never Disable Parent Detection Rules:** Never propose deleting, silencing, or disabling a core parent detection rule ID. Always formulate child rules with level 0 inheritance (`<if_sid>`) or negated boolean clauses (`| where not (...)`).
2. **Multi-Attribute Anchoring Mandatory:** An exclusion must anchor to at least three independent telemetry fields ($\text{Binary Path} + \text{Parent Binary} + \text{CommandLine} \lor \text{User} \lor \text{Signer}$). Single-attribute exclusions are strictly prohibited.
3. **LOLBin Blind-Spot Prevention:** Dual-use system binaries (e.g., `powershell.exe`, `certutil.exe`, `mshta.exe`, `rundll32.exe`, `wmic.exe`) must **never** be excluded without a verified enterprise service parent (e.g., `services.exe`, `AgentExecutor.exe`) and constrained command-line arguments.
4. **Mandatory Dual Validation Tests:** Every tuned rule must provide two test cases:
   - *Negative Test:* Benign administrative command verified to produce 0 alerts.
   - *Positive Test:* Adversary emulation verified to trigger the high-severity parent rule.
5. **Zero Secrets & Data Sanitization:** Never collect credentials, API tokens, passwords, or private keys. Client-side `--sanitize` mode masks user accounts, hostnames, and maps IP addresses to RFC 5737 documentation test subnets (`192.0.2.x`).

---

## Step 1: Telemetry Acquisition & Pre-Flight Checks

Determine how false-positive alert telemetry is being provided:

### Mode A: Automated Alert Log Tuning Engine (Recommended)
Analyze an exported false-positive alert JSON log from Wazuh or Defender:
```bash
# For Wazuh Sysmon / OSSEC alert dumps
python3 ./scripts/tune_siem_rule.py --input wazuh_alerts.json --platform wazuh --format markdown --sanitize

# For Microsoft Defender XDR / Sentinel Advanced Hunting JSON
python3 ./scripts/tune_siem_rule.py --input defender_alerts.json --platform defender --format markdown --sanitize
```

### Mode B: Alert Frequency & Noise Clustering Analysis
Extract recurring process hierarchies, command-line snippets, and account distributions from raw alert dumps:
```bash
python3 ./scripts/analyze_siem_fp.py --input raw_alerts.json --format wazuh --output fp_clustering_summary.json --sanitize
```

### Mode C: Direct Pasted Alert Snippet
If script execution is restricted, paste raw alert JSON or Sysmon Event 1 / Defender ProcessCreated event fields directly into chat.

---

## Step 2: 5-Domain Diagnostic & Analysis Workflow

Execute the detection tuning evaluation in strict sequential order:

### Domain 1: Telemetry Extraction & Attribute Anchoring
1. Inspect the alert payload and extract core telemetry anchors:
   - Process Binary Path (`win.eventdata.image` / `FolderPath`).
   - Parent Process Binary Path (`win.eventdata.parentImage` / `InitiatingProcessFolderPath`).
   - Execution Account (`win.eventdata.user` / `AccountName`).
   - Command-Line Arguments (`win.eventdata.commandLine` / `ProcessCommandLine`).
2. Verify that at least 3 distinct attributes are present.

### Domain 2: Legitimate Process & Vendor Verification
1. Verify the binary against legitimate administrative software catalogs:
   - Backup solutions: Veeam (`VeeamGuestHelper.exe`), Commvault (`cvd.exe`).
   - RMM tools: NinjaOne (`NinjaRMMAgent.exe`), Datto (`AEMAgent.exe`).
   - Endpoint management: Intune (`AgentExecutor.exe`), SCCM (`CcmExec.exe`).
2. Confirm the execution path aligns with standard program directory structures (`C:\Program Files\`, `C:\Program Files (x86)\`). Flag any binary executing from temporary or user-writable paths (`AppData`, `Temp`, `Public`).

### Domain 3: MITRE ATT&CK & LOLBin Blind-Spot Audit
1. Cross-reference the executable against `references/lolbin-blindspot-catalog.md`.
2. If the binary is a recognized Living-off-the-Land binary (e.g. `certutil.exe`, `powershell.exe`, `rundll32.exe`):
   - Assert that parent process is a verified enterprise service daemon (e.g., `services.exe`, `AgentExecutor.exe`).
   - Assert that command-line arguments are explicitly constrained to legitimate parameters.
   - Reject immediately if wildcard or blanket exclusions are proposed for a LOLBin.

### Domain 4: Multi-Platform Rule Code Synthesis
1. **Wazuh XML Generation:**
   - Formulate `<rule id="NEW_ID" level="0">` child rule inheriting parent via `<if_sid>PARENT_ID</if_sid>`.
   - Double-escape backslashes and periods for regex anchors (`^C:\\\\Program Files\\\\...$`).
2. **Microsoft Defender KQL Generation:**
   - Formulate `| where not (...)` multi-field boolean clause using case-insensitive matching (`=~`).
3. **Splunk SPL Generation:**
   - Formulate `NOT (...)` boolean sub-search filter.

### Domain 5: Regression & True-Positive Test Synthesis
1. Formulate a **Negative Test Case** matching legitimate administrative execution.
2. Formulate a **Positive Test Case** simulating an attacker executing the same binary from a rogue directory (e.g. `%TEMP%`) or via an unapproved parent process (e.g. `cmd.exe`), confirming parent detection remains fully operational.

---

## Step 3: Decision Points & Escalation Matrix

Evaluate the tuning findings against the 4-gate governance rubric:

- **Decision Point A (Approved Child Rule):**
  - *Criteria:* Verified legitimate administrative tool, $\ge 3$ distinct anchors, no LOLBin blind spots, dual test cases validated.
  - *Action:* Deploy production child rule syntax to `local_rules.xml` (Wazuh) or custom detection rule (Defender).
- **Decision Point B (Rejected - Broad Exclusion):**
  - *Criteria:* Fewer than 3 telemetry anchors present (e.g., path-only or user-only exclusion).
  - *Action:* Reject exclusion; request command-line arguments and parent process details.
- **Decision Point C (Rejected - Critical Blind Spot):**
  - *Criteria:* Attempted exclusion of LOLBin without strict parent/commandline constraints or binary located in user-writable temp path.
  - *Action:* Block rule deployment; flag critical security vulnerability to SOC Lead.

---

## Output Format Specification

All outputs generated by this skill must conform to `assets/siem-tuning-report-template.md`:

1. **Executive Summary:** Target Rule ID, Noise Volume, Estimated Reduction %, Governance Disposition.
2. **Telemetry Clustering Table:** Process Image, Parent Image, User, and Command Line.
3. **Blind-Spot & Security Review:** Audit against the 4-gate governance rubric.
4. **Production Exclusion Code:** Syntactically verified Wazuh XML or Defender KQL code block.
5. **Dual Validation Test Cases:** Negative and Positive test commands with expected outcomes.
