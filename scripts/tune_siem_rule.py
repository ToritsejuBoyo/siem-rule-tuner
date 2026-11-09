#!/usr/bin/env python3
"""
tune_siem_rule.py - Multi-Platform SIEM False-Positive Rule Tuner & Blind-Spot Auditor.

Ingests false-positive alert JSON telemetry from Wazuh, Microsoft Defender XDR, or generic SIEMs.
Audits proposed exclusions against the MITRE ATT&CK Living Off The Land Binaries (LOLBins) rubric,
enforces multi-attribute anchoring (>= 3 conditions), and synthesizes production-ready
child exclusion rules (Wazuh XML and Defender KQL) with regression test cases.

Enforces Rule 3 (Zero 3rd-party dependencies, strictly standard library)
and Rule 4 (Client-side data sanitization).
"""

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

from analyze_siem_fp import analyze_fp_alerts, extract_alert_attributes, sanitize_bundle

# Recognized Living Off The Land Binaries requiring strict multi-anchor constraints
LOLBIN_CATALOG = {
    "powershell.exe": {"technique": "T1059.001", "name": "PowerShell Scripting"},
    "pwsh.exe": {"technique": "T1059.001", "name": "PowerShell Core"},
    "cmd.exe": {"technique": "T1059.003", "name": "Windows Command Shell"},
    "certutil.exe": {"technique": "T1105", "name": "Certificate Utility / Ingress Transfer"},
    "mshta.exe": {"technique": "T1218.005", "name": "HTML Application Host"},
    "rundll32.exe": {"technique": "T1218.011", "name": "Run DLL Host Process"},
    "regsvr32.exe": {"technique": "T1218.010", "name": "Register OLE Server"},
    "wmic.exe": {"technique": "T1047", "name": "WMI Command Line Utility"},
    "bitsadmin.exe": {"technique": "T1197", "name": "BITS Administration Utility"},
    "cscript.exe": {"technique": "T1059.005", "name": "Command Line VBScript/JScript Engine"},
    "wscript.exe": {"technique": "T1059.005", "name": "Windows VBScript/JScript Engine"},
    "curl.exe": {"technique": "T1105", "name": "Command Line File Transfer"},
    "wget.exe": {"technique": "T1105", "name": "Wget File Transfer"},
    "schtasks.exe": {"technique": "T1053.005", "name": "Scheduled Task Utility"}
}

# Recognized legitimate enterprise service parents
TRUSTED_SERVICE_PARENTS = [
    "services.exe",
    "agentexecutor.exe",
    "ccmexec.exe",
    "ninjarmmagent.exe",
    "veeamguesthelper.exe",
    "aemagent.exe",
    "himds.exe"
]

# Recognized offensive security & credential theft tools
KNOWN_HACKTOOLS = {
    "mimikatz.exe",
    "sharphound.exe",
    "rubeus.exe",
    "seatbelt.exe",
    "bloodhound.exe",
    "pwdump.exe",
    "chisel.exe",
    "nc.exe",
    "netcat.exe"
}


def escape_wazuh_xml_regex(val: str) -> str:
    """Escape backslashes and periods for Wazuh XML regex pattern."""
    if not val:
        return ""
    # Double-escape backslashes for XML text representation
    escaped = val.replace("\\", "\\\\").replace(".", "\\.")
    return f"^{escaped}$"


def extract_binary_name(path: str) -> str:
    """Extract lowercase executable filename from path."""
    if not path:
        return ""
    # Normalize Windows and POSIX separators
    norm = path.replace("\\", "/").strip().lower()
    return norm.split("/")[-1]


def audit_blind_spot_risk(
    image_path: str,
    parent_path: str,
    command_line: str,
    user: str,
    attributes_count: int
) -> Tuple[bool, List[str], str]:
    """Audit proposed exclusion against 4-gate detection engineering rubric."""
    defects = []
    binary_name = extract_binary_name(image_path)
    parent_name = extract_binary_name(parent_path)

    # Gate 1: Multi-Attribute Anchor Requirement (>= 3 conditions)
    if attributes_count < 3:
        defects.append(
            f"Gate 1 Failure (Broad Exclusion): Proposed exclusion has only {attributes_count} condition(s). "
            f"Detection engineering policy requires at least 3 distinct telemetry anchors (Image + Parent + CLI/User/Signer)."
        )

    # Gate 2: LOLBin Security Safeguard
    if binary_name in LOLBIN_CATALOG:
        technique = LOLBIN_CATALOG[binary_name]["technique"]
        # Must have specific parent and command-line
        if not parent_path or parent_name in ("unknown", "explorer.exe", "cmd.exe"):
            defects.append(
                f"Gate 2 Failure (Critical Blind Spot): '{binary_name}' is a high-risk LOLBin ({technique}). "
                f"Excluding it without a verified enterprise parent binary creates a severe bypass vulnerability."
            )
        if not command_line or len(command_line.strip()) < 5:
            defects.append(
                f"Gate 2 Failure (Critical Blind Spot): '{binary_name}' ({technique}) excluded without "
                f"exact command-line argument constraints. Attackers can execute arbitrary payloads using this binary."
            )

    # Gate 3: Wildcard Root Directory Prohibitions
    for dangerous_dir in ["\\temp\\", "\\appdata\\", "\\users\\public\\", "\\tmp/"]:
        if dangerous_dir in image_path.lower():
            if not command_line or parent_name in ("cmd.exe", "powershell.exe", "explorer.exe", "unknown", ""):
                defects.append(
                    f"Gate 3 Failure (Unsafe Directory): Excluding binaries running from temporary or public user paths "
                    f"('{dangerous_dir}') without cryptographic hash, or spawned by untrusted shells ('{parent_name}'), is strictly prohibited."
                )

    # Gate 4: Recognized Malicious Exploitation Tools
    if binary_name in KNOWN_HACKTOOLS:
        defects.append(
            f"Gate 4 Failure (Known Malicious Tool): '{binary_name}' is a recognized offensive exploitation or "
            f"credential theft tool. Creating false-positive exclusion rules for attack tools is strictly prohibited."
        )

    approved = len(defects) == 0
    disposition = "APPROVED" if approved else "REJECTED"
    return approved, defects, disposition


def generate_wazuh_child_rule(
    rule_id: str,
    new_rule_id: int,
    image_path: str,
    parent_path: str,
    user: str,
    command_line: str,
    description: str
) -> str:
    """Generate syntactically correct Wazuh XML child rule (level 0)."""
    lines = [
        '<group name="sysmon,windows,">',
        f'  <!-- Surgical False-Positive Tuning Exclusion for Rule {rule_id} -->',
        f'  <rule id="{new_rule_id}" level="0">',
        f'    <if_sid>{rule_id}</if_sid>'
    ]

    if image_path and image_path != "Unknown":
        escaped_img = escape_wazuh_xml_regex(image_path)
        lines.append(f'    <field name="win.eventdata.image">{escaped_img}</field>')

    if parent_path and parent_path != "Unknown":
        escaped_parent = escape_wazuh_xml_regex(parent_path)
        lines.append(f'    <field name="win.eventdata.parentImage">{escaped_parent}</field>')

    if user and user != "Unknown":
        escaped_user = escape_wazuh_xml_regex(user)
        lines.append(f'    <field name="win.eventdata.user">{escaped_user}</field>')

    if command_line:
        # Use simple substring match for commandLine arguments to allow parameter variations
        cmd_snippet = command_line[:60].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        escaped_cmd = re.escape(cmd_snippet).replace(r"\ ", " ")
        lines.append(f'    <field name="win.eventdata.commandLine" type="pcre2">(?i){escaped_cmd}</field>')

    lines.append(f'    <description>Tuned Exclusion: {description}</description>')
    lines.append('  </rule>')
    lines.append('</group>')

    return "\n".join(lines)


def generate_defender_kql_exclusion(
    image_path: str,
    parent_path: str,
    user: str,
    command_line: str
) -> str:
    """Generate Microsoft Defender XDR / Sentinel KQL exclusion clause."""
    conditions = []

    if image_path and image_path != "Unknown":
        conditions.append(f'    FolderPath =~ @"{image_path}"')

    if parent_path and parent_path != "Unknown":
        conditions.append(f'    and InitiatingProcessFolderPath =~ @"{parent_path}"')

    if user and user != "Unknown":
        conditions.append(f'    and AccountName =~ "{user}"')

    if command_line:
        snippet = command_line[:50].replace('"', '""')
        conditions.append(f'    and ProcessCommandLine has "{snippet}"')

    joined = "\n".join(conditions)
    return f"""// Multi-Attribute Surgical Exclusion Clause
| where not (
{joined}
)"""


def generate_validation_test_cases(
    binary_name: str,
    image_path: str,
    parent_path: str,
    command_line: str
) -> Dict[str, str]:
    """Synthesize negative (FP suppression) and positive (TP preservation) validation test commands."""
    cmd_args = command_line if command_line else "-testExecution"

    # Negative test case: exact match of legitimate administrative activity (must not fire)
    neg_cmd = f'& "{image_path}" {cmd_args}'

    # Positive test case: simulated attacker execution using atypical path or rogue parent (must fire)
    pos_cmd = f'Start-Process powershell.exe -ArgumentList \'-ExecutionPolicy Bypass -Command "& \\"$env:TEMP\\{binary_name}\\" -maliciousPayload"\''

    return {
        "negative_test_command": neg_cmd,
        "positive_test_command": pos_cmd
    }


def tune_alerts_data(
    data: Any,
    platform: str = "wazuh",
    new_rule_id: int = 100101,
    custom_description: Optional[str] = None
) -> Dict[str, Any]:
    """Perform complete tuning evaluation, blind-spot audit, and rule synthesis."""
    if not isinstance(data, (dict, list)):
        return {
            "tuning_disposition": "REJECTED",
            "approved": False,
            "blind_spot_defects": ["Invalid telemetry payload: expected dictionary or list."],
            "production_rule_code": "",
            "platform": platform
        }

    clustering = analyze_fp_alerts(data, platform)
    total_alerts = clustering.get("total_alerts_analyzed", 0)

    # Extract primary indicators
    primary_rule = clustering.get("primary_noisy_rule_id", "60103")
    image_path = clustering.get("primary_process_image", "Unknown")
    parent_path = clustering.get("primary_parent_image", "Unknown")
    top_users = clustering.get("top_users", [])
    user = top_users[0][0] if top_users else "Unknown"

    top_cmds = clustering.get("top_command_snippets", [])
    cmd_snippet = top_cmds[0][0] if top_cmds else ""

    # Count distinct attributes present
    attr_count = 0
    if image_path and image_path != "Unknown":
        attr_count += 1
    if parent_path and parent_path != "Unknown":
        attr_count += 1
    if user and user != "Unknown":
        attr_count += 1
    if cmd_snippet:
        attr_count += 1

    # Audit for blind-spot risks
    approved, defects, disposition = audit_blind_spot_risk(
        image_path, parent_path, cmd_snippet, user, attr_count
    )

    desc = custom_description or (
        f"Exclude legitimate {extract_binary_name(image_path)} activity spawned by {extract_binary_name(parent_path)}."
    )

    # Generate rule code if approved
    wazuh_xml = ""
    defender_kql = ""
    if approved:
        wazuh_xml = generate_wazuh_child_rule(
            primary_rule, new_rule_id, image_path, parent_path, user, cmd_snippet, desc
        )
        defender_kql = generate_defender_kql_exclusion(
            image_path, parent_path, user, cmd_snippet
        )

    # Generate test cases
    test_cases = generate_validation_test_cases(
        extract_binary_name(image_path), image_path, parent_path, cmd_snippet
    )

    rule_code = wazuh_xml if platform == "wazuh" else defender_kql

    return {
        "report_id": f"TUNE-{hashlib.sha256(str(image_path).encode()).hexdigest()[:8].upper()}",
        "platform": platform,
        "parent_rule_id": primary_rule,
        "tuning_disposition": disposition,
        "approved": approved,
        "blind_spot_defects": defects,
        "attributes_anchored_count": attr_count,
        "extracted_attributes": {
            "image_path": image_path,
            "parent_path": parent_path,
            "user": user,
            "command_line_snippet": cmd_snippet
        },
        "noise_metrics": {
            "total_alerts_analyzed": total_alerts,
            "estimated_noise_reduction_pct": 100.0 if approved else 0.0
        },
        "wazuh_xml_child_rule": wazuh_xml,
        "defender_kql_exclusion": defender_kql,
        "production_rule_code": rule_code,
        "validation_test_cases": test_cases
    }


def format_markdown_report(result: Dict[str, Any]) -> str:
    """Format professional Markdown Detection Hardening and Tuning Report."""
    attrs = result.get("extracted_attributes", {})
    noise = result.get("noise_metrics", {})
    tests = result.get("validation_test_cases", {})

    lines = [
        f"# SIEM False-Positive Tuning Report: Rule {result.get('parent_rule_id')}",
        "",
        "## Executive Summary",
        f"- **Tuning Disposition:** **{result.get('tuning_disposition')}**",
        f"- **SIEM Platform:** `{result.get('platform', 'wazuh').upper()}`",
        f"- **Analyzed Noise Volume:** {noise.get('total_alerts_analyzed', 0)} alerts in sample",
        f"- **Projected Noise Reduction:** {noise.get('estimated_noise_reduction_pct', 0.0)}%",
        f"- **Telemetry Anchors Bound:** {result.get('attributes_anchored_count', 0)} / 4 attributes",
        "",
        "---",
        "",
        "## Telemetry Clustering & Attribute Extraction",
        "| Attribute Field | Observed Telemetry Signature | Exclusion Constraint |",
        "| :--- | :--- | :--- |",
        f"| **Process Image** | `{attrs.get('image_path')}` | Anchored exact path regex |",
        f"| **Parent Process** | `{attrs.get('parent_path')}` | Anchored parent hierarchy |",
        f"| **User Account** | `{attrs.get('user')}` | Constrained service account |",
        f"| **Command Argument** | `{attrs.get('command_line_snippet') or 'N/A'}` | Parameter token match |",
        ""
    ]

    if result.get("blind_spot_defects"):
        lines.extend([
            "---",
            "",
            "## Blind-Spot & Security Policy Defects",
            "The proposed exclusion violates SOC detection engineering standards and cannot be deployed:"
        ])
        for idx, defect in enumerate(result["blind_spot_defects"], 1):
            lines.append(f"{idx}. {defect}")
        lines.append("")
    else:
        lines.extend([
            "---",
            "",
            "## Production Ready Exclusion Code",
            f"### Engine: `{result.get('platform', 'wazuh').upper()}`",
            "```xml" if result.get("platform") == "wazuh" else "```kql",
            result.get("production_rule_code", ""),
            "```",
            "",
            "---",
            "",
            "## Dual Validation Test Cases",
            "### Negative Test Case (Benign Administrative Activity - MUST NOT FIRE)",
            "```powershell",
            tests.get("negative_test_command", "# N/A"),
            "```",
            "",
            "### Positive Test Case (Adversary Emulation - MUST FIRE HIGH SEVERITY)",
            "```powershell",
            tests.get("positive_test_command", "# N/A"),
            "```",
            ""
        ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Formulate surgical SIEM false-positive child exclusions.")
    parser.add_argument("--input", "-i", required=True, help="Path to alert JSON file")
    parser.add_argument("--platform", "--siem", "-p", dest="platform", choices=["wazuh", "defender"], default="wazuh", help="Target SIEM platform")
    parser.add_argument("--rule-id", type=int, default=100101, help="New child rule ID (Wazuh only)")
    parser.add_argument("--output", "-o", default=None, help="Output file path (JSON or Markdown)")
    parser.add_argument("--format", "-f", choices=["json", "markdown"], default="json", help="Output format")
    parser.add_argument("--sanitize", action="store_true", help="Sanitize PII, accounts, hostnames, and IP addresses")
    args = parser.parse_args()

    try:
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            raw_data = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error loading input file '{args.input}': {e}\n")
        sys.exit(1)

    if args.sanitize:
        data = sanitize_bundle(raw_data)
    else:
        data = raw_data

    result = tune_alerts_data(data, args.platform, args.rule_id)

    if args.format == "markdown":
        output_content = format_markdown_report(result)
    else:
        output_content = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_content)
        print(f"Tuning report saved to: {args.output}")
    else:
        print(output_content)

    if not result["approved"]:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
