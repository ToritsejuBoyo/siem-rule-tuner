#!/usr/bin/env python3
"""
analyze_siem_fp.py - SIEM False-Positive Alert Log Analyzer & Clustering Engine.

Analyzes raw false-positive alert dumps from Wazuh, Microsoft Defender XDR, and generic SIEMs.
Clusters recurring process hierarchies, command lines, and user accounts to identify
noise reduction targets.

Enforces Rule 3 (Zero 3rd-party dependencies, standard library only)
and Rule 4 (Client-side data sanitization).
"""

import argparse
from collections import Counter
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

TEST_IP_MAP: Dict[str, str] = {}
TEST_IP_COUNTER = 1


def hash_identifier(val: str, prefix: str = "ID") -> str:
    """Generate deterministic SHA-256 masked identifier (idempotent)."""
    if not val:
        return ""
    if val.startswith(f"{prefix}-") and len(val) == len(prefix) + 9:
        return val
    h = hashlib.sha256(val.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{h}"


def sanitize_ip(ip_str: str) -> str:
    """Map IPv4 addresses to RFC 5737 test subnets (192.0.2.x) (idempotent)."""
    global TEST_IP_COUNTER
    if ip_str.startswith("192.0.2."):
        return ip_str
    if ip_str not in TEST_IP_MAP:
        TEST_IP_MAP[ip_str] = f"192.0.2.{TEST_IP_COUNTER % 250 + 1}"
        TEST_IP_COUNTER += 1
    return TEST_IP_MAP[ip_str]


def sanitize_text(text: str) -> str:
    """Mask emails, hostnames, IPs, and internal domains (idempotent)."""
    if not isinstance(text, str):
        return text

    # Mask email addresses
    def _replace_email(m):
        addr = m.group(0)
        if addr.startswith("user-") and "@" in addr and addr.endswith(".corp.example.internal"):
            return addr
        h = hashlib.sha256(addr.encode()).hexdigest()[:6]
        return f"user-{h}@corp.example.internal"

    email_pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9_.-]+"
    text = re.sub(email_pattern, _replace_email, text)

    # Mask IPv4 addresses
    ipv4_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    text = re.sub(ipv4_pattern, lambda m: sanitize_ip(m.group(0)), text)

    # Mask standard FQDNs ending in internal or corp (not preceded by @)
    def _replace_fqdn(m):
        fqdn = m.group(0)
        if fqdn.startswith("host-") and fqdn.endswith(".corp.example.internal"):
            return fqdn
        h = hashlib.sha256(fqdn.encode()).hexdigest()[:6]
        return f"host-{h}.corp.example.internal"

    fqdn_pattern = r"(?<!@)\b[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*\.(?:corp|local|internal|lan)\b"
    text = re.sub(fqdn_pattern, _replace_fqdn, text)

    return text


def sanitize_bundle(data: Any, max_depth: int = 100) -> Any:
    """Recursively sanitize alert dictionary or list structures."""
    if max_depth <= 0:
        return "<MAX_RECURSION_DEPTH_EXCEEDED>"
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            k_low = k.lower()
            if k_low in ("agent_name", "computer_name", "devicename", "hostname", "hosts", "hostnames"):
                if isinstance(v, list):
                    sanitized[k] = [hash_identifier(str(item), "HOST") for item in v]
                else:
                    sanitized[k] = hash_identifier(str(v), "HOST") if v else v
            elif k_low in ("user", "accountname", "accountupn", "username", "users", "accounts"):
                if isinstance(v, list):
                    sanitized[k] = [hash_identifier(str(item), "USER") for item in v]
                else:
                    sanitized[k] = hash_identifier(str(v), "USER") if v else v
            else:
                sanitized[k] = sanitize_bundle(v, max_depth - 1)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_bundle(item, max_depth - 1) for item in data]
    elif isinstance(data, str):
        return sanitize_text(data)
    else:
        return data


def extract_alert_attributes(alert: Any, fmt: str) -> Dict[str, str]:
    """Extract standard telemetry attributes from various SIEM alert formats."""
    img = "Unknown"
    pimg = "Unknown"
    user = "Unknown"
    cmd = ""
    rule_id = "Unknown"
    rule_desc = "Unknown"

    if not isinstance(alert, dict):
        return {
            "rule_id": "Unknown",
            "rule_description": "Unknown",
            "image": "Unknown",
            "parent_image": "Unknown",
            "user": "Unknown",
            "command_line": ""
        }

    if fmt == "wazuh" or "rule" in alert:
        rule_info = alert.get("rule")
        if not isinstance(rule_info, dict):
            rule_info = {}
        rule_id = str(rule_info.get("id") or alert.get("rule_id", "Unknown"))
        rule_desc = str(rule_info.get("description") or alert.get("rule_description", "Unknown"))

        data_obj = alert.get("data")
        if not isinstance(data_obj, dict):
            data_obj = {}
        win_obj = data_obj.get("win")
        if not isinstance(win_obj, dict):
            win_obj = {}
        eventdata = win_obj.get("eventdata")
        if not isinstance(eventdata, dict):
            eventdata = data_obj.get("eventdata")
            if not isinstance(eventdata, dict):
                eventdata = {}

        img = (
            eventdata.get("image") or alert.get("image") or alert.get("process")
            or alert.get("Image") or alert.get("FolderPath") or "Unknown"
        )
        pimg = (
            eventdata.get("parentImage") or alert.get("parentImage") or alert.get("parent_image")
            or alert.get("ParentImage") or alert.get("InitiatingProcessFolderPath") or "Unknown"
        )
        user = eventdata.get("user") or alert.get("user") or alert.get("User", "Unknown")
        cmd = (
            eventdata.get("commandLine") or alert.get("commandLine") or alert.get("command_line")
            or alert.get("CommandLine") or alert.get("ProcessCommandLine") or ""
        )

    elif fmt == "defender" or "DeviceName" in alert or "FolderPath" in alert:
        rule_id = alert.get("AlertId") or alert.get("Title") or "DefenderRule"
        rule_desc = alert.get("AlertTitle") or alert.get("Description") or "Defender Process Event"
        img = alert.get("FolderPath") or alert.get("FileName") or alert.get("Image", "Unknown")
        pimg = alert.get("InitiatingProcessFolderPath") or alert.get("ParentImage", "Unknown")
        user = alert.get("AccountName") or alert.get("InitiatingProcessAccountName", "Unknown")
        cmd = alert.get("ProcessCommandLine") or alert.get("CommandLine", "")

    else:
        img = alert.get("image") or alert.get("process") or alert.get("Image", "Unknown")
        pimg = alert.get("parent_image") or alert.get("ParentImage", "Unknown")
        user = alert.get("user") or alert.get("User", "Unknown")
        cmd = alert.get("command_line") or alert.get("CommandLine", "")
        rule_id = alert.get("rule_id", "GenericRule")

    return {
        "rule_id": str(rule_id),
        "rule_description": str(rule_desc),
        "image": str(img) if img is not None else "Unknown",
        "parent_image": str(pimg) if pimg is not None else "Unknown",
        "user": str(user) if user is not None else "Unknown",
        "command_line": str(cmd) if cmd is not None else ""
    }


def analyze_fp_alerts(alerts_data: Any, fmt: str = "wazuh") -> Dict[str, Any]:
    """Cluster alerts and calculate frequency metrics and noise drivers."""
    if not isinstance(alerts_data, list):
        if isinstance(alerts_data, dict):
            alerts = [alerts_data]
        else:
            return {"error": "Invalid input: expected alert list or dictionary", "total_alerts_analyzed": 0}
    else:
        alerts = alerts_data

    images = Counter()
    parent_images = Counter()
    users = Counter()
    rules = Counter()
    command_snippets = Counter()
    clusters = []

    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        attrs = extract_alert_attributes(alert, fmt)
        images[attrs["image"]] += 1
        parent_images[attrs["parent_image"]] += 1
        users[attrs["user"]] += 1
        rules[attrs["rule_id"]] += 1

        # Extract normalized command argument tokens
        if attrs["command_line"]:
            # Capture first 60 chars of commandline
            snippet = attrs["command_line"][:60].strip()
            command_snippets[snippet] += 1

        clusters.append(attrs)

    total = len(alerts)
    top_rule = rules.most_common(1)[0][0] if rules else "Unknown"
    top_image = images.most_common(1)[0][0] if images else "Unknown"
    top_parent = parent_images.most_common(1)[0][0] if parent_images else "Unknown"

    return {
        "total_alerts_analyzed": total,
        "primary_noisy_rule_id": top_rule,
        "primary_process_image": top_image,
        "primary_parent_image": top_parent,
        "format": fmt,
        "top_process_images": images.most_common(5),
        "top_parent_images": parent_images.most_common(5),
        "top_users": users.most_common(5),
        "top_rules": rules.most_common(5),
        "top_command_snippets": command_snippets.most_common(5),
        "recommendation": (
            f"Rule {top_rule} generates {total} alerts predominantly from '{os.path.basename(str(top_image))}' "
            f"spawned by '{os.path.basename(str(top_parent))}'. Recommend multi-attribute child exclusion."
            if total > 0 else "No alerts analyzed."
        )
    }


def main():
    parser = argparse.ArgumentParser(description="Analyze SIEM false-positive alert dumps.")
    parser.add_argument("--input", "-i", required=True, help="Path to alert JSON file")
    parser.add_argument("--format", "--platform", "--siem", "-f", dest="format", choices=["wazuh", "defender", "generic"], default="wazuh", help="Alert format")
    parser.add_argument("--output", "-o", default=None, help="Output JSON path")
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

    res = analyze_fp_alerts(data, args.format)
    out_json = json.dumps(res, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_json)
        print(f"SIEM analysis saved to {args.output}")
    else:
        print(out_json)


if __name__ == "__main__":
    main()
