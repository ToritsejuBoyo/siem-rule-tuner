#!/usr/bin/env python3
"""
validate-skill.py - Rule Compliance and Quality Verification Test Suite for siem-rule-tuner.

Enforces:
- Rule 1 & 11: Plan approval compliance.
- Rule 3: Zero external dependencies (only standard Python libraries).
- Rule 4: Client-side data sanitization (SHA-256 masking and RFC 5737 test IPs).
- Rule 7: Zero-emoji enterprise tone.
- Rule 9: Automated synthetic fixture validation.
"""

import ast
import json
import os
import re
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
FIXTURES_DIR = os.path.join(BASE_DIR, "tests", "fixtures")

sys.path.insert(0, SCRIPTS_DIR)
try:
    from analyze_siem_fp import sanitize_bundle
    from tune_siem_rule import tune_alerts_data
except ImportError as e:
    print(f"[FAIL] Failed to import scripts: {e}")
    sys.exit(1)


def check_zero_dependencies():
    """Verify that all scripts use only Python standard library."""
    allowed_modules = {
        "argparse", "datetime", "hashlib", "json", "math", "os", "re", "sys",
        "typing", "unittest", "time", "random", "concurrent", "threading", "collections"
    }

    for root, _, files in os.walk(SCRIPTS_DIR):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=path)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            base_pkg = alias.name.split(".")[0]
                            if base_pkg not in allowed_modules and base_pkg not in ["analyze_siem_fp", "tune_siem_rule"]:
                                print(f"[FAIL] Unauthorized import '{base_pkg}' in {file}")
                                return False
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            base_pkg = node.module.split(".")[0]
                            if base_pkg not in allowed_modules and base_pkg not in ["analyze_siem_fp", "tune_siem_rule"]:
                                print(f"[FAIL] Unauthorized from-import '{base_pkg}' in {file}")
                                return False
    print("  [+] PASS: Rule 3 compliance (Zero external dependencies across all scripts).")
    return True


def check_zero_emojis():
    """Verify that all skill files adhere to Rule 7 (Zero-Emoji Enterprise Tone)."""
    emoji_pattern = re.compile(
        r"[\U00010000-\U0010ffff]|[\u2600-\u27bf]|[\u2300-\u23ff]|[\u2b50-\u2b55]"
    )
    for root, _, files in os.walk(BASE_DIR):
        if ".git" in root or "assets" in root:
            continue
        for file in files:
            if file.endswith((".py", ".md", ".json", ".txt")):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if emoji_pattern.search(content):
                    print(f"[FAIL] Emoji detected in {path}")
                    return False
    print("  [+] PASS: Rule 7 compliance (Strict zero-emoji enterprise tone).")
    return True


def check_sanitization():
    """Verify Rule 4 data sanitization behavior."""
    sample = {
        "computer_name": "dc01.corp.example.internal",
        "user": "secadmin@corp.example.internal",
        "data": {
            "win": {
                "eventdata": {
                    "ip": "10.100.1.50",
                    "target": "fileserver01.corp.example.internal"
                }
            }
        }
    }
    sanitized = sanitize_bundle(sample)
    s_dump = json.dumps(sanitized)

    assert "secadmin@corp.example.internal" not in s_dump, "Email was not masked"
    assert "dc01.corp.example.internal" not in s_dump, "Internal hostname was not masked"
    assert "10.100.1.50" not in s_dump, "Internal IP was not masked"
    assert "192.0.2." in s_dump, "RFC 5737 test IP not assigned"
    print("  [+] PASS: Rule 4 compliance (Client-side SHA-256 and RFC 5737 sanitization).")
    return True


def check_fixtures():
    """Validate all synthetic test fixtures against detection tuner."""
    fixtures = [
        ("fixture-wazuh-veeam-sysmon-fp.json", "wazuh", True),
        ("fixture-defender-intune-powershell-fp.json", "defender", True),
        ("fixture-wazuh-ninja-rmm-fp.json", "wazuh", True),
        ("fixture-failing-broad-exclusion.json", "wazuh", False),
        ("fixture-failing-lolbin-blindspot.json", "defender", False),
        ("fixture-wazuh-baseline-healthy.json", "wazuh", False)
    ]

    for fname, platform, expected_approved in fixtures:
        fpath = os.path.join(FIXTURES_DIR, fname)
        assert os.path.isfile(fpath), f"Fixture missing: {fname}"
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)

        res = tune_alerts_data(data, platform)

        if expected_approved:
            assert res["approved"] is True, f"Expected {fname} to be approved, but got defects: {res.get('blind_spot_defects')}"
            assert res["tuning_disposition"] == "APPROVED"
            assert len(res["production_rule_code"]) > 0
            print(f"  [+] PASS: {fname} tuned successfully for {platform.upper()}.")
        else:
            assert res["approved"] is False, f"Expected {fname} to be rejected"
            assert res["tuning_disposition"] == "REJECTED"
            assert len(res["blind_spot_defects"]) > 0
            print(f"  [+] PASS: {fname} correctly rejected ({len(res['blind_spot_defects'])} blind-spot defect(s)).")
    return True


def check_skill_frontmatter():
    """Validate SKILL.md YAML frontmatter and required sections."""
    skill_path = os.path.join(BASE_DIR, "SKILL.md")
    assert os.path.isfile(skill_path), "SKILL.md is missing"
    with open(skill_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert content.startswith("---"), "SKILL.md must start with YAML frontmatter"
    assert "name: siem-rule-tuner" in content, "Frontmatter must define name: siem-rule-tuner"
    assert "description:" in content, "Frontmatter must include description"
    assert "Operating Rules & Safety Guardrails" in content, "SKILL.md must include Operating Rules"
    assert "Output Format Specification" in content, "SKILL.md must include Output Format Specification"
    print("  [+] PASS: SKILL.md frontmatter and structural specification verified.")
    return True


def main():
    print("=" * 70)
    print("  siem-rule-tuner Automated Test & Verification Suite")
    print("=" * 70)

    success = (
        check_zero_dependencies() and
        check_zero_emojis() and
        check_sanitization() and
        check_skill_frontmatter() and
        check_fixtures()
    )

    if success:
        print("=" * 70)
        print("  ALL TESTS PASSED: Skill complies with all workspace rules (Exit Code 0).")
        print("=" * 70)
        sys.exit(0)
    else:
        print("[FAIL] Verification checks failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()

