#!/usr/bin/env python3
"""
test_siem_tuner_engine.py - Functional Unit Tests for SIEM Rule Tuning Engine.
"""

import json
import os
import sys
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
sys.path.insert(0, SCRIPTS_DIR)

from analyze_siem_fp import analyze_fp_alerts, extract_alert_attributes, sanitize_bundle
from tune_siem_rule import (
    audit_blind_spot_risk,
    escape_wazuh_xml_regex,
    extract_binary_name,
    generate_defender_kql_exclusion,
    generate_validation_test_cases,
    generate_wazuh_child_rule,
    tune_alerts_data
)


class TestSiemTunerEngine(unittest.TestCase):

    def test_binary_name_extraction(self):
        """Test extraction of binary name across Windows and POSIX paths."""
        self.assertEqual(extract_binary_name("C:\\Windows\\System32\\powershell.exe"), "powershell.exe")
        self.assertEqual(extract_binary_name("/usr/bin/python3"), "python3")
        self.assertEqual(extract_binary_name("cmd.exe"), "cmd.exe")
        self.assertEqual(extract_binary_name(""), "")

    def test_wazuh_regex_escaping(self):
        """Test proper double-escaping of backslashes and dots for Wazuh XML."""
        raw = "C:\\Program Files\\App\\bin.exe"
        escaped = escape_wazuh_xml_regex(raw)
        self.assertEqual(escaped, "^C:\\\\Program Files\\\\App\\\\bin\\.exe$")

    def test_blind_spot_gate_1_multi_attribute(self):
        """Reject proposed exclusion with fewer than 3 attributes."""
        approved, defects, disp = audit_blind_spot_risk(
            image_path="C:\\Tools\\app.exe",
            parent_path="",
            command_line="",
            user="",
            attributes_count=1
        )
        self.assertFalse(approved)
        self.assertEqual(disp, "REJECTED")
        self.assertTrue(any("Gate 1 Failure" in d for d in defects))

    def test_blind_spot_gate_2_lolbin_rejection(self):
        """Reject LOLBin exclusion without parent or command line constraints."""
        approved, defects, disp = audit_blind_spot_risk(
            image_path="C:\\Windows\\System32\\certutil.exe",
            parent_path="C:\\Windows\\explorer.exe",
            command_line="",
            user="user1",
            attributes_count=3
        )
        self.assertFalse(approved)
        self.assertTrue(any("Gate 2 Failure" in d for d in defects))

    def test_blind_spot_gate_3_unsafe_directory(self):
        """Reject exclusion for binaries running in temp or public directory without command line."""
        approved, defects, disp = audit_blind_spot_risk(
            image_path="C:\\Users\\Public\\malware.exe",
            parent_path="C:\\Windows\\System32\\cmd.exe",
            command_line="",
            user="user1",
            attributes_count=3
        )
        self.assertFalse(approved)
        self.assertTrue(any("Gate 3 Failure" in d for d in defects))

    def test_wazuh_xml_generation(self):
        """Test synthesis of level 0 Wazuh XML child rule."""
        xml = generate_wazuh_child_rule(
            rule_id="60103",
            new_rule_id=100101,
            image_path="C:\\Program Files\\Veeam\\VeeamGuestHelper.exe",
            parent_path="C:\\Windows\\System32\\services.exe",
            user="NT AUTHORITY\\SYSTEM",
            command_line="-runAsService",
            description="Exclude legitimate Veeam activity"
        )
        self.assertIn('<rule id="100101" level="0">', xml)
        self.assertIn('<if_sid>60103</if_sid>', xml)
        self.assertIn('VeeamGuestHelper\\.exe', xml)
        self.assertIn('services\\.exe', xml)
        self.assertIn('NT AUTHORITY\\\\SYSTEM', xml)

    def test_defender_kql_generation(self):
        """Test synthesis of Defender KQL exclusion clause."""
        kql = generate_defender_kql_exclusion(
            image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            parent_path="C:\\Program Files (x86)\\Microsoft Intune Management Extension\\AgentExecutor.exe",
            user="SYSTEM",
            command_line="-file detect.ps1"
        )
        self.assertIn("| where not (", kql)
        self.assertIn('FolderPath =~ @"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"', kql)
        self.assertIn('InitiatingProcessFolderPath =~ @"C:\\Program Files (x86)\\Microsoft Intune Management Extension\\AgentExecutor.exe"', kql)
        self.assertIn('ProcessCommandLine has "-file detect.ps1"', kql)

    def test_validation_test_generation(self):
        """Test synthesis of dual negative and positive test commands."""
        tests = generate_validation_test_cases(
            binary_name="VeeamGuestHelper.exe",
            image_path="C:\\Program Files\\Veeam\\VeeamGuestHelper.exe",
            parent_path="C:\\Windows\\System32\\services.exe",
            command_line="-runAsService"
        )
        self.assertIn("& \"C:\\Program Files\\Veeam\\VeeamGuestHelper.exe\" -runAsService", tests["negative_test_command"])
        self.assertIn("Start-Process powershell.exe", tests["positive_test_command"])


if __name__ == "__main__":
    unittest.main()
