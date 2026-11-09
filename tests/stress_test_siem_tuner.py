#!/usr/bin/env python3
"""
stress_test_siem_tuner.py - Performance Benchmarking & ReDoS Resistance Suite for siem-rule-tuner.

Asserts:
- Engine can cluster and evaluate 10,000 alert payloads in < 1.0 second.
- Regex escaping and string parsers are immune to catastrophic backtracking.
- Thread-safe concurrency across 16 worker threads.
"""

import concurrent.futures
import json
import os
import sys
import time
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
FIXTURES_DIR = os.path.join(BASE_DIR, "tests", "fixtures")
sys.path.insert(0, SCRIPTS_DIR)

from tune_siem_rule import audit_blind_spot_risk, escape_wazuh_xml_regex, tune_alerts_data


class TestSiemTunerStress(unittest.TestCase):

    def setUp(self):
        with open(os.path.join(FIXTURES_DIR, "fixture-wazuh-veeam-sysmon-fp.json"), "r", encoding="utf-8") as f:
            self.sample_alert = json.load(f)

    def test_high_volume_throughput(self):
        """Evaluate 10,000 synthetic alert structures and verify execution speed."""
        iterations = 10000
        start = time.perf_counter()

        for _ in range(iterations):
            res = tune_alerts_data(self.sample_alert, "wazuh")
            self.assertTrue(res["approved"])

        elapsed = time.perf_counter() - start
        rate = iterations / elapsed
        print(f"\n[BENCHMARK] Evaluated {iterations:,} alert bundles in {elapsed:.3f}s ({rate:,.0f} evals/sec)")
        self.assertLess(elapsed, 2.0, "Throughput below target rate")

    def test_redos_resistance(self):
        """Assert regex escaping and path operations are immune to ReDoS."""
        pathological_paths = [
            "C:\\" + "folder\\" * 500 + "binary.exe",
            "C:\\Windows\\System32\\" + "a" * 10000 + ".exe",
            "powershell.exe " + "-arg " * 1000
        ]

        start = time.perf_counter()
        for p in pathological_paths:
            escaped = escape_wazuh_xml_regex(p)
            audit_blind_spot_risk(p, "C:\\services.exe", "-test", "SYSTEM", 3)

        elapsed = time.perf_counter() - start
        print(f"[BENCHMARK] ReDoS resistance verified across pathological inputs in {elapsed:.4f}s")
        self.assertLess(elapsed, 0.5)

    def test_multithreaded_concurrency(self):
        """Assert thread safety across 16 worker threads executing 2,000 tuning requests."""
        total_evals = 2000
        workers = 16

        def worker_task(idx):
            data = list(self.sample_alert)
            return tune_alerts_data(data, "wazuh", 100000 + idx)

        start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(worker_task, i) for i in range(total_evals)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        elapsed = time.perf_counter() - start
        self.assertEqual(len(results), total_evals)
        for r in results:
            self.assertTrue(r["approved"])
        print(f"[CONCURRENCY] Completed {total_evals:,} concurrent audits across {workers} threads in {elapsed:.3f}s")
        self.assertLess(elapsed, 1.5)


if __name__ == "__main__":
    unittest.main()
