import unittest
from unittest.mock import patch

from tools.final_truth import verify_bug_bounty_truth
import server


CLOUD_RECON_PUBLIC = """
CLOUD RECON for www.example.org
============================================================
🔴 PUBLIC S3 BUCKETS (CRITICAL)
----------------------------------------
  https://example-downloads.s3.amazonaws.com
    Files: 11 — PUBLICLY LISTABLE
    PoC: curl 'https://example-downloads.s3.amazonaws.com'
"""


class BalancedTruthVerificationTests(unittest.TestCase):
    def _verify(self, **kwargs):
        with patch("tools.final_truth.requests.get", side_effect=Exception("offline")), patch(
            "tools.final_truth.requests.request", side_effect=Exception("offline")
        ):
            return verify_bug_bounty_truth(**kwargs)

    def test_balanced_surfaces_actionable_findings_from_tool_outputs(self):
        result = self._verify(
            chat_query="Scan https://example.org",
            report_text="",
            tool_outputs=[{"name": "cloud_recon", "text": CLOUD_RECON_PUBLIC}],
            verification_policy="balanced",
            primary_target="https://example.org",
        )
        names = [f["name"] for f in result["findings"]]
        self.assertIn("Public Cloud Storage Exposure", names)
        finding = next(f for f in result["findings"] if f["name"] == "Public Cloud Storage Exposure")
        self.assertEqual(finding["status"], "confirmed")
        self.assertGreaterEqual(int(finding["evidence_count"]), 1)
        self.assertGreaterEqual(int(result["summary"]["actionable_count"]), 1)

    def test_strict_vs_balanced_gate_behavior(self):
        balanced = self._verify(
            chat_query="Scan https://example.org",
            report_text="",
            tool_outputs=[{"name": "cloud_recon", "text": CLOUD_RECON_PUBLIC}],
            verification_policy="balanced",
            primary_target="https://example.org",
        )
        strict = self._verify(
            chat_query="Scan https://example.org",
            report_text="",
            tool_outputs=[{"name": "cloud_recon", "text": CLOUD_RECON_PUBLIC}],
            verification_policy="strict",
            primary_target="https://example.org",
        )
        self.assertGreater(int(balanced["summary"]["ready_count"]), int(strict["summary"]["ready_count"]))

    def test_profile_detection_ignores_payload_hosts(self):
        noisy_tool = """
        payload target: http://metadata.google.internal/computeMetadata/v1/
        reflected origin: https://evil.com
        dns clue: cloudflare.net
        """
        result = self._verify(
            chat_query="Scan https://smallsite.dev",
            report_text="",
            tool_outputs=[{"name": "exploit_target", "text": noisy_tool}],
            verification_policy="balanced",
            primary_target="https://smallsite.dev",
        )
        self.assertNotIn("Big Program", result["summary"]["profile"])

    def test_evidence_corpus_includes_tool_outputs_when_report_present(self):
        result = self._verify(
            chat_query="Scan https://example.org",
            report_text="No severe findings in narrative report.",
            tool_outputs=[{"name": "cloud_recon", "text": CLOUD_RECON_PUBLIC}],
            verification_policy="balanced",
            primary_target="https://example.org",
        )
        finding = next(f for f in result["findings"] if f["name"] == "Public Cloud Storage Exposure")
        self.assertEqual(finding["status"], "confirmed")
        self.assertGreaterEqual(int(finding["evidence_count"]), 1)

    def test_final_report_contains_both_gate_and_actionable_sections(self):
        truth_result = self._verify(
            chat_query="Scan https://example.org",
            report_text="",
            tool_outputs=[{"name": "cloud_recon", "text": CLOUD_RECON_PUBLIC}],
            verification_policy="balanced",
            primary_target="https://example.org",
        )
        report = server._build_gated_final_report(
            truth_result=truth_result,
            query="Scan https://example.org",
            mode="deep",
            events=[],
            extra_pass_used=False,
            session_meta={},
        )
        self.assertIn("### Exploit-Proven HIGH/CRITICAL (Evidence-Backed)", report)
        self.assertIn("### Actionable Evidence-Backed Findings", report)


if __name__ == "__main__":
    unittest.main()

