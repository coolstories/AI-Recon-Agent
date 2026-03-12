import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import aquatone_scan
from tools import arjun_scan
from tools import dns_recon
from tools import ffuf_scan
from tools import gitleaks_scan
from tools import naabu_scan
from tools import nuclei_scan
from tools import port_scanner
from tools import semgrep_scan
from tools import subdomain_enum
from tools import testssl_scan
from tools import trufflehog_scan
from tools import waybackurls_scan
from tools import web_request
from tools import wfuzz_scan
from tools import wpscan_scan


class WrapperBinaryResolutionTests(unittest.TestCase):
    def test_wrappers_propagate_missing_error_from_auto_installer(self):
        cases = [
            ("tools.arjun_scan.find_binary_or_auto_install", arjun_scan.run_arjun, {"target_url": "https://example.com"}),
            ("tools.wfuzz_scan.find_binary_or_auto_install", wfuzz_scan.run_wfuzz, {"target_url": "https://example.com/FUZZ"}),
            ("tools.waybackurls_scan.find_binary_or_auto_install", waybackurls_scan.run_waybackurls, {"target": "example.com"}),
            ("tools.semgrep_scan.find_binary_or_auto_install", semgrep_scan.run_semgrep, {"path": "."}),
            ("tools.trufflehog_scan.find_binary_or_auto_install", trufflehog_scan.run_trufflehog, {"path": "."}),
            ("tools.gitleaks_scan.find_binary_or_auto_install", gitleaks_scan.run_gitleaks, {"path": "."}),
            ("tools.aquatone_scan.find_binary_or_auto_install", aquatone_scan.run_aquatone, {"targets": "https://example.com"}),
        ]
        for patch_path, fn, kwargs in cases:
            with self.subTest(wrapper=patch_path):
                with patch(patch_path, return_value=(None, None, "ERROR: simulated missing binary")) as mocked:
                    out = fn(**kwargs)
                self.assertIn("ERROR: simulated missing binary", out)
                mocked.assert_called_once()

    def test_testssl_missing_binary_uses_python_fallback(self):
        with patch(
            "tools.testssl_scan.find_binary_or_auto_install",
            return_value=(None, None, "ERROR: missing testssl"),
        ), patch("tools.testssl_scan._python_tls_fallback", return_value="TLS_FALLBACK_OK"):
            out = testssl_scan.run_testssl("example.com", timeout=15)
        self.assertIn("COVERAGE DOWNGRADE", out)
        self.assertIn("ERROR: missing testssl", out)
        self.assertIn("TLS_FALLBACK_OK", out)

    def test_nuclei_missing_binary_runs_both_fallbacks(self):
        with patch(
            "tools.nuclei_scan.find_binary_or_auto_install",
            return_value=(None, None, "ERROR: missing nuclei"),
        ), patch("tools.testssl_scan.run_testssl", return_value="TLS_SCAN_FALLBACK"), patch(
            "tools.vuln_check.check_exposed_paths", return_value="EXPOSED_PATHS_FALLBACK"
        ):
            out = nuclei_scan.run_nuclei("https://example.com", timeout=20)
        self.assertIn("COVERAGE DOWNGRADE", out)
        self.assertIn("ERROR: missing nuclei", out)
        self.assertIn("TLS_SCAN_FALLBACK", out)
        self.assertIn("EXPOSED_PATHS_FALLBACK", out)

    def test_naabu_missing_binary_uses_internal_port_scan_fallback(self):
        with patch(
            "tools.naabu_scan.find_binary_or_auto_install",
            return_value=(None, None, "ERROR: missing naabu"),
        ), patch("tools.naabu_scan.port_scan", return_value="PORT_SCAN_FALLBACK_OK"):
            out = naabu_scan.run_naabu("https://example.com", timeout=20)
        self.assertIn("COVERAGE DOWNGRADE", out)
        self.assertIn("ERROR: missing naabu", out)
        self.assertIn("PORT_SCAN_FALLBACK_OK", out)

    def test_naabu_runtime_resource_limit_uses_internal_port_scan_fallback(self):
        with patch(
            "tools.naabu_scan.find_binary_or_auto_install",
            return_value=("naabu", "/usr/local/bin/naabu", ""),
        ), patch(
            "tools.naabu_scan.run_command",
            side_effect=OSError(11, "Resource temporarily unavailable"),
        ), patch("tools.naabu_scan.port_scan", return_value="PORT_SCAN_RESOURCE_FALLBACK_OK"):
            out = naabu_scan.run_naabu("https://example.com", timeout=20)
        self.assertIn("COVERAGE DOWNGRADE", out)
        self.assertIn("resource", out.lower())
        self.assertIn("PORT_SCAN_RESOURCE_FALLBACK_OK", out)

    def test_wpscan_missing_binary_runs_wordpress_fallback_assessment(self):
        with patch(
            "tools.wpscan_scan.find_binary_or_auto_install",
            return_value=(None, None, "ERROR: missing wpscan"),
        ), patch(
            "tools.wpscan_scan._wpscan_fallback_assessment",
            return_value="WPSCAN_FALLBACK_OK",
        ):
            out = wpscan_scan.run_wpscan("https://example.com", timeout=20)
        self.assertIn("COVERAGE DOWNGRADE", out)
        self.assertIn("ERROR: missing wpscan", out)
        self.assertIn("WPSCAN_FALLBACK_OK", out)

    def test_wpscan_exec_failure_without_report_runs_fallback(self):
        fake_result = {
            "stdout": "",
            "stderr": "runtime error",
            "exit_code": 1,
            "timed_out": False,
            "elapsed": 0.4,
            "command": "wpscan ...",
        }
        with patch(
            "tools.wpscan_scan.find_binary_or_auto_install",
            return_value=("wpscan", "/tmp/wpscan", ""),
        ), patch("tools.wpscan_scan.run_command", return_value=fake_result), patch(
            "tools.wpscan_scan._wpscan_fallback_assessment",
            return_value="WPSCAN_EXEC_FALLBACK_OK",
        ):
            out = wpscan_scan.run_wpscan("https://example.com", timeout=20)
        self.assertIn("COVERAGE DOWNGRADE", out)
        self.assertIn("WPSCAN_EXEC_FALLBACK_OK", out)


class FfufFallbackAndIsolationTests(unittest.TestCase):
    def test_ffuf_fallback_chain_reaches_internal_probe(self):
        with patch(
            "tools.ffuf_scan.find_binary_or_auto_install",
            return_value=(None, None, "ERROR: missing ffuf"),
        ), patch(
            "tools.wfuzz_scan.run_wfuzz",
            return_value="ERROR: Wfuzz binary not found on PATH. Tried: wfuzz.",
        ), patch(
            "tools.ffuf_scan._run_internal_http_fallback",
            return_value="=== Internal HTTP Path Fallback Scan ===\nNo interesting paths discovered.",
        ):
            out = ffuf_scan.run_ffuf("https://example.com", timeout=5)
        self.assertIn("internal http path fallback executed", out.lower())
        self.assertIn("ERROR: missing ffuf", out)

    def test_ffuf_does_not_read_legacy_shared_tmp_output(self):
        stale_tmp = Path("/tmp/ffuf_output.json")
        stale_payload = {
            "results": [
                {"status": 200, "length": 123, "url": "https://stale.example/admin"},
            ]
        }
        stale_tmp.write_text(json.dumps(stale_payload), encoding="utf-8")

        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_dir = Path(tmpdir)
            fake_result = {
                "stdout": "",
                "stderr": "",
                "exit_code": -9,
                "timed_out": True,
                "elapsed": 0.2,
                "command": "ffuf ...",
            }
            with patch("tools.ffuf_scan.create_artifact_dir", return_value=artifact_dir), patch(
                "tools.ffuf_scan.find_binary_or_auto_install",
                return_value=("ffuf", "/usr/local/bin/ffuf", ""),
            ), patch("tools.ffuf_scan.run_command", return_value=fake_result):
                out = ffuf_scan.run_ffuf("https://example.com", timeout=1)

        self.assertNotIn("stale.example", out)
        self.assertIn("Found 0 results", out)


class SSLRetryBehaviorTests(unittest.TestCase):
    def test_check_ssl_cert_normalizes_url_and_reports_retry_diagnostics(self):
        addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", 443)),
        ]
        with patch("tools.web_request.socket.getaddrinfo", return_value=addrinfo), patch(
            "tools.web_request.socket.create_connection", side_effect=socket.timeout("timed out")
        ):
            out = web_request.check_ssl_cert("https://example.com/login")
        self.assertIn("SSL CHECK ERROR", out)
        self.assertIn("host=example.com", out)
        self.assertIn("resolved_ips=2", out)
        self.assertIn("attempts=", out)


class ThreadExhaustionFallbackTests(unittest.TestCase):
    def test_dns_recon_thread_limit_falls_back_to_sequential(self):
        events = []

        def cb(event_type, data):
            events.append(str(data.get("message", "")))

        def fake_resolve(domain, rtype, timeout=5):
            if rtype == "A" and domain == "example.com":
                return ["93.184.216.34"]
            if rtype == "NS" and domain == "example.com":
                return ["ns1.example.com."]
            if rtype == "SRV" and domain == "_http._tcp.example.com":
                return ["0 5 80 example.com."]
            return []

        with patch("tools.dns_recon._resolve", side_effect=fake_resolve), patch(
            "tools.dns_recon._attempt_zone_transfer", return_value=None
        ), patch(
            "tools.dns_recon.ThreadPoolExecutor", side_effect=RuntimeError("can't start new thread")
        ):
            out = dns_recon.dns_recon("example.com", stream_callback=cb)

        self.assertIn("DNS RECONNAISSANCE for example.com", out)
        self.assertTrue(any("thread limit reached" in msg.lower() for msg in events))

    def test_subdomain_enum_thread_limit_falls_back_to_sequential(self):
        events = []

        def cb(event_type, data):
            events.append(str(data.get("message", "")))

        def fake_resolve(name, record_type="A"):
            if record_type == "A" and name in {"www.example.com", "api.example.com"}:
                return ["93.184.216.34"]
            return []

        def fake_get(url, *args, **kwargs):
            class Resp:
                def __init__(self, status_code=200, text=""):
                    self.status_code = status_code
                    self.text = text
                    self.headers = {}

                def json(self):
                    return []

            if "crt.sh" in url:
                return Resp(status_code=200, text="[]")
            return Resp(status_code=200, text="<title>OK</title>")

        with patch("tools.subdomain_enum.SUBDOMAIN_WORDLIST", ["www", "api"]), patch(
            "tools.subdomain_enum._resolve", side_effect=fake_resolve
        ), patch("tools.subdomain_enum.requests.get", side_effect=fake_get), patch(
            "tools.subdomain_enum.ThreadPoolExecutor", side_effect=RuntimeError("can't start new thread")
        ):
            out = subdomain_enum.subdomain_enumerate("example.com", mode="active", stream_callback=cb)

        self.assertIn("SUBDOMAIN ENUMERATION for example.com", out)
        self.assertIn("www.example.com", out)
        self.assertTrue(any("thread limit reached" in msg.lower() for msg in events))

    def test_port_scan_thread_limit_falls_back_to_sequential(self):
        events = []

        def cb(event_type, data):
            events.append(str(data.get("message", "")))

        with patch("tools.port_scanner.socket.gethostbyname", return_value="93.184.216.34"), patch(
            "tools.port_scanner._scan_port", side_effect=lambda host, port, timeout=2: port if port == 80 else None
        ), patch(
            "tools.port_scanner._grab_banner", return_value=("HTTP", "Server: nginx", "1.25.0")
        ), patch(
            "tools.port_scanner.ThreadPoolExecutor", side_effect=RuntimeError("can't start new thread")
        ):
            out = port_scanner.port_scan(
                "example.com",
                scan_type="custom",
                custom_ports="80,443",
                stream_callback=cb,
            )

        self.assertIn("PORT SCAN RESULTS", out)
        self.assertIn("PORT 80/tcp", out)
        self.assertTrue(any("thread limit reached" in msg.lower() for msg in events))


if __name__ == "__main__":
    unittest.main()
