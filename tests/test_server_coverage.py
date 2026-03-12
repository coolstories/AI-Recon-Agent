import unittest
from unittest.mock import patch

import server


class ServerCoverageSignalTests(unittest.TestCase):
    def test_coverage_failure_parser_ignores_benign_parse_error_text(self):
        events = [
            {"type": "tool_call", "name": "run_terminal"},
            {
                "type": "tool_result",
                "name": "run_terminal",
                "result": (
                    "HTTP/2 200\n"
                    "content-type: text/xml\n"
                    "<faultString>parse error. not well formed</faultString>"
                ),
            },
            {"type": "tool_call", "name": "exploit_target"},
            {"type": "tool_result", "name": "exploit_target", "result": "ERROR: exploit module timeout"},
        ]

        summary = server._summarize_tool_coverage(events)
        self.assertEqual(summary["failed_result_count"], 1)
        self.assertIn("exploit_target", summary["failed_tools"])
        self.assertNotIn("run_terminal", summary["failed_tools"])

    def test_friendly_runtime_error_includes_llm_diagnostics_for_401(self):
        exc = Exception("Error code: 401 - {'error': {'message': 'User not found.', 'code': 401}}")
        with patch.object(server, "LLM_DEBUG_ERRORS", True), patch.dict(
            server.os.environ,
            {"OPENROUTER_API_KEY": "sk-test-debug-key-123", "OPENROUTER_MODEL": "openai/gpt-5.4"},
            clear=False,
        ):
            msg = server._friendly_runtime_error_message(exc)

        self.assertIn("LLM provider authentication failed", msg)
        self.assertIn("status_code=401", msg)
        self.assertIn("key_format=openai_or_other", msg)
        self.assertIn("model=openai/gpt-5.4", msg)
        self.assertIn("hint=", msg)
        self.assertNotIn("sk-test-debug-key-123", msg)

    def test_sanitize_tool_call_messages_keeps_complete_batches(self):
        msgs = [
            {"role": "system", "content": "s"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "dns_recon", "arguments": "{}"}},
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "ok"},
            {"role": "assistant", "content": "done"},
        ]
        sanitized, dropped = server._sanitize_tool_call_message_sequence(msgs)
        self.assertEqual(dropped, 0)
        self.assertEqual(sanitized, msgs)

    def test_sanitize_tool_call_messages_drops_incomplete_or_orphan_tool_messages(self):
        msgs = [
            {"role": "system", "content": "s"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "dns_recon", "arguments": "{}"}},
                    {"id": "call_2", "type": "function", "function": {"name": "port_scan", "arguments": "{}"}},
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "partial"},
            {"role": "assistant", "content": "next"},
            {"role": "tool", "tool_call_id": "orphan", "content": "bad"},
        ]
        sanitized, dropped = server._sanitize_tool_call_message_sequence(msgs)
        self.assertEqual(dropped, 2)
        self.assertEqual(sanitized, [
            {"role": "system", "content": "s"},
            {"role": "assistant", "content": "next"},
        ])


if __name__ == "__main__":
    unittest.main()
