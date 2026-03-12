import unittest

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


if __name__ == "__main__":
    unittest.main()

