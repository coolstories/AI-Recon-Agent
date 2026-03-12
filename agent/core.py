import json
from agent.llm import chat_completion_stream
from agent.prompts import SYSTEM_PROMPT
from agent.intent import build_intent_system_message
from utils.display import (
    print_tool_call,
    print_tool_result,
    print_agent_message,
    print_error,
    print_info,
    print_step_header,
    create_thinking_stream,
    create_response_stream,
    console,
)
from tools.terminal import run_terminal, TOOL_DEFINITION as TERMINAL_TOOL
from tools.web_request import (
    make_web_request,
    check_ssl_cert,
    TOOL_DEFINITION_WEB,
    TOOL_DEFINITION_SSL,
)
from tools.search import search_web, TOOL_DEFINITION as SEARCH_TOOL
from tools.geocode import geocode_location, TOOL_DEFINITION as GEOCODE_TOOL
from tools.overpass import query_overpass, TOOL_DEFINITION as OVERPASS_TOOL
from tools.file_io import (
    read_file,
    write_file,
    TOOL_DEFINITION_READ,
    TOOL_DEFINITION_WRITE,
)
from tools.shodan_search import (
    shodan_host_lookup,
    shodan_search,
    TOOL_DEFINITION_HOST as SHODAN_HOST_TOOL,
    TOOL_DEFINITION_SEARCH as SHODAN_SEARCH_TOOL,
)
from tools.public_cams import (
    search_public_cams,
    TOOL_DEFINITION as PUBLIC_CAMS_TOOL,
)
from tools.live_cams import (
    search_live_webcams,
    TOOL_DEFINITION as LIVE_CAMS_TOOL,
)
from tools.cve_lookup import (
    lookup_cve,
    TOOL_DEFINITION as CVE_LOOKUP_TOOL,
)
from tools.vuln_check import (
    check_exposed_paths,
    TOOL_DEFINITION as VULN_CHECK_TOOL,
)
from tools.ffuf_scan import (
    run_ffuf,
    TOOL_DEFINITION as FFUF_TOOL,
)
from tools.nuclei_scan import (
    run_nuclei,
    TOOL_DEFINITION as NUCLEI_TOOL,
)
from tools.shodan_recon import (
    shodan_lookup,
    TOOL_DEFINITION as SHODAN_RECON_TOOL,
)
from tools.exploit import (
    exploit_target,
    TOOL_DEFINITION as EXPLOIT_TOOL,
)
from tools.telegram import (
    send_telegram,
    send_telegram_file,
    TOOL_DEFINITION_SEND as TELEGRAM_SEND_TOOL,
    TOOL_DEFINITION_FILE as TELEGRAM_FILE_TOOL,
)
from tools.port_scanner import port_scan, TOOL_DEFINITION as PORT_SCAN_TOOL
from tools.subdomain_enum import subdomain_enumerate, TOOL_DEFINITION as SUBDOMAIN_TOOL
from tools.param_miner import param_mine, TOOL_DEFINITION as PARAM_MINE_TOOL
from tools.cors_scanner import cors_scan, TOOL_DEFINITION as CORS_TOOL
from tools.header_audit import header_audit, TOOL_DEFINITION as HEADER_AUDIT_TOOL
from tools.js_analyzer import js_analyze, TOOL_DEFINITION as JS_ANALYZER_TOOL
from tools.cms_scanner import cms_scan, TOOL_DEFINITION as CMS_SCAN_TOOL
from tools.dns_recon import dns_recon, TOOL_DEFINITION as DNS_RECON_TOOL
from tools.waf_fingerprint import waf_fingerprint, TOOL_DEFINITION as WAF_TOOL
from tools.graphql_exploit import graphql_exploit, TOOL_DEFINITION as GRAPHQL_TOOL
from tools.cloud_recon import cloud_recon, TOOL_DEFINITION as CLOUD_RECON_TOOL
from tools.api_fuzzer import api_fuzz, TOOL_DEFINITION as API_FUZZ_TOOL
from tools.cache_poisoner import cache_poison, TOOL_DEFINITION as CACHE_POISON_TOOL
from tools.http_smuggler import http_smuggle, TOOL_DEFINITION as HTTP_SMUGGLE_TOOL
from tools.oauth_tester import oauth_test, TOOL_DEFINITION as OAUTH_TOOL
from tools.race_tester import race_test, TOOL_DEFINITION as RACE_TOOL
from tools.supply_chain import supply_chain_scan, TOOL_DEFINITION as SUPPLY_CHAIN_TOOL
from tools.trufflehog_scan import run_trufflehog, TOOL_DEFINITION as TRUFFLEHOG_TOOL
from tools.gitleaks_scan import run_gitleaks, TOOL_DEFINITION as GITLEAKS_TOOL
from tools.aquatone_scan import run_aquatone, TOOL_DEFINITION as AQUATONE_TOOL
from tools.testssl_scan import run_testssl, TOOL_DEFINITION as TESTSSL_TOOL
from tools.naabu_scan import run_naabu, TOOL_DEFINITION as NAABU_TOOL
from tools.waybackurls_scan import run_waybackurls, TOOL_DEFINITION as WAYBACKURLS_TOOL
from tools.arjun_scan import run_arjun, TOOL_DEFINITION as ARJUN_TOOL
from tools.wfuzz_scan import run_wfuzz, TOOL_DEFINITION as WFUZZ_TOOL
from tools.semgrep_scan import run_semgrep, TOOL_DEFINITION as SEMGREP_TOOL

ALL_TOOLS = [
    TERMINAL_TOOL,
    TOOL_DEFINITION_WEB,
    TOOL_DEFINITION_SSL,
    SEARCH_TOOL,
    GEOCODE_TOOL,
    OVERPASS_TOOL,
    TOOL_DEFINITION_READ,
    TOOL_DEFINITION_WRITE,
    SHODAN_HOST_TOOL,
    SHODAN_SEARCH_TOOL,
    PUBLIC_CAMS_TOOL,
    LIVE_CAMS_TOOL,
    CVE_LOOKUP_TOOL,
    VULN_CHECK_TOOL,
    FFUF_TOOL,
    NUCLEI_TOOL,
    SHODAN_RECON_TOOL,
    EXPLOIT_TOOL,
    TELEGRAM_SEND_TOOL,
    TELEGRAM_FILE_TOOL,
    PORT_SCAN_TOOL,
    SUBDOMAIN_TOOL,
    PARAM_MINE_TOOL,
    CORS_TOOL,
    HEADER_AUDIT_TOOL,
    JS_ANALYZER_TOOL,
    CMS_SCAN_TOOL,
    DNS_RECON_TOOL,
    WAF_TOOL,
    GRAPHQL_TOOL,
    CLOUD_RECON_TOOL,
    API_FUZZ_TOOL,
    CACHE_POISON_TOOL,
    HTTP_SMUGGLE_TOOL,
    OAUTH_TOOL,
    RACE_TOOL,
    SUPPLY_CHAIN_TOOL,
    TRUFFLEHOG_TOOL,
    GITLEAKS_TOOL,
    AQUATONE_TOOL,
    TESTSSL_TOOL,
    NAABU_TOOL,
    WAYBACKURLS_TOOL,
    ARJUN_TOOL,
    WFUZZ_TOOL,
    SEMGREP_TOOL,
]

TOOL_HANDLERS = {
    "run_terminal": lambda args: run_terminal(
        command=args["command"],
        timeout=args.get("timeout", 120),
    ),
    "web_request": lambda args: make_web_request(
        url=args["url"],
        method=args.get("method", "GET"),
    ),
    "check_ssl": lambda args: check_ssl_cert(
        hostname=args["hostname"],
    ),
    "search_web": lambda args: search_web(
        query=args["query"],
        max_results=args.get("max_results", 10),
    ),
    "geocode": lambda args: geocode_location(
        location=args["location"],
    ),
    "overpass_query": lambda args: query_overpass(
        lat=args["lat"],
        lon=args["lon"],
        radius=args.get("radius", 500),
    ),
    "read_file": lambda args: read_file(
        filepath=args["filepath"],
    ),
    "write_file": lambda args: write_file(
        filepath=args["filepath"],
        content=args["content"],
    ),
    "shodan_host": lambda args: shodan_host_lookup(
        ip=args["ip"],
    ),
    "shodan_search": lambda args: shodan_search(
        query=args["query"],
        max_results=args.get("max_results", 20),
    ),
    "search_public_cams": lambda args: search_public_cams(
        lat=args["lat"],
        lon=args["lon"],
        radius_km=args.get("radius_km", 10),
    ),
    "search_live_webcams": lambda args: search_live_webcams(
        location=args["location"],
        max_results=args.get("max_results", 15),
    ),
    "lookup_cve": lambda args: lookup_cve(
        software=args["software"],
        version=args["version"],
    ),
    "check_exposed_paths": lambda args: check_exposed_paths(
        base_url=args["base_url"],
    ),
    "run_ffuf": lambda args: run_ffuf(
        target_url=args["target_url"],
        mode=args.get("mode", "dir"),
        wordlist=args.get("wordlist", "common"),
        extensions=args.get("extensions", ""),
        threads=args.get("threads", 50),
        timeout=args.get("timeout", 120),
    ),
    "run_nuclei": lambda args: run_nuclei(
        target=args["target"],
        templates=args.get("templates", "auto"),
        severity=args.get("severity", "critical,high,medium"),
        timeout=args.get("timeout", 300),
        rate_limit=args.get("rate_limit", 150),
    ),
    "shodan_lookup": lambda args: shodan_lookup(
        target=args["target"],
        query_type=args.get("query_type", "host"),
    ),
    "exploit_target": lambda args: exploit_target(
        target=args["target"],
        exploit_type=args.get("exploit_type", "auto"),
        options=args.get("options", {}),
    ),
    "send_telegram": lambda args: send_telegram(
        message=args["message"],
        chat_id=args.get("chat_id", ""),
        parse_mode=args.get("parse_mode", "Markdown"),
    ),
    "send_telegram_file": lambda args: send_telegram_file(
        file_path=args["file_path"],
        caption=args.get("caption", ""),
    ),
    "port_scan": lambda args: port_scan(
        target=args["target"],
        scan_type=args.get("scan_type", "top100"),
        custom_ports=args.get("custom_ports", ""),
    ),
    "subdomain_enum": lambda args: subdomain_enumerate(
        target=args["target"],
        mode=args.get("mode", "passive"),
    ),
    "param_mine": lambda args: param_mine(
        target=args["target"],
        method=args.get("method", "GET"),
    ),
    "cors_scan": lambda args: cors_scan(target=args["target"]),
    "header_audit": lambda args: header_audit(target=args["target"]),
    "js_analyze": lambda args: js_analyze(target=args["target"]),
    "cms_scan": lambda args: cms_scan(target=args["target"]),
    "dns_recon": lambda args: dns_recon(target=args["target"]),
    "waf_fingerprint": lambda args: waf_fingerprint(target=args["target"]),
    "graphql_exploit": lambda args: graphql_exploit(target=args["target"]),
    "cloud_recon": lambda args: cloud_recon(target=args["target"]),
    "api_fuzz": lambda args: api_fuzz(target=args["target"], mode=args.get("mode", "full")),
    "cache_poison": lambda args: cache_poison(target=args["target"]),
    "http_smuggle": lambda args: http_smuggle(target=args["target"]),
    "oauth_test": lambda args: oauth_test(target=args["target"]),
    "race_test": lambda args: race_test(
        target=args["target"], endpoint=args.get("endpoint", ""),
        method=args.get("method", "POST"), payload=args.get("payload"),
        parallel=args.get("parallel", 15),
    ),
    "supply_chain_scan": lambda args: supply_chain_scan(target=args["target"]),
    "run_trufflehog": lambda args: run_trufflehog(
        path=args["path"],
        scan_mode=args.get("scan_mode", "filesystem"),
        timeout=args.get("timeout", 300),
    ),
    "run_gitleaks": lambda args: run_gitleaks(
        path=args["path"],
        timeout=args.get("timeout", 300),
    ),
    "run_aquatone": lambda args: run_aquatone(
        targets=args["targets"],
        timeout=args.get("timeout", 300),
    ),
    "run_testssl": lambda args: run_testssl(
        target=args["target"],
        mode=args.get("mode", "fast"),
        timeout=args.get("timeout", 420),
    ),
    "run_naabu": lambda args: run_naabu(
        target=args["target"],
        scan_type=args.get("scan_type", "top100"),
        rate=args.get("rate", 1000),
        timeout=args.get("timeout", 180),
    ),
    "run_waybackurls": lambda args: run_waybackurls(
        target=args["target"],
        timeout=args.get("timeout", 120),
    ),
    "run_arjun": lambda args: run_arjun(
        target_url=args["target_url"],
        method=args.get("method", "GET"),
        timeout=args.get("timeout", 240),
    ),
    "run_wfuzz": lambda args: run_wfuzz(
        target_url=args["target_url"],
        wordlist=args.get("wordlist", "common"),
        hide_codes=args.get("hide_codes", "404"),
        threads=args.get("threads", 20),
        timeout=args.get("timeout", 180),
    ),
    "run_semgrep": lambda args: run_semgrep(
        path=args["path"],
        config=args.get("config", "auto"),
        timeout=args.get("timeout", 600),
    ),
}

MAX_ITERATIONS = 50


class Agent:
    def __init__(self):
        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT}
        ]

    def reset(self):
        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT}
        ]

    def run(self, user_input: str) -> str:
        self.messages.append({"role": "system", "content": build_intent_system_message(user_input)})
        self.messages.append({"role": "user", "content": user_input})

        for iteration in range(MAX_ITERATIONS):
            print_step_header(iteration + 1, MAX_ITERATIONS)

            # Stream the LLM response
            thinking_stream = create_thinking_stream()
            has_tool_calls = False
            final_message = None

            try:
                for event in chat_completion_stream(self.messages, tools=ALL_TOOLS):
                    etype = event["type"]

                    if etype == "content_delta":
                        # Stream thinking text live
                        thinking_stream.write(event["text"])

                    elif etype == "tool_call_start":
                        # End any ongoing thinking stream
                        thinking_stream.end()
                        has_tool_calls = True
                        console.print(f"[bold yellow]⚡ Calling tool: [/bold yellow][yellow]{event['name']}[/yellow]")

                    elif etype == "tool_call_args_delta":
                        # We could stream args too but it's noisy; skip
                        pass

                    elif etype == "done":
                        thinking_stream.end()
                        final_message = event

            except Exception as e:
                thinking_stream.end()
                print_error(f"LLM API error: {str(e)}")
                return f"Error communicating with LLM: {str(e)}"

            if final_message is None:
                print_error("Stream ended without a final message.")
                return "Error: stream ended unexpectedly."

            full_content = final_message["content"]
            tool_calls = final_message["tool_calls"]

            # If the model wants to call tools
            if tool_calls:
                # Store assistant message with tool calls
                self.messages.append({
                    "role": "assistant",
                    "content": full_content or "",
                    "tool_calls": tool_calls,
                })

                # Execute each tool call
                for tc in tool_calls:
                    func_name = tc["function"]["name"]
                    raw_args = tc["function"]["arguments"]
                    try:
                        args = json.loads(raw_args)
                    except json.JSONDecodeError:
                        args = {}

                    # Display what tool is being called with args
                    args_summary = json.dumps(args, indent=None)[:200]
                    print_tool_call(func_name, args_summary)

                    # Execute the tool
                    handler = TOOL_HANDLERS.get(func_name)
                    if handler:
                        result = handler(args)
                    else:
                        result = f"ERROR: Unknown tool '{func_name}'"

                    # Display result
                    print_tool_result(result)

                    # Add tool result to messages
                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": result,
                    })

            # If no tool calls, this is the final response — stream it nicely
            else:
                final_text = full_content or "(No response from agent)"
                self.messages.append({
                    "role": "assistant",
                    "content": final_text,
                })
                # The text was already streamed live via thinking_stream,
                # now show the formatted final report
                print_agent_message(final_text)
                return final_text

        print_error("Agent reached maximum iterations without completing.")
        return "Agent reached maximum iterations. The task may be partially complete — check the output above."
