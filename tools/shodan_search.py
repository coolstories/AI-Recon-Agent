from __future__ import annotations

from tools.shodan_recon import shodan_lookup


def shodan_host_lookup(ip: str) -> str:
    """Compatibility wrapper: use Netlas-first host lookup under the legacy shodan_host tool name."""
    return shodan_lookup(ip, query_type="host")


def shodan_search(query: str, max_results: int = 20) -> str:
    """Compatibility wrapper: use Netlas-first search under the legacy shodan_search tool name."""
    return shodan_lookup(query, query_type="search", max_results=max_results)


TOOL_DEFINITION_HOST = {
    "type": "function",
    "function": {
        "name": "shodan_host",
        "description": (
            "Legacy passive recon host tool name with Netlas-first backend. "
            "Looks up a specific host/IP for ports, services, metadata, and IOC context. "
            "Uses NETLAS_API_KEY primarily; falls back to SHODAN_API_KEY only on Netlas auth/quota/plan-limit failures."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "IP address or host to inspect",
                }
            },
            "required": ["ip"],
        },
    },
}


TOOL_DEFINITION_SEARCH = {
    "type": "function",
    "function": {
        "name": "shodan_search",
        "description": (
            "Legacy passive recon search tool name with Netlas-first backend. "
            "Accepts Shodan-like query terms (city:, country:, org:, port:) and adapts them for Netlas search."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query. Example: webcam city:Tokyo",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Max results to return. Default: 20",
                    "default": 20,
                },
            },
            "required": ["query"],
        },
    },
}
