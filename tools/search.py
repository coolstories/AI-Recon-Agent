from ddgs import DDGS


def search_web(query: str, max_results: int = 10) -> str:
    """Search the web using DuckDuckGo and return results."""
    try:
        ddgs = DDGS()
        results = list(ddgs.text(query, max_results=max_results))

        if not results:
            return "No search results found."

        output = []
        for i, r in enumerate(results, 1):
            output.append(f"{i}. {r.get('title', 'No title')}")
            output.append(f"   URL: {r.get('href', 'N/A')}")
            output.append(f"   {r.get('body', 'No description')}")
            output.append("")

        return "\n".join(output)
    except Exception as e:
        return f"SEARCH ERROR: {str(e)}"


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "search_web",
        "description": "Search the internet using DuckDuckGo. Use this for OSINT research: finding CVEs, known vulnerabilities, data breaches, tech stack info, exposed credentials, etc.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The search query. Be specific, e.g. 'Apache 2.4.49 CVE vulnerabilities' or 'site:example.com exposed admin panel'"
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return. Default: 10",
                    "default": 10
                }
            },
            "required": ["query"]
        }
    }
}
