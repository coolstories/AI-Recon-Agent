import requests


def geocode_location(location: str) -> str:
    """Convert a location description to latitude/longitude using OpenStreetMap Nominatim."""
    try:
        resp = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params={
                "q": location,
                "format": "json",
                "limit": 3,
            },
            headers={"User-Agent": "AIReconAgent/1.0"},
            timeout=15,
        )
        resp.raise_for_status()
        results = resp.json()

        if not results:
            return f"No geocoding results found for '{location}'."

        output = []
        for r in results:
            output.append(f"Name: {r.get('display_name', 'N/A')}")
            output.append(f"Latitude: {r['lat']}")
            output.append(f"Longitude: {r['lon']}")
            output.append(f"Type: {r.get('type', 'N/A')}")
            output.append("")

        return "\n".join(output)
    except Exception as e:
        return f"GEOCODE ERROR: {str(e)}"


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "geocode",
        "description": "Convert a natural language location description into latitude/longitude coordinates using OpenStreetMap Nominatim. Use this before querying for nearby CCTV cameras.",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "A location description, e.g. 'Shibuya crossing, Tokyo' or 'Times Square, New York'"
                }
            },
            "required": ["location"]
        }
    }
}
