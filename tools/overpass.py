import requests


def query_overpass(lat: float, lon: float, radius: int = 500, query_type: str = "cctv") -> str:
    """Query OpenStreetMap Overpass API for surveillance cameras or other features near a location."""

    if query_type == "cctv":
        overpass_query = f"""
[out:json][timeout:30];
(
  node["man_made"="surveillance"](around:{radius},{lat},{lon});
  node["amenity"="cctv"](around:{radius},{lat},{lon});
  way["man_made"="surveillance"](around:{radius},{lat},{lon});
);
out body;
>;
out skel qt;
"""
    else:
        overpass_query = f"""
[out:json][timeout:30];
(
  node["{query_type}"](around:{radius},{lat},{lon});
);
out body;
>;
out skel qt;
"""

    try:
        resp = requests.post(
            "https://overpass-api.de/api/interpreter",
            data={"data": overpass_query},
            timeout=60,
            headers={"User-Agent": "AIReconAgent/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()

        elements = data.get("elements", [])
        if not elements:
            return f"No {query_type} features found within {radius}m of ({lat}, {lon}).\nThis means OpenStreetMap has no tagged surveillance/CCTV nodes in this area. This does NOT mean there are no cameras — only that none are mapped in OSM."

        output = []
        output.append(f"Found {len(elements)} {query_type} feature(s) within {radius}m of ({lat}, {lon}):\n")

        for i, elem in enumerate(elements, 1):
            osm_id = elem.get('id', 'N/A')
            osm_type = elem.get('type', 'node')  # node, way, or relation
            output.append(f"--- Camera #{i} ---")
            output.append(f"  OSM ID: {osm_id}")
            if 'lat' in elem and 'lon' in elem:
                output.append(f"  Location: {elem['lat']}, {elem['lon']}")
                output.append(f"  Google Maps: https://www.google.com/maps?q={elem['lat']},{elem['lon']}")
            # Verifiable OSM link — user can click to confirm this is real
            output.append(f"  OSM Link: https://www.openstreetmap.org/{osm_type}/{osm_id}")
            tags = elem.get("tags", {})
            if tags:
                for k, v in tags.items():
                    output.append(f"  {k}: {v}")
            output.append("")

        return "\n".join(output)
    except Exception as e:
        return f"OVERPASS ERROR: {str(e)}"


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "overpass_query",
        "description": "Query OpenStreetMap Overpass API to find real-world features near a location. Primarily used to find CCTV/surveillance cameras. Data comes from OpenStreetMap contributors — results are real mapped features, not estimates.",
        "parameters": {
            "type": "object",
            "properties": {
                "lat": {
                    "type": "number",
                    "description": "Latitude of the center point"
                },
                "lon": {
                    "type": "number",
                    "description": "Longitude of the center point"
                },
                "radius": {
                    "type": "integer",
                    "description": "Search radius in meters. Default: 500",
                    "default": 500
                }
            },
            "required": ["lat", "lon"]
        }
    }
}
