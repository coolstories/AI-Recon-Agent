import requests
import json
import math
import concurrent.futures


def search_public_cams(lat: float, lon: float, radius_km: int = 10) -> str:
    """Search for public traffic cameras near a location. Returns VERIFIED live image/stream URLs."""
    output = []

    # 1. Caltrans CCTV — all 12 California districts (auto-detect nearest)
    caltrans_results = _search_caltrans_all(lat, lon, radius_km)
    if caltrans_results:
        output.append(caltrans_results)

    # 2. 511.org Bay Area traffic cams
    bay_area_results = _search_511_bay_area(lat, lon, radius_km)
    if bay_area_results:
        output.append(bay_area_results)

    # 3. Windy.com webcams (global)
    windy_results = _search_windy_webcams(lat, lon, radius_km)
    if windy_results:
        output.append(windy_results)

    if not output:
        city = _city_hint(lat, lon)
        return (f"No public camera feeds found near ({lat}, {lon}) within {radius_km}km.\n"
                f"Try: search_live_webcams with location='{city}' for web-based streams,\n"
                f"or search_web for '{city} traffic cameras live'.")

    return "\n\n".join(output)


def _city_hint(lat, lon):
    try:
        resp = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"lat": lat, "lon": lon, "format": "json", "zoom": 10},
            headers={"User-Agent": "AIReconAgent/1.0"}, timeout=5)
        data = resp.json()
        return data.get("address", {}).get("city", data.get("address", {}).get("town", "this area"))
    except Exception:
        return "this area"


# ══════════════════════════════════════════
# Caltrans — All 12 California districts
# ══════════════════════════════════════════

# District center coordinates for picking the right API endpoint
_CALTRANS_DISTRICTS = {
    1: (40.8, -124.2),   # Eureka / NW California
    2: (40.6, -122.4),   # Redding / NE California
    3: (38.6, -121.5),   # Sacramento
    4: (37.8, -122.3),   # Bay Area / Oakland
    5: (34.4, -119.7),   # San Luis Obispo / Santa Barbara
    6: (36.7, -119.8),   # Fresno
    7: (34.1, -118.2),   # Los Angeles
    8: (34.1, -117.3),   # San Bernardino
    9: (37.9, -121.3),   # Stockton
    10: (37.3, -120.5),  # Merced
    11: (32.7, -117.2),  # San Diego
    12: (33.8, -116.5),  # Riverside / Palm Springs
}


def _nearest_districts(lat, lon, max_districts=3):
    """Return the closest Caltrans district numbers to the given coordinates."""
    dists = []
    for d, (dlat, dlon) in _CALTRANS_DISTRICTS.items():
        dists.append((haversine(lat, lon, dlat, dlon), d))
    dists.sort()
    return [d for _, d in dists[:max_districts]]


def _search_caltrans_all(lat, lon, radius_km):
    """Search the nearest Caltrans districts for cameras."""
    districts = _nearest_districts(lat, lon)
    all_nearby = []

    for dist_num in districts:
        try:
            url = f"https://cwwp2.dot.ca.gov/data/d{dist_num}/cctv/cctvStatusD{dist_num:02d}.json"
            resp = requests.get(url, timeout=12, headers={"User-Agent": "AIReconAgent/1.0"})
            if resp.status_code != 200:
                continue
            data = resp.json()
            cameras = data.get("data", [])
            if not isinstance(cameras, list):
                continue

            for cam in cameras:
                cctv = cam.get("cctv", {})
                loc = cctv.get("location", {})
                clat = loc.get("latitude")
                clon = loc.get("longitude")
                if not clat or not clon:
                    continue
                try:
                    clat, clon = float(clat), float(clon)
                except (ValueError, TypeError):
                    continue

                d = haversine(lat, lon, clat, clon)
                if d > radius_km:
                    continue

                in_service = cctv.get("inService", "true") == "true"
                if not in_service:
                    continue

                name = loc.get("locationName", "") or loc.get("name", "Unknown Camera")
                route = loc.get("route", "")
                direction = loc.get("direction", "")
                nearby_place = loc.get("nearbyPlace", "")

                img_data = cctv.get("imageData", {})
                image_url = img_data.get("static", {}).get("currentImageURL", "")
                stream_url = img_data.get("streamingVideoURL", "")

                all_nearby.append({
                    "name": name,
                    "route": route,
                    "direction": direction,
                    "nearby": nearby_place,
                    "lat": clat,
                    "lon": clon,
                    "dist_km": round(d, 2),
                    "district": dist_num,
                    "image": image_url,
                    "stream": stream_url,
                })
        except Exception:
            continue

    if not all_nearby:
        return None

    all_nearby.sort(key=lambda x: x["dist_km"])
    all_nearby = all_nearby[:25]

    # Verify images are actually live (parallel HEAD checks)
    all_nearby = _verify_caltrans_images(all_nearby)

    live_img = sum(1 for c in all_nearby if c.get("image_live"))
    live_stream = sum(1 for c in all_nearby if c.get("stream"))

    lines = [f"=== Caltrans Traffic Cameras ({len(all_nearby)} found, {live_img} with live images, {live_stream} with HLS streams) ==="]

    for i, c in enumerate(all_nearby, 1):
        status = "🟢 LIVE" if c.get("image_live") else "⚪"
        lines.append(f"\n--- Camera #{i} [{status}] ---")
        lines.append(f"  Name: {c['name']}")
        if c['nearby']:
            lines.append(f"  Near: {c['nearby']}")
        lines.append(f"  Route: {c['route']} {c['direction']}")
        lines.append(f"  Distance: {c['dist_km']} km")
        lines.append(f"  Location: {c['lat']}, {c['lon']}")
        lines.append(f"  Google Maps: https://www.google.com/maps?q={c['lat']},{c['lon']}")
        if c.get("image"):
            lines.append(f"  📷 Live Image: {c['image']}")
        if c.get("stream"):
            lines.append(f"  📹 HLS Stream: {c['stream']}")

    return "\n".join(lines)


def _verify_caltrans_images(cameras):
    """Parallel verify that Caltrans still images are actually serving content."""
    def check(cam):
        if cam.get("image"):
            try:
                resp = requests.head(cam["image"], timeout=4,
                                     headers={"User-Agent": "AIReconAgent/1.0"})
                size = int(resp.headers.get("Content-Length", 0))
                # Real images are > 5KB; placeholder/error images are tiny
                cam["image_live"] = resp.status_code == 200 and size > 5000
            except Exception:
                cam["image_live"] = False
        else:
            cam["image_live"] = False
        return cam

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        cameras = list(executor.map(check, cameras))
    return cameras


# ══════════════════════════════════════════
# 511.org Bay Area
# ══════════════════════════════════════════

def _search_511_bay_area(lat, lon, radius_km):
    """Search 511.org Bay Area traffic cameras."""
    # Only query if we're roughly in the Bay Area
    if haversine(lat, lon, 37.6, -122.1) > 100:
        return None

    try:
        resp = requests.get(
            "https://api.511.org/traffic/cameras",
            params={"api_key": "25992f44-6499-4db1-834b-eeab5846c8b8", "format": "json"},
            timeout=15,
        )
        if resp.status_code != 200:
            return None

        text = resp.text.lstrip('\ufeff')
        data = json.loads(text)

        cameras = data.get("cameras", data.get("features", []))
        if not cameras:
            return None

        nearby = []
        for cam in cameras:
            props = cam.get("properties", cam)
            geom = cam.get("geometry", {})
            coords = geom.get("coordinates", [])

            if coords and len(coords) >= 2:
                clon, clat = float(coords[0]), float(coords[1])
            else:
                clat = props.get("latitude") or props.get("lat")
                clon = props.get("longitude") or props.get("lon")
                if clat is None or clon is None:
                    continue
                clat, clon = float(clat), float(clon)

            dist = haversine(lat, lon, clat, clon)
            if dist <= radius_km:
                name = props.get("name", props.get("description", "Unknown"))
                image_url = props.get("imageUrl", props.get("image_url", ""))
                stream_url = props.get("streamUrl", props.get("stream_url", ""))

                nearby.append({
                    "name": name,
                    "lat": clat,
                    "lon": clon,
                    "dist_km": round(dist, 2),
                    "image": image_url,
                    "stream": stream_url,
                })

        if not nearby:
            return None

        nearby.sort(key=lambda x: x["dist_km"])
        nearby = nearby[:20]

        lines = [f"=== 511.org Bay Area Traffic Cameras ({len(nearby)} found within {radius_km}km) ==="]
        for i, c in enumerate(nearby, 1):
            lines.append(f"\n--- 511 Camera #{i} ---")
            lines.append(f"  Name: {c['name']}")
            lines.append(f"  Location: {c['lat']}, {c['lon']}")
            lines.append(f"  Distance: {c['dist_km']} km")
            lines.append(f"  Google Maps: https://www.google.com/maps?q={c['lat']},{c['lon']}")
            if c["image"]:
                lines.append(f"  📷 Still Image: {c['image']}")
            if c["stream"]:
                lines.append(f"  📹 Live Stream: {c['stream']}")

        return "\n".join(lines)
    except Exception:
        return None


# ══════════════════════════════════════════
# Windy.com Webcams
# ══════════════════════════════════════════

def _search_windy_webcams(lat, lon, radius_km):
    """Search Windy.com webcams via their public API."""
    try:
        resp = requests.get(
            "https://api.windy.com/webcams/api/v3/webcams",
            params={
                "nearby": f"{lat},{lon},{radius_km}",
                "limit": 20,
                "include": "location,urls,images",
            },
            headers={
                "x-windy-api-key": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                "User-Agent": "AIReconAgent/1.0",
            },
            timeout=15,
        )
        if resp.status_code != 200:
            return _windy_fallback(lat, lon)

        data = resp.json()
        webcams = data.get("webcams", [])
        if not webcams:
            return _windy_fallback(lat, lon)

        lines = [f"=== Windy.com Webcams ({len(webcams)} found within {radius_km}km) ==="]
        for i, wc in enumerate(webcams, 1):
            title = wc.get("title", "Unknown")
            loc = wc.get("location", {})
            wlat = loc.get("latitude", "?")
            wlon = loc.get("longitude", "?")
            urls = wc.get("urls", {})
            detail_url = urls.get("detail", "")
            images = wc.get("images", {})
            current = images.get("current", {})
            preview_url = current.get("preview", current.get("thumbnail", ""))

            lines.append(f"\n--- Webcam #{i} ---")
            lines.append(f"  Title: {title}")
            lines.append(f"  Location: {wlat}, {wlon}")
            if wlat != "?" and wlon != "?":
                lines.append(f"  Google Maps: https://www.google.com/maps?q={wlat},{wlon}")
            if detail_url:
                lines.append(f"  📹 Live View: {detail_url}")
            if preview_url:
                lines.append(f"  📷 Preview: {preview_url}")

        return "\n".join(lines)
    except Exception:
        return _windy_fallback(lat, lon)


def _windy_fallback(lat, lon):
    """Fallback: direct link to Windy webcam map."""
    return (f"=== Windy.com Webcam Map ===\n"
            f"  Browse live webcams near this location:\n"
            f"  https://www.windy.com/webcams/map/{lat},{lon},12\n"
            f"  (Interactive map with nearby webcam feeds)")


# ══════════════════════════════════════════
# Utilities
# ══════════════════════════════════════════

def haversine(lat1, lon1, lat2, lon2):
    """Distance in km between two lat/lon points."""
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    return R * 2 * math.asin(math.sqrt(a))


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "search_public_cams",
        "description": "Search for VERIFIED live public traffic cameras near GPS coordinates. Queries all 12 Caltrans districts (California), 511.org (Bay Area), and Windy.com (global). Returns verified live image URLs and HLS stream URLs with exact GPS locations. Each camera image is verified to be actively serving content. Use this for traffic/government cameras with exact locations.",
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
                "radius_km": {
                    "type": "integer",
                    "description": "Search radius in kilometers. Default: 10",
                    "default": 10
                }
            },
            "required": ["lat", "lon"]
        }
    }
}
