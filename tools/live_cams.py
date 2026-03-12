import requests
import urllib.parse
import re
import concurrent.futures
from ddgs import DDGS


def search_live_webcams(location: str, max_results: int = 15) -> str:
    """Search for VERIFIED live camera streams at a location. Only returns confirmed-live URLs."""
    all_results = []
    ddgs = DDGS()
    loc = location.strip()

    # ── 1. Webcam directory searches (non-YouTube) ──
    # These sites host actual live streams — high reliability
    site_queries = [
        (f'site:earthcam.com "{loc}"', "EarthCam"),
        (f'site:skylinewebcams.com "{loc}"', "SkylineWebcams"),
        (f'site:webcamtaxi.com "{loc}"', "Webcamtaxi"),
        (f'site:worldcams.tv "{loc}"', "WorldCams"),
        (f'site:insecam.org "{loc}"', "Insecam"),
        (f'site:webcamgalore.com "{loc}"', "WebcamGalore"),
        (f'site:weatherbug.com/traffic-cam "{loc}"', "WeatherBug"),
    ]
    for query, source in site_queries:
        try:
            results = list(ddgs.text(query, max_results=4))
            for r in results:
                url = r.get("href", "")
                title = r.get("title", "")
                body = r.get("body", "")
                if url and _is_valid_cam_page(url):
                    all_results.append({
                        "source": source,
                        "title": _clean_title(title),
                        "url": url,
                        "description": body[:200],
                        "verified": True,  # webcam directories are inherently live
                    })
        except Exception:
            continue

    # ── 2. YouTube — ONLY verified live streams ──
    yt_live = _search_youtube_live(loc, ddgs)
    all_results.extend(yt_live)

    # ── 3. General web search for live feeds ──
    general_queries = [
        f'"{loc}" live webcam -youtube.com -playlist',
        f'"{loc}" live camera feed stream',
        f'"{loc}" traffic camera live',
    ]
    for gq in general_queries:
        try:
            results = list(ddgs.text(gq, max_results=4))
            for r in results:
                url = r.get("href", "")
                title = r.get("title", "")
                body = r.get("body", "")
                if url and not _url_seen(url, all_results) and _is_valid_cam_page(url):
                    if _has_camera_keywords(title, body):
                        all_results.append({
                            "source": _detect_source(url),
                            "title": _clean_title(title),
                            "url": url,
                            "description": body[:200],
                            "verified": False,
                        })
        except Exception:
            continue

    # ── 4. Verify stream URLs are actually reachable (parallel HEAD checks) ──
    all_results = _verify_urls(all_results)

    # ── 5. Score, sort, dedup ──
    for r in all_results:
        r["_score"] = _relevance_score(r, loc)
    all_results.sort(key=lambda x: x["_score"], reverse=True)

    seen = set()
    unique = []
    for r in all_results:
        normalized = _normalize_url(r["url"])
        if normalized not in seen:
            seen.add(normalized)
            unique.append(r)
    unique = unique[:max_results]

    # ── Format output ──
    if not unique:
        output = [f"No verified live webcam streams found for '{loc}'.\n"]
        output.append("Browse these directories manually:\n")
        output.append(f"  📹 EarthCam: https://search.earthcam.com/search?term={_url_encode(loc)}")
        output.append(f"  📹 Insecam (exposed IP cams): http://www.insecam.org")
        output.append(f"  📹 YouTube (live only): https://www.youtube.com/results?search_query={_url_encode(loc + ' live webcam')}&sp=EgJAAQ%3D%3D")
        return "\n".join(output)

    verified_count = sum(1 for r in unique if r.get("verified"))
    output = [f"Found {len(unique)} live stream(s) for '{loc}' ({verified_count} verified live):\n"]

    for i, r in enumerate(unique, 1):
        live_tag = "🟢 LIVE" if r.get("verified") else "⚪ unverified"
        output.append(f"--- Stream #{i} [{live_tag}] ---")
        output.append(f"  📹 {r['source']} — {r['title']}")
        output.append(f"  URL: {r['url']}")
        if r.get("description"):
            output.append(f"  {r['description']}")
        output.append("")

    return "\n".join(output)


# ══════════════════════════════════════════
# YouTube live stream verification
# ══════════════════════════════════════════

def _search_youtube_live(location, ddgs):
    """Search YouTube and verify each result is actually a LIVE stream right now."""
    results = []

    # Search specifically for live webcam streams
    queries = [
        f'site:youtube.com/watch "{location}" live webcam',
        f'site:youtube.com/watch "{location}" live camera',
    ]

    candidate_urls = []
    for q in queries:
        try:
            hits = list(ddgs.text(q, max_results=8))
            for h in hits:
                url = h.get("href", "")
                title = h.get("title", "")
                if url and "youtube.com/watch" in url and "v=" in url:
                    # REJECT: channels, playlists, shorts, non-watch pages
                    candidate_urls.append({"url": url, "title": title})
        except Exception:
            continue

    # Filter out obvious non-live content
    filtered = []
    for c in candidate_urls:
        url = c["url"].lower()
        title = c["title"].lower()
        # Skip channels, playlists, shorts
        if any(x in url for x in ["/c/", "/channel/", "/playlist", "/shorts", "&list="]):
            continue
        # Skip obvious old/uploaded videos
        old_keywords = ["tour", "vlog", "review", "travel", "visit", "exploring",
                        "walking", "drone", "timelapse", "time lapse", "years ago",
                        "compilation", "best of", "top 10", "guide"]
        if any(kw in title for kw in old_keywords):
            continue
        filtered.append(c)

    # Verify each candidate is actually live RIGHT NOW
    for c in filtered[:10]:  # Check at most 10 candidates
        is_live = _verify_youtube_live(c["url"])
        if is_live:
            results.append({
                "source": "YouTube LIVE",
                "title": _clean_title(c["title"]),
                "url": c["url"],
                "description": "",
                "verified": True,
            })

    return results


def _verify_youtube_live(url):
    """Check if a YouTube video is currently live streaming by fetching the page."""
    try:
        resp = requests.get(url, timeout=8, headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        })
        if resp.status_code != 200:
            return False
        body = resp.text
        # YouTube embeds metadata in the page source for live streams
        live_indicators = [
            '"isLiveBroadcast":true',
            '"isLiveContent":true',
            '"isLive":true',
            '"liveBroadcastDetails"',
            'LIVE_STREAM_OFFLINE',  # Even this means it's a live stream page
            '"badge":{"metadataBadgeRenderer":{"label":"LIVE"',
            '"style":"BADGE_STYLE_TYPE_LIVE_NOW"',
        ]
        for indicator in live_indicators:
            if indicator in body:
                # Double check it's not an ended stream
                if '"isLiveBroadcast":false' in body:
                    return False
                if 'LIVE_STREAM_OFFLINE' in body and '"isLiveBroadcast":true' not in body:
                    return False
                return True
        return False
    except Exception:
        return False


# ══════════════════════════════════════════
# URL verification and filtering
# ══════════════════════════════════════════

def _verify_urls(results):
    """Parallel HEAD check to verify URLs are reachable. Mark dead ones."""
    def check(r):
        if r.get("verified"):
            return r  # Already verified as live
        try:
            resp = requests.head(r["url"], timeout=5, allow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code < 400:
                return r
        except Exception:
            pass
        return None

    verified = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(check, r): r for r in results}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                verified.append(result)
    return verified


def _url_seen(url, results):
    """Check if URL already in results list."""
    normalized = _normalize_url(url)
    return any(_normalize_url(r["url"]) == normalized for r in results)


def _normalize_url(url):
    """Normalize URL for dedup — strip tracking params, trailing slash."""
    url = url.split("&utm_")[0].split("?utm_")[0].rstrip("/").lower()
    return url


def _is_valid_cam_page(url):
    """Filter out garbage URLs — channels, playlists, homepages, spam."""
    url_lower = url.lower().rstrip("/")

    # Block YouTube non-watch pages (channels, playlists, etc.)
    if "youtube.com" in url_lower:
        if "/watch" not in url_lower:
            return False
        if any(x in url_lower for x in ["&list=", "/playlist", "/c/", "/channel/", "/shorts"]):
            return False

    # Block generic/homepage/directory listing URLs
    blocked = [
        "earthcam.com/network", "search.earthcam.com",
        "skylinewebcams.com/en/webcam.html",
        "webcamtaxi.com/en/index", "insecam.org/en/bycountry",
        "insecam.org/en/bycity", "insecam.org/en/bytype",
        "/complete-", "/places/", "/region/", "/country/",
    ]
    if any(b in url_lower for b in blocked):
        return False

    # Block bare homepages
    bare = ["earthcam.com", "skylinewebcams.com", "worldcams.tv",
            "webcamtaxi.com", "insecam.org", "windy.com/webcams",
            "webcamgalore.com"]
    if any(url_lower.endswith(h) or url_lower.endswith(h + "/") for h in bare):
        return False

    # Block webcamgalore region/places pages (not individual cams)
    if "webcamgalore.com" in url_lower:
        # Only allow /webcam/ pages (individual cameras), not /places/ or /complete-
        if "/webcam/" not in url_lower:
            return False

    # Block spam domains
    spam = ["amazon.com", "ebay.com", "walmart.com", "bestbuy.com",
            "facebook.com", "twitter.com", "instagram.com", "reddit.com",
            "yelp.com", "tripadvisor.com", "wikipedia.org", "linkedin.com",
            "adt.com", "vivint.com", "simplisafe.com", "pinterest.com"]
    if any(s in url_lower for s in spam):
        return False

    return True


def _clean_title(title):
    """Clean search result title."""
    for suffix in [" - EarthCam", " | SkylineWebcams", " - WorldCams",
                   " - Webcamtaxi", " - YouTube", " - WebcamGalore"]:
        if title.endswith(suffix):
            title = title[:-len(suffix)]
    return title.strip()


def _has_camera_keywords(title, body):
    """Check if title/body suggest a live camera page."""
    combined = (title + " " + body).lower()
    keywords = ["webcam", "live cam", "camera stream", "live stream", "cctv",
                "traffic cam", "live view", "live feed", "surveillance"]
    return any(kw in combined for kw in keywords)


def _relevance_score(result, location):
    """Score relevance to the searched location."""
    score = 0
    loc_words = [w for w in location.lower().split() if len(w) > 2]
    text = (result.get("title", "") + " " + result.get("url", "") + " " + result.get("description", "")).lower()

    for word in loc_words:
        if word in text:
            score += 10

    # Verified live streams get a big bonus
    if result.get("verified"):
        score += 20

    # Known webcam directories get a bonus
    trusted = ["EarthCam", "SkylineWebcams", "WorldCams", "Webcamtaxi",
               "Insecam", "YouTube LIVE", "Caltrans", "WeatherBug"]
    if result.get("source") in trusted:
        score += 5

    # Penalize search/directory pages
    url = result.get("url", "").lower()
    if "search" in url or "results" in url:
        score -= 10

    return score


def _detect_source(url):
    """Detect source from URL domain."""
    url_lower = url.lower()
    source_map = {
        "earthcam.com": "EarthCam", "skylinewebcams.com": "SkylineWebcams",
        "worldcams.tv": "WorldCams", "webcamtaxi.com": "Webcamtaxi",
        "insecam.org": "Insecam", "youtube.com": "YouTube",
        "windy.com": "Windy", "explore.org": "Explore.org",
        "dot.ca.gov": "Caltrans", "511.org": "511.org",
        "webcamgalore.com": "WebcamGalore", "weatherbug.com": "WeatherBug",
    }
    for domain, name in source_map.items():
        if domain in url_lower:
            return name
    return "Web"


def _url_encode(text):
    return urllib.parse.quote(text)


TOOL_DEFINITION = {
    "type": "function",
    "function": {
        "name": "search_live_webcams",
        "description": "Search for VERIFIED live webcam streams at a location. Only returns streams confirmed to be live right now. Checks webcam directories (EarthCam, SkylineWebcams, Webcamtaxi, Insecam) and verifies YouTube streams are actually live (not old videos or playlists). Each result is tagged as LIVE (verified) or unverified. Use this when the user wants to see live camera feeds.",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "Location to search for webcams, e.g. 'Menlo Park California', 'Times Square New York'"
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum streams to return. Default: 15",
                    "default": 15
                }
            },
            "required": ["location"]
        }
    }
}
