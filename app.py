import os
import json
import re
import datetime
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st
from google import genai
from google.genai import types

# ============================================================
# 📡 Gemini 3 OSINT Investigation Engine (RAW -> Evidence-first)
# ============================================================
# מטרות:
# 1) Flash: אוסף OSINT גולמי עם URL בלבד, כולל חובה לחיפוש:
#    - X/Twitter (site:x.com + site:twitter.com)
#    - Telegram (site:t.me)
#    - Satellite imagery (מקורות ציבוריים)
#    - Public leak reporting (עיתונאות/דו"חות ציבוריים בלבד)
# 2) Pro: מנתח רק מתוך items_ranked (ללא המצאות), וכל שורה משמעותית
#    חייבת להכיל [#] + URL -> enforced by code + prompt.
# ============================================================

# ----------------------------
# Config
# ----------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
FLASH_MODEL = os.getenv("FLASH_MODEL", "gemini-3-flash-preview")
PRO_MODEL = os.getenv("PRO_MODEL", "gemini-3-pro-preview")

if not GEMINI_API_KEY:
    st.error("Missing GEMINI_API_KEY. Please set it in your environment.")
    st.stop()

client = genai.Client(api_key=GEMINI_API_KEY)

FACT_CHECK_SITES = [
    "FakeReporter.net",
    "Irrelevant.org.il",
    "TheWhistle (Globes)",
    "Snopes",
    "Bellingcat",
    "CheckYourFact",
    "FullFact.org",
    "Abu Ali Express",
]

# ----------------------------
# Helpers
# ----------------------------
def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()

def _clean_links(raw: str) -> List[str]:
    urls = re.findall(r"https?://[^\s)>\]]+", raw or "")
    out, seen = [], set()
    for u in urls:
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out[:100]

def _safe_json_loads(s: str) -> Dict[str, Any]:
    s = (s or "").strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s).strip()
    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            return obj
        return {"error": "JSON is not an object", "raw": s}
    except Exception:
        m = re.search(r"(\{.*\})", s, re.DOTALL)
        if m:
            try:
                obj = json.loads(m.group(1))
                if isinstance(obj, dict):
                    return obj
            except Exception:
                pass
        return {"error": "Failed to parse JSON (strict)", "raw": s}

def _extract_grounding_urls(resp: Any) -> List[str]:
    urls: List[str] = []
    try:
        if getattr(resp, "candidates", None):
            gm = resp.candidates[0].grounding_metadata
            if gm and getattr(gm, "grounding_chunks", None):
                for chunk in gm.grounding_chunks:
                    if getattr(chunk, "web", None) and getattr(chunk.web, "uri", None):
                        urls.append(chunk.web.uri)
    except Exception:
        pass
    return list(dict.fromkeys(urls))

_COORD_RE = re.compile(r"(-?\d{1,3}\.\d+)\s*,\s*(-?\d{1,3}\.\d+)")

def _strip_coordinates(text: str) -> str:
    if not text:
        return text
    return _COORD_RE.sub("[coord-redacted]", text)

def _domain(url: str) -> str:
    try:
        m = re.search(r"https?://([^/]+)/", url)
        return (m.group(1).lower() if m else "").strip()
    except Exception:
        return ""

def _normalize_platform(url: str, platform: Optional[str]) -> str:
    u = (url or "").lower()
    p = (platform or "").lower().strip()

    if p in {"x", "twitter"}:
        return "x"
    if p in {"telegram", "t.me"}:
        return "telegram"
    if p in {"official", "gov", "government"}:
        return "official"

    if "t.me/" in u:
        return "telegram"
    if "twitter.com/" in u or "x.com/" in u:
        return "x"

    # official heuristics
    dom = _domain(u)
    if dom.endswith(".gov") or dom in {"defense.gov", "whitehouse.gov", "omb.gov", "congress.gov"}:
        return "official"

    return "web"

def _guess_item_type(url: str, current: Optional[str]) -> str:
    if current in {"text", "image", "video", "document", "map"}:
        return current
    u = (url or "").lower()
    if any(u.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".webp", ".gif"]):
        return "image"
    if any(u.endswith(ext) for ext in [".mp4", ".mov", ".webm"]):
        return "video"
    if any(u.endswith(ext) for ext in [".pdf", ".doc", ".docx"]):
        return "document"
    return "text"

# דומיינים "חשודים" (לא חוסמים לחלוטין, אבל מענישים ניקוד + מסמנים)
SUSPECT_DOMAIN_HINTS = [
    "war.gov",  # דוגמה מהתוצאה אצלך - לא סטנדרטי
]

HIGH_TRUST_DOMAINS = {
    "defense.gov", "www.defense.gov",
    "whitehouse.gov", "www.whitehouse.gov",
    "omb.gov", "www.omb.gov",
    "congress.gov", "www.congress.gov",
    "gao.gov", "www.gao.gov",
    "nasa.gov", "www.nasa.gov",
    "earthdata.nasa.gov",
    "usgs.gov", "www.usgs.gov",
    "copernicus.eu", "www.copernicus.eu",
    "europa.eu", "commission.europa.eu",
    "sipri.org", "www.sipri.org",
    "reuters.com", "www.reuters.com",
    "apnews.com", "www.apnews.com",
    "bbc.co.uk", "www.bbc.co.uk", "bbc.com", "www.bbc.com",
    "ft.com", "www.ft.com",
}

def _sanitize_item(it: Dict[str, Any]) -> Dict[str, Any]:
    url = (it.get("url") or "").strip()
    platform = _normalize_platform(url, it.get("platform"))
    item_type = _guess_item_type(url, it.get("item_type"))

    raw_excerpt = _strip_coordinates((it.get("raw_excerpt") or "").strip())
    if len(raw_excerpt) > 320:
        raw_excerpt = raw_excerpt[:320].rstrip() + "…"

    media_urls = it.get("media_urls") or []
    if not isinstance(media_urls, list):
        media_urls = []
    media_urls = [str(u).strip() for u in media_urls if str(u).strip()][:10]

    tags = it.get("tags") or it.get("hard_signal_tags") or []
    if not isinstance(tags, list):
        tags = []
    tags = [str(t).strip() for t in tags if str(t).strip()]

    allowed = {
        "notam", "gps_jamming", "hospital", "reserve_callup", "air_defense", "movement", "evac_warning",
        "budget_official", "budget_media", "budget_factcheck", "macro_anchor", "claim_origin",
        "official_statement", "policy_doc",
        "satellite_imagery", "leak_report", "whistleblower_claim",
        "other",
    }
    tags = [t for t in tags if t in allowed]
    if not tags:
        tags = ["other"]

    loc_hints = it.get("location_hints") or []
    if not isinstance(loc_hints, list):
        loc_hints = []
    loc_hints = [_strip_coordinates(str(x).strip()) for x in loc_hints if str(x).strip()][:10]

    flags = it.get("credibility_flags") or {}
    if not isinstance(flags, dict):
        flags = {}

    def _to_bool_or_null(v):
        if v is True or v is False:
            return v
        return None

    flags_out = {
        "is_primary_source": _to_bool_or_null(flags.get("is_primary_source")),
        "has_original_media": _to_bool_or_null(flags.get("has_original_media")),
        "appears_repost": _to_bool_or_null(flags.get("appears_repost")),
    }

    published_time = it.get("published_time", None)
    if published_time is not None:
        published_time = str(published_time).strip()
        if published_time.lower() in {"", "none", "null"}:
            published_time = None

    author = it.get("author_or_channel", None)
    if author is not None:
        author = str(author).strip() or None

    dom = _domain(url)

    return {
        "platform": platform,
        "url": url,
        "domain": dom,
        "published_time": published_time,
        "author_or_channel": author,
        "item_type": item_type,
        "raw_excerpt": raw_excerpt,
        "media_urls": media_urls,
        "tags": tags,
        "location_hints": loc_hints,
        "credibility_flags": flags_out,
    }

def _dedupe_items(items: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    notes: List[str] = []
    seen_urls = set()
    seen_excerpt = set()
    out: List[Dict[str, Any]] = []
    for it in items:
        url = (it.get("url") or "").strip()
        if not url:
            continue
        if url in seen_urls:
            continue
        seen_urls.add(url)

        ex = (it.get("raw_excerpt") or "").strip().lower()
        ex_key = re.sub(r"\s+", " ", ex)[:220]
        if ex_key and ex_key in seen_excerpt:
            notes.append(f"Removed near-duplicate excerpt: {url}")
            continue
        if ex_key:
            seen_excerpt.add(ex_key)

        out.append(it)

    if len(out) < len(items):
        notes.insert(0, f"Deduped {len(items) - len(out)} items.")
    return out, notes

def _score_item_rulebased(it: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []

    plat = it.get("platform")
    dom = it.get("domain") or ""

    # Platform baseline
    if plat == "official":
        score += 42; reasons.append("Official +42")
    elif plat == "web":
        score += 18; reasons.append("Web +18")
    elif plat == "x":
        score += 10; reasons.append("X +10")
    elif plat == "telegram":
        score += 8; reasons.append("Telegram +8")
    else:
        score += 10; reasons.append("Other +10")

    # Domain trust tweaks
    if dom in HIGH_TRUST_DOMAINS or dom.endswith(".gov"):
        score += 12; reasons.append("High-trust domain +12")

    if any(bad in dom for bad in SUSPECT_DOMAIN_HINTS):
        score -= 25; reasons.append("Suspect domain -25")

    # Tag weights
    tags = set(it.get("tags") or [])
    tag_weights = {
        "budget_official": 22,
        "budget_factcheck": 18,
        "budget_media": 14,
        "macro_anchor": 14,
        "policy_doc": 16,
        "official_statement": 14,
        "claim_origin": 6,

        "notam": 18,
        "hospital": 16,
        "reserve_callup": 16,
        "gps_jamming": 14,
        "movement": 12,         # תזוזות צבא — נשאר
        "air_defense": 12,
        "evac_warning": 10,

        "satellite_imagery": 16,
        "leak_report": 14,
        "whistleblower_claim": 8,

        "other": 0,
    }
    tag_boost = sum(tag_weights.get(t, 0) for t in tags)
    if tag_boost:
        score += tag_boost
        reasons.append(f"Tags +{tag_boost} ({', '.join(sorted(tags))})")

    flags = it.get("credibility_flags") or {}
    if flags.get("is_primary_source") is True:
        score += 10; reasons.append("Primary +10")
    if flags.get("has_original_media") is True:
        score += 8; reasons.append("Original media +8")
    if flags.get("appears_repost") is True:
        score -= 10; reasons.append("Repost -10")

    if it.get("published_time"):
        score += 4; reasons.append("Has time +4")

    score = max(0, min(100, score))
    bucket = "High" if score >= 75 else ("Medium" if score >= 50 else "Low")

    out = dict(it)
    out["evidence_score"] = score
    out["evidence_bucket"] = bucket
    out["evidence_reasons"] = reasons[:8]
    return out

def _rank_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    scored = [_score_item_rulebased(it) for it in items]
    scored.sort(key=lambda x: (x.get("evidence_score", 0), x.get("published_time") or ""), reverse=True)
    return scored

def _count_tags(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for it in items:
        for t in it.get("tags") or []:
            counts[t] = counts.get(t, 0) + 1
    return counts

def classify_topic(user_text: str) -> str:
    t = (user_text or "").lower()
    finance_keywords = [
        "budget", "תקציב", "trillion", "טריליון", "billion", "מיליארד", "gdp", "תמ\"ג",
        "appropriation", "omb", "congress", "pentagon", "defense budget", "dod",
    ]
    conflict_keywords = [
        "war", "מלחמה", "attack", "תקיפה", "missile", "טילים", "iran", "איראן",
        "notam", "צו 8", "מילואים", "gps", "jamming", "satellite", "לוויין",
        "deployment", "movement", "air defense",
    ]
    f = any(k in t for k in finance_keywords)
    w = any(k in t for k in conflict_keywords)
    if f and not w:
        return "claim_finance"
    if w and not f:
        return "conflict"
    if f and w:
        return "mixed"
    return "general_claim"

# ----------------------------
# Flash: RAW collector with forced searches
# ----------------------------
def run_flash_deep_investigation(user_claim: str, user_links: List[str], images: List[bytes], topic: str) -> Dict[str, Any]:
    search_tool = types.Tool(google_search=types.GoogleSearch())
    today = datetime.datetime.now().strftime("%Y-%m-%d")

    forced_social = """
MANDATORY SOCIAL SEARCH (must run):
- X/Twitter:
  * site:x.com "<core keywords>"
  * site:twitter.com "<core keywords>"
- Telegram:
  * site:t.me "<core keywords>"
REQUIREMENT:
- If results exist, include at least 2 X items and 2 Telegram items in items[].
"""

    forced_satellite = """
MANDATORY SATELLITE/IMAGERY SEARCH (public only; must run):
- Search: "satellite imagery" + <core entity/location> + <date/window>
- Prefer public/credible sources & analyses:
  * NASA Earthdata / USGS / Copernicus (Sentinel/Landsat) + reputable OSINT analysis (e.g., Bellingcat)
REQUIREMENT:
- If any relevant public satellite/imagery analysis exists, include 1-2 items tagged satellite_imagery.
"""

    forced_leaks = """
MANDATORY "LEAKS" SEARCH (public reporting only; must run):
- Search: ("leaked" OR "whistleblower") + <core keywords>
- Prefer: Bellingcat / ICIJ / OCCRP / major outlets (Reuters/AP/BBC/FT/WSJ)
- DO NOT seek illegal repositories.
REQUIREMENT:
- If reputable public leak-reporting exists, include 1 item tagged leak_report or whistleblower_claim.
"""

    finance_pack = """
INVESTIGATION PACK (Finance / Budget Claims) - MUST TRY:
OFFICIAL:
1) site:defense.gov (budget request OR FY2026 OR fiscal year 2026) defense
2) site:whitehouse.gov budget defense FY
3) site:omb.gov budget defense
4) site:congress.gov (national defense authorization OR appropriations) FY2026
MEDIA:
5) Reuters US defense budget FY2026
6) AP Pentagon budget request FY2026
FACT CHECK:
7) site:snopes.com 4.3 trillion defense budget
8) FullFact OR CheckYourFact OR FakeReporter keywords
MACRO ANCHORS:
9) SIPRI global military spending total
10) US GDP defense spending percentage
"""

    conflict_pack = """
INVESTIGATION PACK (Conflict / Security Claims) - public only:
1) Official statements (gov/mil)
2) NOTAM / aviation authority notices
3) Public hospital readiness notices
4) Reuters / AP / BBC on the specific claim
5) Fact-check sources
6) GPS jamming reports (public)
7) Publicly reported deployments/movements (NO routes/coords)
"""

    general_pack = """
INVESTIGATION PACK (General Claim Verification):
- Official statements, credible media, fact-check, origin tracing on X/Telegram.
"""

    pack = general_pack
    if topic == "claim_finance":
        pack = finance_pack
    elif topic == "conflict":
        pack = conflict_pack
    elif topic == "mixed":
        pack = finance_pack + "\n" + conflict_pack

    prompt = f"""
You are an OSINT RAW COLLECTOR.
Date: {today}.
Mission: Investigate the user's claim deeply by collecting RAW evidence items with direct URLs only.

ABSOLUTE RULES:
- Output ONLY JSON. No prose.
- Every item MUST have a direct URL.
- raw_excerpt must be verbatim excerpt (short), no paraphrase.
- Do NOT invent any fact.
- No tactical intelligence: no coordinates, routes, targets. If coordinates appear, redact.
- Collect both supporting and refuting items.

{forced_social}
{forced_satellite}
{forced_leaks}

{pack}

USER CLAIM:
{user_claim}

USER PROVIDED LINKS:
{user_links}

OUTPUT SCHEMA (STRICT JSON):
{{
  "subject": "<short restatement of claim>",
  "topic": "{topic}",
  "collection_timestamp_utc": "{_utc_now_iso()}",
  "claim_decomposition": {{
    "key_entities": ["..."],
    "key_numbers": ["..."],
    "key_dates_or_timeframe": ["..."],
    "core_assertions": ["..."],
    "core_keywords_for_search": ["..."]
  }},
  "query_log": ["<at least 10 queries you ran>"],
  "items": [
    {{
      "platform": "x|telegram|web|official",
      "url": "<direct URL>",
      "published_time": "<ISO-8601 if known else null>",
      "author_or_channel": "<handle/channel/site if known else null>",
      "item_type": "text|image|video|document|map",
      "raw_excerpt": "<verbatim excerpt max 280 chars (redact coordinates)>",
      "media_urls": ["<url>", "..."],
      "tags": [
        "budget_official|budget_media|budget_factcheck|macro_anchor|claim_origin|official_statement|policy_doc|notam|gps_jamming|hospital|reserve_callup|air_defense|movement|evac_warning|satellite_imagery|leak_report|whistleblower_claim|other"
      ],
      "location_hints": ["<place names only>"],
      "credibility_flags": {{
        "is_primary_source": true|false|null,
        "has_original_media": true|false|null,
        "appears_repost": true|false|null
      }}
    }}
  ],
  "origin_trace": {{
    "earliest_found": {{
      "platform": "x|telegram|web|official|unknown",
      "url": "<url or null>",
      "notes": "<short note>"
    }},
    "spread_patterns": ["<short notes>"]
  }},
  "coverage_gaps": ["<what could not be found>"]
}}

COLLECTION TARGET:
- Aim for 15-25 items if possible.
- Try to include:
  * ≥2 X, ≥2 Telegram (if exist)
  * ≥2 official anchors (if topic finance -> MUST be .gov anchors if exist)
  * ≥1 fact-check (if exists)
  * ≥1 satellite_imagery (if exists)
  * ≥1 leak_report/whistleblower_claim (only if reputable public reporting exists)
"""

    parts = [types.Part(text=prompt)]
    for img in images[:8]:
        parts.append(types.Part(inline_data=types.Blob(mime_type="image/png", data=img)))

    config = types.GenerateContentConfig(
        tools=[search_tool],
        temperature=0.0,
        response_mime_type="application/json",
    )

    try:
        resp = client.models.generate_content(
            model=FLASH_MODEL,
            contents=[types.Content(role="user", parts=parts)],
            config=config,
        )
        pkg = _safe_json_loads(resp.text)
        pkg["verified_links"] = _extract_grounding_urls(resp)  # debug
        return pkg
    except Exception as e:
        return {"error": f"Flash Model Error: {str(e)}", "items": [], "verified_links": []}

# ----------------------------
# Enrich / Rank / Make Evidence Blocks
# ----------------------------
def enrich_and_rank_package(pkg: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(pkg)
    items = out.get("items", [])
    if not isinstance(items, list):
        items = []

    sanitized: List[Dict[str, Any]] = []
    for it in items:
        if isinstance(it, dict) and it.get("url"):
            sanitized.append(_sanitize_item(it))

    deduped, notes = _dedupe_items(sanitized)
    out["items"] = deduped[:220]
    out["dedupe_notes"] = notes[:80]

    ranked = _rank_items(out["items"])
    out["items_ranked"] = ranked[:120]
    out["tag_counts"] = _count_tags(out["items_ranked"])

    out["anchor_counts"] = {
        "official": sum(1 for it in out["items_ranked"] if it.get("platform") == "official"),
        "x": sum(1 for it in out["items_ranked"] if it.get("platform") == "x"),
        "telegram": sum(1 for it in out["items_ranked"] if it.get("platform") == "telegram"),
        "satellite": sum(1 for it in out["items_ranked"] if "satellite_imagery" in (it.get("tags") or [])),
        "leaks": sum(1 for it in out["items_ranked"] if ("leak_report" in (it.get("tags") or []) or "whistleblower_claim" in (it.get("tags") or []))),
        "suspect_domains": sum(1 for it in out["items_ranked"] if any(bad in (it.get("domain") or "") for bad in SUSPECT_DOMAIN_HINTS)),
    }
    return out

def build_evidence_blocks(items_ranked: List[Dict[str, Any]], limit: int = 20) -> str:
    """
    בונה "בלוקים" שה-Pro חייב להשתמש בהם. כל בלוק כולל [#] + URL + excerpt.
    זה מקטין סיכוי להמצאות ומכריח ציטוטים.
    """
    blocks = []
    for idx, it in enumerate(items_ranked[:limit], start=1):
       
