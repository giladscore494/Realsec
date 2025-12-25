import os
import json
import re
import datetime
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st
from google import genai
from google.genai import types

# ============================================================
# 📡 Gemini 3 OSINT Investigation Engine (Evidence-first)
# ============================================================
# שינוי מרכזי בבקשה שלך:
# - Flash מחויב לחפש גם ב-X/Twitter וגם ב-Telegram (דרך site:x.com / site:twitter.com / site:t.me),
#   וגם לחפש "תמונות לוויין" ציבוריות + "הדלפות" ציבוריות (חקירה עיתונאית/דו"חות).
#
# חשוב:
# - אין כאן API רשמי ל-X/Telegram. האכיפה נעשית דרך Google Search עם site:...
# - "הדלפות" = רק תוכן ציבורי שפורסם ע"י כלי תקשורת/גופים מוכרים. לא חיפוש/שימוש בחומרים גנובים.
# - אין מודיעין טקטי/אופרטיבי: אין קואורדינטות, אין נתיבים, אין "איך לבצע".
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
    return out[:80]

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

def _normalize_platform(url: str, platform: Optional[str]) -> str:
    u = (url or "").lower()
    p = (platform or "").lower().strip()

    if p in {"x", "twitter"}:
        return "x"
    if p in {"telegram", "t.me"}:
        return "telegram"
    if p in {"official", "gov", "government"}:
        return "official"
    if p:
        return p

    if "t.me/" in u:
        return "telegram"
    if "twitter.com/" in u or "x.com/" in u:
        return "x"
    if any(dom in u for dom in ["whitehouse.gov", "defense.gov", "congress.gov", "omb.gov", "gao.gov"]):
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
        # conflict-ish / hard signals (public, non-actionable)
        "notam", "gps_jamming", "hospital", "reserve_callup", "air_defense", "movement", "evac_warning",
        # claim verification / finance anchors
        "budget_official", "budget_media", "budget_factcheck", "macro_anchor", "claim_origin",
        "official_statement", "policy_doc", "other",
        # new: satellite + leaks (public)
        "satellite_imagery", "leak_report", "whistleblower_claim",
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

    return {
        "platform": platform,
        "url": url,
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
            notes.append(f"Removed near-duplicate excerpt for URL: {url}")
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
    if plat == "official":
        score += 40; reasons.append("Official baseline +40")
    elif plat == "web":
        score += 18; reasons.append("Web baseline +18")
    elif plat == "x":
        score += 10; reasons.append("X baseline +10")
    elif plat == "telegram":
        score += 8; reasons.append("Telegram baseline +8")
    else:
        score += 10; reasons.append("Other baseline +10")

    tags = set(it.get("tags") or [])
    tag_weights = {
        # finance/verification
        "budget_official": 22,
        "budget_factcheck": 18,
        "budget_media": 14,
        "macro_anchor": 14,
        "policy_doc": 16,
        "official_statement": 14,
        "claim_origin": 6,

        # conflict-ish (public)
        "notam": 18,
        "hospital": 16,
        "reserve_callup": 16,
        "gps_jamming": 14,
        "movement": 12,
        "air_defense": 12,
        "evac_warning": 10,

        # new
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

def _report_has_minimum_citations(report: str, min_urls: int, min_item_refs: int) -> bool:
    url_count = len(re.findall(r"https?://", report or "", flags=re.IGNORECASE))
    ref_count = len(re.findall(r"#\d+", report or ""))
    return url_count >= min_urls and ref_count >= min_item_refs

# ----------------------------
# Topic classifier (lightweight)
# ----------------------------
def classify_topic(user_text: str) -> str:
    t = (user_text or "").lower()
    finance_keywords = [
        "budget", "תקציב", "trillion", "טריליון", "billion", "מיליארד", "gdp", "תמ\"ג",
        "appropriation", "omb", "congress", "pentagon", "defense budget"
    ]
    conflict_keywords = [
        "war", "מלחמה", "attack", "תקיפה", "missile", "טילים", "iran", "איראן",
        "notam", "צו 8", "מילואים", "gps", "jamming", "פיקוד העורף", "satellite", "לוויין"
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
# Step 1: Flash - Deep RAW Investigator (with forced social/sat/leaks)
# ----------------------------
def run_flash_deep_investigation(user_claim: str, user_links: List[str], images: List[bytes], topic: str) -> Dict[str, Any]:
    search_tool = types.Tool(google_search=types.GoogleSearch())
    today = datetime.datetime.now().strftime("%Y-%m-%d")

    # Forced cross-domain query packs (social + satellite + leaks)
    forced_social = """
MANDATORY SOCIAL SEARCH (must run):
- X/Twitter:
  * site:x.com "<core keywords>"  (also try Hebrew/Russian variants)
  * site:twitter.com "<core keywords>"
- Telegram:
  * site:t.me "<core keywords>"  (also try Hebrew/Russian variants)
- Output requirement:
  * If any relevant results exist, include at least 2 X items and 2 Telegram items in items[].
"""

    forced_satellite = """
MANDATORY SATELLITE/IMAGERY SEARCH (public only; must run):
- Try: "satellite imagery" + <core location/entity> + <date/window>
- Prefer public/credible imagery sources & analyses:
  * site:earthdata.nasa.gov
  * site:usgs.gov
  * site:copernicus.eu
  * Sentinel / Landsat references
  * Credible OSINT analysis pages/articles (e.g., Bellingcat) that cite imagery
- Output requirement:
  * If any relevant satellite/imagery analysis exists, include at least 1-2 items tagged satellite_imagery.
"""

    forced_leaks = """
MANDATORY "LEAKS" SEARCH (public reporting only; must run):
- Look for PUBLIC investigative reporting referencing leaked documents/whistleblowers:
  * "leaked" OR "whistleblower" + <core keywords>
  * site:bellingcat.com
  * site:icij.org
  * site:occrp.org
  * major outlets (Reuters/AP/FT/WSJ/BBC etc.)
- DO NOT seek stolen/illegal material repositories.
- Output requirement:
  * If any reputable public leak-reporting exists, include 1 item tagged leak_report or whistleblower_claim.
"""

    finance_pack = """
INVESTIGATION PACK (Finance / Budget Claims):
- Official anchors (must try):
  1) site:defense.gov budget request FY
  2) site:whitehouse.gov budget defense FY
  3) site:omb.gov budget defense
  4) site:congress.gov defense appropriation FY
- Credible media anchors:
  5) Reuters US defense budget
  6) AP Pentagon budget request
- Fact-check:
  7) site:snopes.com <claim keywords>
  8) FullFact / CheckYourFact / FakeReporter <claim keywords>
- Macro anchors:
  9) US GDP latest estimate
  10) SIPRI global military spending total latest
"""

    conflict_pack = """
INVESTIGATION PACK (Conflict / Security Claims):
- Official/public anchors (must try):
  1) Official statements (gov/mil) relevant to claim
  2) NOTAM / aviation authority notices (public)
  3) Public health/hospital notices (public only)
- Credible media anchors:
  4) Reuters / AP / BBC / major outlets on the specific claim
- Fact-check:
  5) FakeReporter/Irrelevant/Snopes/FullFact keywords
- Hard indicators (public only; non-actionable):
  6) GPS jamming reports (public articles)
  7) Reserve call-up reports (public)
  8) Hospital readiness (public)
  9) Publicly reported movement/deployment (NO coordinates/routes)
"""

    general_pack = """
INVESTIGATION PACK (General Claim Verification):
- Try official statements, credible media, and fact-check sources.
- Try origin tracing on Telegram and X.
- Collect at least 12 items if possible.
"""

    pack = general_pack
    if topic == "claim_finance":
        pack = finance_pack
    elif topic == "conflict":
        pack = conflict_pack
    elif topic == "mixed":
        pack = finance_pack + "\n" + conflict_pack

    prompt = f"""
You are an OSINT INVESTIGATOR (RAW COLLECTOR, not an analyst).
Date: {today}.
Mission: Investigate the user's claim deeply by collecting evidence items with URLs,
cross-checking official anchors, credible media, fact-checkers, and tracing the claim's origin.

ABSOLUTE RULES:
- Output ONLY JSON. No prose.
- Every item MUST have a direct URL.
- raw_excerpt must be copied from the source (tight excerpt), no paraphrase.
- Do NOT invent numbers, names, or context.
- Do NOT provide actionable tactical intelligence:
  no coordinates, no routes, no targets. If a source has coordinates, redact them.
- Collect BOTH supporting and refuting evidence.
- You MUST run the mandatory search blocks below.

{forced_social}
{forced_satellite}
{forced_leaks}

{pack}

USER CLAIM:
{user_claim}

USER-PROVIDED LINKS (if any):
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
    "core_keywords_for_search": ["..."]   // must include 6-12 keywords/phrases to reuse in social searches
  }},
  "query_log": [
    "<list the key queries you actually ran (at least 10)>"
  ],
  "items": [
    {{
      "platform": "x|telegram|web|official",
      "url": "<direct URL>",
      "published_time": "<ISO-8601 if known else null>",
      "author_or_channel": "<handle/channel/site if known else null>",
      "item_type": "text|image|video|document|map",
      "raw_excerpt": "<max 280 chars verbatim excerpt (redact coordinates)>",
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
  "coverage_gaps": ["<what could not be found>"],
  "dedupe_notes": []
}}

COLLECTION TARGETS:
- Aim for 15-25 items if possible.
- If results exist, try to include:
  * ≥2 X items, ≥2 Telegram items
  * ≥1-2 satellite_imagery items
  * ≥1 leak_report/whistleblower_claim item (only if from reputable public reporting)
  * ≥2 official anchors, ≥2 credible media, ≥1 fact-check (if exists)
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
        pkg["verified_links"] = _extract_grounding_urls(resp)  # debug-only
        return pkg
    except Exception as e:
        return {"error": f"Flash Model Error: {str(e)}", "items": [], "verified_links": []}

# ----------------------------
# Step 1.5: Enrich + Rank (Deterministic)
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
    out["items"] = deduped[:180]
    out["dedupe_notes"] = list(dict.fromkeys((out.get("dedupe_notes") or []) + notes))[:60]

    ranked = _rank_items(out["items"])
    out["items_ranked"] = ranked[:90]
    out["tag_counts"] = _count_tags(out["items_ranked"])

    out["anchor_counts"] = {
        "official": sum(1 for it in out["items_ranked"] if it.get("platform") == "official"),
        "x": sum(1 for it in out["items_ranked"] if it.get("platform") == "x"),
        "telegram": sum(1 for it in out["items_ranked"] if it.get("platform") == "telegram"),
        "satellite": sum(1 for it in out["items_ranked"] if "satellite_imagery" in (it.get("tags") or [])),
        "leaks": sum(1 for it in out["items_ranked"] if ("leak_report" in (it.get("tags") or []) or "whistleblower_claim" in (it.get("tags") or []))),
    }
    return out

# ----------------------------
# Step 2: Pro - Evidence-first Analysis
# ----------------------------
def run_pro_analysis(enriched_pkg: Dict[str, Any], mode: str) -> str:
    today = datetime.datetime.now().strftime("%Y-%m-%d")

    system_instruction = (
        "You are a Senior Analyst. Evidence-first. "
        "You MUST NOT invent facts. You MUST cite [#] + URL for every non-trivial claim."
    )

    pro_input = {
        "subject": enriched_pkg.get("subject"),
        "topic": enriched_pkg.get("topic"),
        "collection_timestamp_utc": enriched_pkg.get("collection_timestamp_utc"),
        "claim_decomposition": enriched_pkg.get("claim_decomposition", {}),
        "query_log": enriched_pkg.get("query_log", []),
        "tag_counts": enriched_pkg.get("tag_counts", {}),
        "anchor_counts": enriched_pkg.get("anchor_counts", {}),
        "origin_trace": enriched_pkg.get("origin_trace", {}),
        "coverage_gaps": enriched_pkg.get("coverage_gaps", []),
        "items_ranked": (enriched_pkg.get("items_ranked", []) or [])[:50],
    }

    if mode == "PARTIAL":
        mode_rules = """
MODE=PARTIAL:
- Do NOT output numeric probabilities.
- Keep cautious: supported / refuted / unknown.
- Verdict must be one of: "נכון חלקית", "לא מאומת", "מטעה", "ככל הנראה כוזב".
"""
        min_urls, min_refs = 6, 5
    else:
        mode_rules = """
MODE=FULL:
- You may provide verdict + confidence (Low/Medium/High) but not invented numbers.
- Prefer anchoring to official/fact-check/media first, then social, then satellite/leaks.
"""
        min_urls, min_refs = 9, 7

    user_prompt = f"""
Date: {today}

HARD RULES:
1) Every claim must cite [#] + URL (same line).
2) No URL => write "לא ידוע / אין ראיה".
3) Do NOT invent names, numbers, dates, operations, exercises, or events.
4) If evidence is conflicting, show both sides with citations.
5) Social posts (X/Telegram) are not authoritative. Treat as "claims" unless corroborated.
6) Satellite/leaks items must be treated cautiously; only if from credible public reporting/analysis.

{mode_rules}

DATA PACKAGE (JSON):
{json.dumps(pro_input, ensure_ascii=False)}

OUTPUT FORMAT (Hebrew, precise):

1) Evidence Table (Top 12):
| # | פלטפורמה | תגיות | Score | מקור (URL) | Excerpt |

2) Cross-source Triangulation:
- Official anchors: what they say.
- Credible media: what they say.
- Fact-check: what they say.
- Social (X/Telegram): what is being claimed, and whether corroborated.
- Satellite/leaks (if present): what they add (with strict caution).
Each bullet must cite [#] + URL.

3) Origin Trace:
- Earliest found / likely origin with [#] + URL, else "לא ידוע".

4) Verdict + Confidence:
- Verdict: one of ["נכון", "נכון חלקית", "מטעה", "ככל הנראה כוזב", "לא מאומת"]
- Confidence: Low/Medium/High
- 2-4 lines with citations.

5) Missing Evidence:
- Practical list: what links/docs would close gaps.
"""

    try:
        resp = client.models.generate_content(
            model=PRO_MODEL,
            contents=[types.Content(role="user", parts=[types.Part(text=user_prompt)])],
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.2,
            ),
        )
        report = resp.text or ""
        if not _report_has_minimum_citations(report, min_urls=min_urls, min_item_refs=min_refs):
            return (
                "❌ הדו\"ח נחסם: אין מספיק ציטוטים [#] + URL.\n\n"
                "זה מונע המצאות. בדוק items_ranked/coverage_gaps ונסה שוב."
            )
        return report
    except Exception as e:
        return f"Pro Model Error: {str(e)}"

# ----------------------------
# Decide mode (based on evidence + required sources)
# ----------------------------
def decide_mode(enriched_pkg: Dict[str, Any]) -> str:
    ranked = enriched_pkg.get("items_ranked", []) or []
    anchors = enriched_pkg.get("anchor_counts", {}) or {}

    # FULL requires enough evidence + at least some social coverage if exists
    if len(ranked) >= 16 and anchors.get("official", 0) >= 2 and anchors.get("x", 0) >= 1 and anchors.get("telegram", 0) >= 1:
        return "FULL"
    if len(ranked) >= 7:
        return "PARTIAL"
    return "NO_EVIDENCE"

# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="Gemini 3 OSINT Investigation Engine", layout="wide", page_icon="📡")

st.markdown(
    """
<style>
  .stTextArea textarea { font-size: 16px !important; }
  .small { font-size: 13px; opacity: 0.85; }
</style>
""",
    unsafe_allow_html=True,
)

st.title("📡 Gemini 3 OSINT Investigation Engine")
st.caption(f"Engine: {FLASH_MODEL} (RAW Investigator) → {PRO_MODEL} (Evidence-first Analyst)")

with st.sidebar:
    st.header("מערך איסוף")
    st.info(
        "המערכת מחויבת לחפש גם ב-X/Twitter וגם ב-Telegram (דרך Google site:), "
        "ולנסות לאתר גם אנליזות/מקורות על תמונות לוויין ציבוריות + דיווחי הדלפות ציבוריים (חקירה עיתונאית)."
    )
    st.divider()
    st.write("**מקורות אימות:**")
    st.write(FACT_CHECK_SITES)
    st.divider()
    st.write("כלל ברזל: בלי URL תומך — אין טענה.")

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("📝 טענה / שמועה לבדיקה")
    user_text = st.text_area(
        "הדבק טענה אחת (קישורים אופציונלי):",
        height=240,
        placeholder="לדוגמה: 'ארה\"ב העלתה תקציב ביטחון ל-4.3 טריליון' או 'יש הכנות חריגות בזירה X'...",
    )
    user_links_raw = st.text_area("קישורים ספציפיים (אופציונלי):", height=120)

with col2:
    st.subheader("📷 ראיות (אופציונלי)")
    uploaded = st.file_uploader(
        "העלה סקרינשוטים/תמונות (אופציונלי):",
        type=["png", "jpg", "jpeg"],
        accept_multiple_files=True,
    )
    if uploaded:
        st.success(f"{len(uploaded)} קבצים נטענו")

run_btn = st.button("🚀 חקור ונתח", type="primary", use_container_width=True)

if run_btn:
    if not user_text and not user_links_raw.strip() and not uploaded:
        st.error("חובה להזין טענה או קישור או להעלות תמונה.")
        st.stop()

    links = _clean_links(user_links_raw)
    imgs = [f.read() for f in uploaded] if uploaded else []

    topic = classify_topic(user_text)

    with st.status("מבצע חקירה OSINT (RAW) + הצלבות...", expanded=True) as status:
        st.write(f"📡 **Flash:** חיפוש חובה ב-X/Telegram + לוויין + הדלפות ציבוריות (topic={topic})…")
        raw_pkg = run_flash_deep_investigation(user_text, links, imgs, topic)

        if raw_pkg.get("error"):
            status.update(label="שגיאה באיסוף", state="error")
            st.error(raw_pkg["error"])
            st.stop()

        enriched = enrich_and_rank_package(raw_pkg)
        mode = decide_mode(enriched)

        ranked = enriched.get("items_ranked", []) or []
        tag_counts = enriched.get("tag_counts", {}) or {}
        anchor_counts = enriched.get("anchor_counts", {}) or {}

        st.markdown(
            f"""
<div class="small">
<b>Mode:</b> {mode} |
<b>items_ranked:</b> {len(ranked)} |
<b>anchors:</b> {anchor_counts} |
<b>tag_counts:</b> {tag_counts if tag_counts else "None"}
</div>
""",
            unsafe_allow_html=True,
        )

        if mode == "NO_EVIDENCE":
            status.update(label="אין מספיק ראיות עם URL", state="error")
            st.error(
                "אין מספיק פריטי ראיות עם URL כדי להפיק ניתוח אמין.\n\n"
                "מה לעשות:\n"
                "- לחדד ניסוח (שנה/מספר/שם גוף/שם מסמך)\n"
                "- או להוסיף 1–3 קישורים\n"
                "- או להעלות סקרינשוט"
            )
            with st.expander("⭐ items_ranked (מה כן נאסף)"):
                st.json(ranked[:30])
            with st.expander("🕳️ coverage_gaps"):
                st.write(enriched.get("coverage_gaps", []))
            st.stop()

        st.write("🧠 **Pro:** ניתוח Evidence-first עם ציטוטים [#] + URL לכל טענה…")
        report = run_pro_analysis(enriched, mode=mode)

        status.update(label="החקירה הושלמה", state="complete")

    st.divider()
    st.markdown("## 📊 דו\"ח אימות טענה (Evidence-first)")
    st.markdown(report)

    with st.expander("⭐ items_ranked (Top 50)"):
        st.json(ranked[:50])

    with st.expander("🔍 RAW items (Top 120)"):
        st.json((enriched.get("items") or [])[:120])

    with st.expander("🧩 claim_decomposition"):
        st.json(enriched.get("claim_decomposition", {}))

    with st.expander("🧪 query_log"):
        st.json(enriched.get("query_log", []))

    with st.expander("🧭 origin_trace"):
        st.json(enriched.get("origin_trace", {}))

    with st.expander("🕳️ coverage_gaps"):
        st.json(enriched.get("coverage_gaps", []))

    with st.expander("🧪 verified_links (debug only)"):
        st.json(enriched.get("verified_links", []))
```0
