import os
import json
import re
import datetime
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st
from google import genai
from google.genai import types

# ============================================================
# 📡 Gemini 3 OSINT War Room (RAW Collector -> Analyst)
# ============================================================
# IMPORTANT SAFETY NOTE (built-in guardrails):
# - We allow collecting publicly available reports that mention "movement"/military activity,
#   but we do NOT allow turning this into actionable tracking (no coordinates, routes, targets).
# - The system enforces "evidence-first": NO claims without URLs.
# ============================================================

# ----------------------------
# Config & Client
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
# Utilities
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
    return out[:50]

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
    except json.JSONDecodeError:
        m = re.search(r"(\{.*\})", s, re.DOTALL)
        if m:
            try:
                obj = json.loads(m.group(1))
                if isinstance(obj, dict):
                    return obj
            except Exception:
                pass
        return {"error": "Failed to parse JSON", "raw": s}

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

_COORD_RE = re.compile(
    r"(-?\d{1,3}\.\d+)\s*,\s*(-?\d{1,3}\.\d+)"  # lat,lon
)

def _strip_coordinates(text: str) -> str:
    if not text:
        return text
    # remove coordinate-like patterns
    return _COORD_RE.sub("[coord-redacted]", text)

def _sanitize_item(it: Dict[str, Any]) -> Dict[str, Any]:
    url = (it.get("url") or "").strip()
    platform = _normalize_platform(url, it.get("platform"))
    item_type = _guess_item_type(url, it.get("item_type"))

    raw_excerpt = (it.get("raw_excerpt") or "").strip()
    raw_excerpt = _strip_coordinates(raw_excerpt)
    if len(raw_excerpt) > 320:
        raw_excerpt = raw_excerpt[:320].rstrip() + "…"

    media_urls = it.get("media_urls") or []
    if not isinstance(media_urls, list):
        media_urls = []
    media_urls = [str(u).strip() for u in media_urls if str(u).strip()][:10]

    tags = it.get("hard_signal_tags") or []
    if not isinstance(tags, list):
        tags = []
    tags = [str(t).strip() for t in tags if str(t).strip()]
    allowed = {
        "notam", "gps_jamming", "hospital", "reserve_callup",
        "air_defense", "movement", "evac_warning", "other"
    }
    tags = [t for t in tags if t in allowed]
    if not tags:
        tags = ["other"]

    loc_hints = it.get("location_hints") or []
    if not isinstance(loc_hints, list):
        loc_hints = []
    loc_hints = [ _strip_coordinates(str(x).strip()) for x in loc_hints if str(x).strip()][:10]

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
        "hard_signal_tags": tags,
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
    reasons = []

    plat = it.get("platform")
    if plat == "official":
        score += 35; reasons.append("Official baseline +35")
    elif plat == "web":
        score += 15; reasons.append("Web baseline +15")
    elif plat == "x":
        score += 10; reasons.append("X baseline +10")
    elif plat == "telegram":
        score += 8; reasons.append("Telegram baseline +8")
    else:
        score += 10; reasons.append("Other baseline +10")

    tags = set(it.get("hard_signal_tags") or [])
    hard_tag_weights = {
        "notam": 18,
        "hospital": 16,
        "reserve_callup": 16,
        "gps_jamming": 14,
        "movement": 12,
        "air_defense": 12,
        "evac_warning": 10,
        "other": 0,
    }
    tag_boost = sum(hard_tag_weights.get(t, 0) for t in tags)
    if tag_boost:
        score += tag_boost
        reasons.append(f"Hard-signal +{tag_boost} ({', '.join(sorted(tags))})")

    flags = it.get("credibility_flags") or {}
    if flags.get("has_original_media") is True:
        score += 12; reasons.append("Original media +12")
    elif (it.get("media_urls") or []):
        score += 8; reasons.append("Media URLs +8")

    if flags.get("is_primary_source") is True:
        score += 12; reasons.append("Primary +12")

    if flags.get("appears_repost") is True:
        score -= 12; reasons.append("Repost -12")

    if it.get("published_time"):
        score += 4; reasons.append("Has time +4")

    score = max(0, min(100, score))
    bucket = "High" if score >= 70 else ("Medium" if score >= 45 else "Low")

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
        for t in it.get("hard_signal_tags") or []:
            counts[t] = counts.get(t, 0) + 1
    return counts

def _has_enough_evidence(enriched_pkg: Dict[str, Any], min_items: int = 8) -> bool:
    ranked = enriched_pkg.get("items_ranked", []) or []
    return len(ranked) >= min_items

def _report_has_minimum_citations(report: str, min_urls: int = 8, min_item_refs: int = 6) -> bool:
    # Must include URLs + item references like [#3]
    url_count = len(re.findall(r"https?://", report or "", flags=re.IGNORECASE))
    ref_count = len(re.findall(r"#\d+", report or ""))
    return url_count >= min_urls and ref_count >= min_item_refs

# ----------------------------
# Step 1: Flash RAW OSINT Collection
# ----------------------------
def run_flash_raw_collection(user_news: str, links: List[str], images: List[bytes]) -> Dict[str, Any]:
    search_tool = types.Tool(google_search=types.GoogleSearch())
    current_date = datetime.datetime.now().strftime("%Y-%m-%d")

    # We allow collection of publicly reported "movement" signals,
    # but explicitly disallow turning into actionable tracking (coordinates/routes).
    prompt = f"""
You are an OSINT RAW COLLECTOR (not an analyst). Current Date: {current_date}.
Goal: collect PRIMARY and SECONDARY source items relevant to the user subject.
DO NOT summarize. DO NOT estimate likelihood. DO NOT draw conclusions.

SAFETY / NON-ACTIONABLE RULES:
- Do NOT provide exact coordinates, routes, targets, or actionable tactical guidance.
- If a source contains coordinates, redact them in raw_excerpt and location_hints.
- "movement" tag is allowed only as "publicly reported movement/activity", not tracking.

COLLECTION RULES:
- Output ONLY raw items you found via the search tool results (or provided links/images).
- Every claim must be attached to a URL.
- Prefer items with: official docs, NOTAMs, hospital notices, public warnings, statements, and public OSINT verification.
- Telegram: collect channel post URLs (t.me/<channel>/<msg_id>).
- Deduplicate: same URL only once.

SEARCH QUERIES (execute):
1) Twitter/X: site:twitter.com OR site:x.com + keywords from subject
2) Telegram: site:t.me + keywords from subject
3) Official/Public: Home Front Command / Ministry of Health / airports / NOTAM / gov statements
4) Hard indicators: "NOTAM", "airport closure", "hospital emergency protocol", "reserve call-up tzav 8", "GPS jamming", "Waze GPS spoofing"
5) Movement/activity (public): "deployment", "convoy", "air defense moved", "military activity" (PUBLIC claims only)

OUTPUT FORMAT: STRICT JSON ONLY.
Return this schema exactly:

{{
  "subject": "<repeat user subject briefly>",
  "collection_timestamp_utc": "<ISO-8601 UTC now>",
  "items": [
    {{
      "platform": "x|telegram|web|official",
      "url": "<direct URL>",
      "published_time": "<ISO-8601 if known else null>",
      "author_or_channel": "<handle/channel/site if known else null>",
      "item_type": "text|image|video|document|map",
      "raw_excerpt": "<max 280 chars verbatim excerpt (redact coordinates if present)>",
      "media_urls": ["<url>", "..."],
      "hard_signal_tags": ["notam|gps_jamming|hospital|reserve_callup|air_defense|movement|evac_warning|other"],
      "location_hints": ["<place names only, no coordinates>"],
      "credibility_flags": {{
        "is_primary_source": true|false|null,
        "has_original_media": true|false|null,
        "appears_repost": true|false|null
      }}
    }}
  ],
  "coverage_gaps": ["What you tried but could not find with sources"],
  "dedupe_notes": ["Brief notes about duplicates removed"]
}}

IMPORTANT:
- raw_excerpt must be copied from the source or tightly extracted; no paraphrase.
- If you cannot confirm published_time, set null.
- Minimum 8 items if available; otherwise return whatever exists.
"""

    parts = [
        types.Part(text=prompt),
        types.Part(text=f"Subject to Investigate: {user_news}\nLinks provided: {links}\nUTC now: {_utc_now_iso()}"),
    ]
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

        if not pkg.get("collection_timestamp_utc"):
            pkg["collection_timestamp_utc"] = _utc_now_iso()
        if not pkg.get("subject"):
            pkg["subject"] = (user_news or "").strip()[:200]

        items = pkg.get("items", [])
        if not isinstance(items, list):
            items = []

        sanitized: List[Dict[str, Any]] = []
        for it in items:
            if isinstance(it, dict) and it.get("url"):
                sanitized.append(_sanitize_item(it))

        deduped, notes = _dedupe_items(sanitized)
        pkg["items"] = deduped[:120]
        pkg["dedupe_notes"] = list(dict.fromkeys((pkg.get("dedupe_notes") or []) + notes))[:30]
        pkg["coverage_gaps"] = pkg.get("coverage_gaps") if isinstance(pkg.get("coverage_gaps"), list) else []
        pkg["verified_links"] = _extract_grounding_urls(resp)

        return pkg

    except Exception as e:
        return {"error": f"Flash Model Error: {str(e)}", "verified_links": [], "items": []}

# ----------------------------
# Step 1.5: Enrich + Rank (Deterministic)
# ----------------------------
def enrich_and_rank_package(pkg: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(pkg)
    items = out.get("items", [])
    if not isinstance(items, list):
        items = []
    ranked = _rank_items([it for it in items if isinstance(it, dict) and it.get("url")])
    out["items_ranked"] = ranked[:80]
    out["hard_signal_tag_counts"] = _count_tags(out["items_ranked"])
    return out

# ----------------------------
# Step 2: Pro Analysis (Evidence-first + ACH)
# ----------------------------
def run_pro_strategic_analysis(pkg: Dict[str, Any]) -> str:
    today = datetime.datetime.now().strftime("%Y-%m-%d")

    system_instruction = (
        "You are a Senior Intelligence Assessment Officer. "
        "Use Evidence-first reasoning and the 'Analysis of Competing Hypotheses' (ACH) method. "
        "Be cold, precise, and do not exaggerate."
    )

    # Keep Pro input tight and evidence-bound
    pro_input = {
        "subject": pkg.get("subject"),
        "collection_timestamp_utc": pkg.get("collection_timestamp_utc"),
        "hard_signal_tag_counts": pkg.get("hard_signal_tag_counts", {}),
        "items_ranked": (pkg.get("items_ranked", []) or [])[:45],
        "coverage_gaps": (pkg.get("coverage_gaps", []) or [])[:30],
        "verified_links": (pkg.get("verified_links", []) or [])[:40],
        "dedupe_notes": (pkg.get("dedupe_notes", []) or [])[:30],
    }

    user_prompt = f"""
HARD RULES (must comply):
1) You may ONLY make claims supported by the URLs inside items_ranked.
2) Every non-trivial claim MUST include:
   - an item reference like [#3] AND
   - the supporting URL on the same line.
3) If evidence is insufficient, you MUST say: "אין מספיק נתונים" and list what is missing.
4) You MUST NOT invent names, numbers, dates, operations, exercises, or units.
5) Today is {today}. Use this date consistently.

DATA PACKAGE (JSON):
{json.dumps(pro_input, ensure_ascii=False)}

OUTPUT (Hebrew, intelligence style, precise):

A) Evidence Table (Top 10):
Markdown table:
| # | פלטפורמה | תגיות Hard Signal | Evidence Score | מקור (URL) | Excerpt קצר | הערת אמינות |
- Each row must include URL.
- Excerpt must match raw_excerpt.

B) Hard Signals Status (only evidence-based):
For each:
- NOTAM/תעופה
- בתי חולים/בריאות
- צו 8/מילואים
- שיבושי GPS
- פעילות/תזוזות (publicly reported)
Write:
- "נמצא" / "לא נמצא"
- If "נמצא" must cite at least 1 item reference [#] and URL.

C) ACH:
Hypothesis A: Real escalation
Hypothesis B: PsyOps/noise
For each: supporting evidence + contradicting evidence, with [#] and URL.

D) Probability Matrix:
| טווח זמן | סבירות (%) | נימוק (Evidence Based) | רמת ביטחון |
Apply this rule:
If no logistic/operational hard signals are supported by URLs -> immediate probability must be LOW.

E) Bottom line (2–4 sentences), evidence-based, with at least 2 [#] references and URLs.
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
        return resp.text
    except Exception as e:
        return f"Pro Model Error: {str(e)}"

# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="Gemini 3 OSINT War Room", layout="wide", page_icon="📡")

st.markdown(
    """
<style>
  .stTextArea textarea { font-size: 16px !important; }
  .stAlert { direction: rtl; }
  .small { font-size: 13px; opacity: 0.85; }
</style>
""",
    unsafe_allow_html=True,
)

st.title("📡 Gemini 3 Advanced OSINT & War Predictor")
st.caption(f"Engine: {FLASH_MODEL} (RAW Collector) → {PRO_MODEL} (Analyst) | Evidence-first + ACH")

with st.sidebar:
    st.header("מערך איסוף")
    st.info("המערכת אוספת OSINT גולמי (RAW) ומכריחה ציטוטי URL לפני מסקנות.")
    st.divider()
    st.write("**מקורות אימות:**")
    st.write(FACT_CHECK_SITES)
    st.divider()
    st.write("**עיקרון:** בלי URL תומך — אין טענה.")

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("📝 הזנת מידע")
    user_text = st.text_area(
        "נושא החקירה (טקסט חופשי / שמועה):",
        height=200,
        placeholder="לדוגמה: שמועה על הודעת פקע״ר / שיבושי GPS / NOTAM / גיוס מילואים…",
    )
    user_links = st.text_area("קישורים ספציפיים (אופציונלי):", height=110)

with col2:
    st.subheader("📷 ראיות ויזואליות")
    uploaded = st.file_uploader(
        "העלה צילומי מסך/מפות:",
        type=["png", "jpg", "jpeg"],
        accept_multiple_files=True,
    )
    if uploaded:
        st.success(f"{len(uploaded)} קבצים נטענו לניתוח")

run_btn = st.button("🚀 הרץ הערכת מודיעין מלאה", type="primary", use_container_width=True)

if run_btn:
    if not user_text and not user_links.strip() and not uploaded:
        st.error("חובה להזין טקסט, או קישור, או להעלות תמונה.")
        st.stop()

    links = _clean_links(user_links)
    imgs = [f.read() for f in uploaded] if uploaded else []

    with st.status("מבצע איסוף RAW + ניתוח Evidence-first...", expanded=True) as status:
        st.write("📡 **Flash (RAW Collector):** איסוף פריטים עם URL בלבד + תיוג Hard Signals…")
        raw_pkg = run_flash_raw_collection(user_text, links, imgs)

        if "error" in raw_pkg and not raw_pkg.get("items"):
            status.update(label="שגיאה באיסוף", state="error")
            st.error(f"תקלה: {raw_pkg['error']}")
            st.stop()

        enriched_pkg = enrich_and_rank_package(raw_pkg)

        # UI: show counts (not True/False hacks)
        tag_counts = enriched_pkg.get("hard_signal_tag_counts", {}) or {}
        st.markdown(
            f"""
<div class="small">
<b>Items:</b> {len(enriched_pkg.get("items", []) or [])} |
<b>Ranked:</b> {len(enriched_pkg.get("items_ranked", []) or [])} |
<b>Hard Signal tag counts:</b> {tag_counts if tag_counts else "None"}
</div>
""",
            unsafe_allow_html=True,
        )

        # HARD STOP: not enough evidence -> do not allow “war probability”
        MIN_ITEMS_REQUIRED = 8
        if not _has_enough_evidence(enriched_pkg, MIN_ITEMS_REQUIRED):
            status.update(label="אין מספיק ראיות OSINT עם URL", state="error")
            st.error(
                "אין מספיק פריטי OSINT עם URL כדי לבצע הערכת הסתברות.\n\n"
                "כדי שזה יעבוד:\n"
                "- הדבק 3–10 קישורי X/Telegram ספציפיים, או\n"
                "- תן שמועה ספציפית (מה נטען + איפה + מתי), או\n"
                "- העלה סקרינשוטים."
            )
            with st.expander("⭐ items_ranked (מה כן נאסף)"):
                st.json((enriched_pkg.get("items_ranked", []) or [])[:25])
            st.stop()

        st.write("🧠 **Pro (Analyst):** Evidence Table + ACH + מטריצת סבירות (רק עם ציטוט URL)…")
        final_report = run_pro_strategic_analysis(enriched_pkg)

        # HARD BLOCK: report must contain URLs + item refs
        if not _report_has_minimum_citations(final_report, min_urls=8, min_item_refs=6):
            status.update(label="דו״ח נחסם: חסרים ציטוטים תומכים", state="error")
            st.error(
                "הדו״ח נחסם כי הוא לא עומד בכלל: "
                "כל טענה חייבת לכלול [#] + URL. "
                "זה מונע המצאות."
            )
            with st.expander("📄 דו״ח גולמי שהוחזר (לבדיקה)"):
                st.text(final_report)
            with st.expander("⭐ items_ranked"):
                st.json((enriched_pkg.get("items_ranked", []) or [])[:25])
            st.stop()

        status.update(label="הערכת המצב הושלמה", state="complete")

    st.divider()
    st.markdown("## 📊 דו\"ח מודיעין מסכם")
    st.markdown(final_report)

    with st.expander("🔍 OSINT גולמי (items)"):
        st.json({"subject": enriched_pkg.get("subject"), "items": enriched_pkg.get("items", [])[:80]})

    with st.expander("⭐ OSINT מדורג (items_ranked)"):
        st.json((enriched_pkg.get("items_ranked", []) or [])[:40])

    with st.expander("🔗 verified_links (grounding metadata)"):
        vlinks = enriched_pkg.get("verified_links", []) or []
        if not vlinks:
            st.write("לא נמצאו verified_links (יכול לקרות).")
        else:
            for link in vlinks[:60]:
                st.markdown(f"- [{link}]({link})")

    with st.expander("🕳️ Coverage Gaps"):
        gaps = enriched_pkg.get("coverage_gaps", []) or []
        if not gaps:
            st.write("לא דווחו פערי כיסוי.")
        else:
            for g in gaps[:40]:
                st.write(f"- {g}")

    with st.expander("🧹 Dedupe Notes"):
        dn = enriched_pkg.get("dedupe_notes", []) or []
        if not dn:
            st.write("אין.")
        else:
            for n in dn[:40]:
                st.write(f"- {n}")
