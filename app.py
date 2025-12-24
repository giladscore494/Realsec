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
# - Flash: RAW OSINT collection ONLY (no conclusions)
# - Pro: Evidence-first scoring + ACH
# ============================================================

# ----------------------------
# Config & Client
# ----------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

FLASH_MODEL = os.getenv("FLASH_MODEL", "gemini-3-flash-preview")
PRO_MODEL   = os.getenv("PRO_MODEL",   "gemini-3-pro-preview")

if not GEMINI_API_KEY:
    st.error("Missing GEMINI_API_KEY. Please set it in your environment.")
    st.stop()

client = genai.Client(api_key=GEMINI_API_KEY)

# Sources you present to user (UI only)
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
        # try to recover object-like blob
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
    # unique preserve order
    return list(dict.fromkeys(urls))

def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()

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

def _dedupe_items(items: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    notes: List[str] = []
    seen_urls = set()
    seen_excerpt_hash = set()
    out: List[Dict[str, Any]] = []

    for it in items:
        url = (it.get("url") or "").strip()
        if not url:
            continue

        # URL dedupe
        if url in seen_urls:
            continue
        seen_urls.add(url)

        # excerpt dedupe (light)
        ex = (it.get("raw_excerpt") or "").strip().lower()
        ex_key = re.sub(r"\s+", " ", ex)[:200]
        if ex_key and ex_key in seen_excerpt_hash:
            notes.append(f"Removed near-duplicate excerpt for URL: {url}")
            continue
        if ex_key:
            seen_excerpt_hash.add(ex_key)

        out.append(it)

    if len(out) < len(items):
        notes.insert(0, f"Deduped {len(items) - len(out)} items.")
    return out, notes

def _sanitize_item(it: Dict[str, Any]) -> Dict[str, Any]:
    # Enforce schema & safe defaults
    url = (it.get("url") or "").strip()
    platform = _normalize_platform(url, it.get("platform"))
    item_type = _guess_item_type(url, it.get("item_type"))

    # raw_excerpt: keep short, no paraphrase enforcement here (model instruction handles)
    raw_excerpt = (it.get("raw_excerpt") or "").strip()
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
    # normalize known tags only + allow "other"
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
    loc_hints = [str(x).strip() for x in loc_hints if str(x).strip()][:10]

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

def _score_item_rulebased(it: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic evidence score (0-100) for prioritization (NOT truth).
    """
    score = 0
    reasons = []

    # Platform baseline
    plat = it.get("platform")
    if plat == "official":
        score += 35; reasons.append("Official platform baseline +35")
    elif plat == "web":
        score += 15; reasons.append("Web baseline +15")
    elif plat == "x":
        score += 10; reasons.append("X baseline +10")
    elif plat == "telegram":
        score += 8; reasons.append("Telegram baseline +8")
    else:
        score += 10; reasons.append("Unknown platform baseline +10")

    # Hard signal tags
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
        reasons.append(f"Hard-signal tags +{tag_boost} ({', '.join(sorted(tags))})")

    # Media
    flags = it.get("credibility_flags") or {}
    if flags.get("has_original_media") is True:
        score += 12; reasons.append("Has original media +12")
    elif (it.get("media_urls") or []):
        score += 8; reasons.append("Has media URLs +8")

    # Primary source flag
    if flags.get("is_primary_source") is True:
        score += 12; reasons.append("Marked primary source +12")

    # Repost penalty
    if flags.get("appears_repost") is True:
        score -= 12; reasons.append("Appears repost -12")

    # Published time existence (not accuracy)
    if it.get("published_time"):
        score += 4; reasons.append("Has published_time +4")

    # cap
    score = max(0, min(100, score))

    # Confidence bucket from score (just prioritization)
    if score >= 70:
        bucket = "High"
    elif score >= 45:
        bucket = "Medium"
    else:
        bucket = "Low"

    out = dict(it)
    out["evidence_score"] = score
    out["evidence_bucket"] = bucket
    out["evidence_reasons"] = reasons[:8]
    return out

def _rank_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    scored = [_score_item_rulebased(it) for it in items]
    scored.sort(key=lambda x: (x.get("evidence_score", 0), x.get("published_time") or ""), reverse=True)
    return scored

# ----------------------------
# Step 1: Source Discovery (Flash Model - RAW OSINT ONLY)
# ----------------------------
def run_flash_raw_collection(user_news: str, links: List[str], images: List[bytes]) -> Dict[str, Any]:
    search_tool = types.Tool(google_search=types.GoogleSearch())
    current_date = datetime.datetime.now().strftime("%Y-%m-%d")

    prompt = f"""
You are an OSINT RAW COLLECTOR (not an analyst). Current Date: {current_date}.
Goal: collect PRIMARY and SECONDARY source items relevant to the user subject.
DO NOT summarize the event. DO NOT estimate likelihood. DO NOT draw conclusions.

COLLECTION RULES:
- Output ONLY raw items you found via the search tool results (or provided links/images).
- Every claim must be attached to a URL.
- Prefer items with: original media, official docs, NOTAMs, hospital notices, gov statements, geolocation cues.
- Telegram: collect channel post URLs (t.me/<channel>/<msg_id>).
- Deduplicate: same URL appears only once; same text repeats -> keep earliest source you can identify.

SEARCH QUERIES (execute):
1) Twitter/X signals: site:twitter.com OR site:x.com + keywords from subject
2) Telegram signals: site:t.me + keywords from subject
3) Official: IDF / Home Front Command / PMO / Ministry of Health / airports / NOTAM
4) Hard indicators: "NOTAM", "airport closure", "hospital underground", "reserve call-up tzav 8", "GPS jamming", "Waze GPS spoofing Israel"

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
      "raw_excerpt": "<max 280 chars verbatim excerpt>",
      "media_urls": ["<url>", "..."],
      "hard_signal_tags": ["notam|gps_jamming|hospital|reserve_callup|air_defense|movement|evac_warning|other"],
      "location_hints": ["<place names / coordinates if present>"],
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
- Minimum 6 items if available; otherwise return whatever exists.
"""

    parts = [
        types.Part(text=prompt),
        types.Part(text=f"Subject to Investigate: {user_news}\nLinks provided: {links}\nUTC now: {_utc_now_iso()}"),
    ]

    for img in images[:8]:
        # Assume png; if you want strict mime detection, add it later
        parts.append(types.Part(inline_data=types.Blob(mime_type="image/png", data=img)))

    config = types.GenerateContentConfig(
        tools=[search_tool],
        temperature=0.0,  # hard facts mode
        response_mime_type="application/json",
    )

    try:
        resp = client.models.generate_content(
            model=FLASH_MODEL,
            contents=[types.Content(role="user", parts=parts)],
            config=config,
        )
        pkg = _safe_json_loads(resp.text)

        # Force timestamp if missing
        if not pkg.get("collection_timestamp_utc"):
            pkg["collection_timestamp_utc"] = _utc_now_iso()

        # Ensure items list
        items = pkg.get("items", [])
        if not isinstance(items, list):
            items = []

        # Sanitize + require URL
        sanitized = []
        for it in items:
            if isinstance(it, dict) and it.get("url"):
                sanitized.append(_sanitize_item(it))

        # Dedupe
        deduped, notes = _dedupe_items(sanitized)
        pkg["items"] = deduped[:80]
        pkg["dedupe_notes"] = list(dict.fromkeys((pkg.get("dedupe_notes") or []) + notes))[:20]

        # Add verified links from grounding metadata (if any)
        pkg["verified_links"] = _extract_grounding_urls(resp)

        # If model didn't put subject, set it
        if not pkg.get("subject"):
            pkg["subject"] = (user_news or "").strip()[:200]

        # If coverage_gaps missing
        if "coverage_gaps" not in pkg or not isinstance(pkg.get("coverage_gaps"), list):
            pkg["coverage_gaps"] = []

        return pkg

    except Exception as e:
        return {"error": f"Flash Model Error: {str(e)}", "verified_links": [], "items": []}

# ----------------------------
# Step 1.5: Local Ranking (Deterministic) for Pro input
# ----------------------------
def enrich_and_rank_package(pkg: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(pkg)
    items = out.get("items", [])
    if not isinstance(items, list):
        items = []
    ranked = _rank_items([it for it in items if isinstance(it, dict) and it.get("url")])
    out["items_ranked"] = ranked[:60]

    # quick counts (for UI)
    tag_counts: Dict[str, int] = {}
    for it in ranked:
        for t in it.get("hard_signal_tags") or []:
            tag_counts[t] = tag_counts.get(t, 0) + 1
    out["hard_signal_tag_counts"] = tag_counts

    return out

# ----------------------------
# Step 2: Strategic Analysis (Pro Model - Evidence-first + ACH)
# ----------------------------
def run_pro_strategic_analysis(pkg: Dict[str, Any]) -> str:
    system_instruction = (
        "You are a Senior Intelligence Assessment Officer. "
        "Use Evidence-first reasoning and the 'Analysis of Competing Hypotheses' (ACH) method. "
        "Be cold, precise, and do not exaggerate."
    )

    # Feed ranked items only (reduce noise + token cost)
    pro_input = {
        "subject": pkg.get("subject"),
        "collection_timestamp_utc": pkg.get("collection_timestamp_utc"),
        "hard_signal_tag_counts": pkg.get("hard_signal_tag_counts", {}),
        "items_ranked": pkg.get("items_ranked", [])[:40],
        "coverage_gaps": pkg.get("coverage_gaps", []),
        "verified_links": pkg.get("verified_links", [])[:30],
        "dedupe_notes": pkg.get("dedupe_notes", [])[:20],
    }

    user_prompt = f"""
נתח את ה-Data Package הבא והפק דו"ח הערכת מצב.
התבסס אך ורק על המידע שנאסף (קישורים/פריטים). אל תמציא.

DATA PACKAGE (JSON):
{json.dumps(pro_input, ensure_ascii=False)}

חובה לבצע:
א) "Evidence Table" — טבלת Markdown עם 10 הפריטים המובילים (לפי evidence_score):
| # | פלטפורמה | תגיות Hard Signal | Evidence Score | מקור (URL) | מה נטען (Excerpt קצר) | הערת אמינות |
הערת אמינות = משפט קצר לפי כללים: Primary? Media? Repost?

ב) סטטוס סימנים מעידים (Hard Signals Status):
- NOTAM / שדות תעופה
- בתי חולים / משרד הבריאות
- צו 8 / גיוס מילואים
- שיבושי GPS
- תנועות כוחות / פריסות הגנ"א
לכל סעיף: "נמצא/לא נמצא" + ציין איזה URLs תומכים.

ג) ניתוח השערות מתחרות (ACH):
- השערה א' (הסלמה ממשית)
- השערה ב' (רעש/לוחמה פסיכולוגית/שמועה)
לכל השערה: מה הראיות שתומכות? מה הראיות שסותרות?
בסוף הכרעה: איזה צד חזק יותר על בסיס ראיות בלבד.

ד) טבלת סבירות (The Probability Matrix):
| טווח זמן | סבירות (%) | נימוק (Evidence Based) | רמת ביטחון |
|---|---|---|---|
| מיידי (עד חודש) | % | ... | נמוכה/בינונית/גבוהה |
| קצר (3 חודשים) | % | ... | ... |
| בינוני (6 חודשים) | % | ... | ... |
| ארוך (שנה) | % | ... | ... |

כלל ברזל לקביעת אחוזים:
אם אין סימנים לוגיסטיים/מבצעיים (NOTAM, בתי חולים, צו 8, הודעות רשמיות) — הסבירות למלחמה מיידית חייבת להיות נמוכה, גם אם השיח ברשתות רועש.

ה) מסקנה למקבל ההחלטות:
2–4 משפטים, חד, בלי דרמה.

כתוב בעברית מודיעינית, קרה ומדויקת.
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
# Streamlit Interface
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

st.title("📡 Gemini 3 Advanced OSINT War Room")
st.caption(f"Engine: {FLASH_MODEL} (RAW Collector) -> {PRO_MODEL} (Analyst) | Evidence-first + ACH")

with st.sidebar:
    st.header("מערך איסוף")
    st.info("המערכת אוספת OSINT גולמי (RAW) ולא מסיקה מסקנות בשלב האיסוף.\n\nמקורות: X/Telegram/Web/Official")
    st.divider()
    st.write("**מקורות אימות (רשימה):**")
    st.write(FACT_CHECK_SITES)
    st.divider()
    st.write("**טיפ:** הכי חשוב = URLs ישירים + חומר גלם (וידאו/מסמכים/NOTAM).")

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("📝 הזנת מידע")
    user_text = st.text_area(
        "נושא החקירה (טקסט חופשי / שמועה):",
        height=200,
        placeholder="לדוגמה: דיווחים בטלגרם על תנועת כוחות חריגה בגבול הצפון...",
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
    if not user_text and not uploaded and not user_links.strip():
        st.error("חובה להזין טקסט, או קישור, או להעלות תמונה.")
        st.stop()

    links = _clean_links(user_links)
    imgs = [f.read() for f in uploaded] if uploaded else []

    with st.status("מבצע איסוף OSINT גולמי + ניתוח ACH...", expanded=True) as status:
        # --- Step 1: RAW collection
        st.write("📡 **Flash (RAW):** איסוף חומר גלם מהאינטרנט (כולל X/Telegram/רשמי) + תיוג Hard Signals...")
        raw_pkg = run_flash_raw_collection(user_text, links, imgs)

        if "error" in raw_pkg and not raw_pkg.get("items"):
            status.update(label="שגיאה באיסוף", state="error")
            st.error(f"תקלה: {raw_pkg['error']}")
            st.stop()

        enriched_pkg = enrich_and_rank_package(raw_pkg)

        items_count = len(enriched_pkg.get("items", []))
        ranked_count = len(enriched_pkg.get("items_ranked", []))
        tag_counts = enriched_pkg.get("hard_signal_tag_counts", {})

        st.markdown(
            f"""
<div class="small">
<b>כמות פריטים שנאספו:</b> {items_count} |
<b>כמות לאחר דירוג:</b> {ranked_count} |
<b>תגיות Hard Signals:</b> {tag_counts if tag_counts else "לא זוהו"}
</div>
""",
            unsafe_allow_html=True,
        )

        # --- Step 2: Pro analysis
        st.write("🧠 **Pro:** בניית Evidence Table + ניתוח השערות מתחרות (ACH) + מטריצת סבירות...")
        final_report = run_pro_strategic_analysis(enriched_pkg)

        status.update(label="הערכת המצב הושלמה", state="complete")

    st.divider()
    st.markdown("## 📊 דו\"ח מודיעין מסכם (Evidence-first)")
    st.markdown(final_report)

    # RAW items (full)
    with st.expander("🔍 OSINT גולמי שנאסף (items)"):
        st.json({"subject": enriched_pkg.get("subject"), "items": enriched_pkg.get("items", [])})

    # Ranked items (top)
    with st.expander("⭐ פריטים מדורגים (Top items_ranked)"):
        st.json(enriched_pkg.get("items_ranked", [])[:25])

    # Verified/grounding URLs
    with st.expander("🔗 מקורות שאומתו ע\"י grounding metadata (אם קיימים)"):
        vlinks = enriched_pkg.get("verified_links", [])
        if not vlinks:
            st.write("לא נמצאו grounding links (זה יכול לקרות).")
        else:
            for link in vlinks[:50]:
                st.markdown(f"- [{link}]({link})")

    # Coverage gaps
    with st.expander("🕳️ Coverage Gaps (מה לא נמצא)"):
        gaps = enriched_pkg.get("coverage_gaps", [])
        if not gaps:
            st.write("לא דווחו פערי כיסוי.")
        else:
            for g in gaps[:30]:
                st.write(f"- {g}")

    # Dedupe notes
    with st.expander("🧹 Dedupe Notes"):
        dn = enriched_pkg.get("dedupe_notes", [])
        if not dn:
            st.write("אין.")
        else:
            for n in dn[:30]:
                st.write(f"- {n}")
```0