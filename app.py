import os
import json
import re
import datetime
from typing import Any, Dict, List, Tuple, Optional

import streamlit as st
from google import genai
from google.genai import types

# ============================================================
# 📡 Gemini 3 OSINT Engine (Evidence-first)
# Flash  -> RAW Collector (URL-cited items only)
# Pro    -> Analyst (Evidence Table + ACH)
#
# SAFETY / SCOPE GUARDRAILS:
# - This app is for verifying PUBLIC claims and detecting disinformation.
# - It MUST NOT generate operational/tactical guidance (no coordinates, no targeting).
# - Evidence-first: Without supporting URL, we don't allow conclusions.
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

# ----------------------------
# Display-only source list (not scraped directly)
# ----------------------------
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
# Regex / parsing helpers
# ----------------------------
URL_RE = re.compile(r"https?://[^\s)\]>\"']+", re.IGNORECASE)
MARKER_RE = re.compile(r"\[#(\d+)\]")

def _iso_now_utc() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def _clean_links(raw: str) -> List[str]:
    urls = URL_RE.findall(raw or "")
    out, seen = [], set()
    for u in urls:
        u = u.strip().rstrip(".,;)")
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out[:40]

def _safe_json_loads(s: str) -> Dict[str, Any]:
    s = (s or "").strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s).strip()
    try:
        return json.loads(s)
    except Exception:
        m = re.search(r"(\{.*\})", s, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                pass
        return {"error": "Failed to parse JSON", "raw": s[:4000]}

def _extract_grounding_urls(resp: Any) -> List[str]:
    urls: List[str] = []
    try:
        if getattr(resp, "candidates", None):
            gm = resp.candidates[0].grounding_metadata
            if gm and getattr(gm, "grounding_chunks", None):
                for chunk in gm.grounding_chunks:
                    if chunk.web and chunk.web.uri:
                        urls.append(chunk.web.uri)
    except Exception:
        pass
    seen, out = set(), []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out

def _clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))

def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

# ----------------------------
# Evidence normalization & scoring (deterministic)
# ----------------------------
HARD_TAGS = {
    "military_movements",
    "air_defense",
    "notam_flights",
    "satellite_imagery",
    "logistics_medical",
    "gps_jamming",
    "cyber",
    "official_document",
    "leak",
    "other",
}

def _detect_platform_from_url(url: str) -> str:
    u = (url or "").lower()
    if "t.me/" in u or "telegram" in u or "tgstat" in u or "telemetr" in u:
        return "telegram"
    if "x.com/" in u or "twitter.com/" in u or "nitter" in u:
        return "x"
    if any(dom in u for dom in ["whitehouse.gov", ".mil", ".gov", "mod.gov", "defense.gov"]):
        return "official"
    if any(dom in u for dom in ["bellingcat", "maxar", "planet.com", "sentinel", "copernicus"]):
        return "osint"
    return "web"

def _bucket(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"

def _score_item(it: Dict[str, Any]) -> Tuple[int, List[str]]:
    """
    Deterministic scoring, so you are not 100% dependent on the model's scoring.
    """
    reasons: List[str] = []
    score = 0

    platform = (it.get("platform") or "").strip().lower()
    url = (it.get("url") or "").strip()
    flags = it.get("credibility_flags") or {}

    # baseline by platform
    if platform == "official":
        score += 35
        reasons.append("Official baseline +35")
    elif platform in ("major_media",):
        score += 22
        reasons.append("Major media baseline +22")
    elif platform in ("osint", "satellite"):
        score += 18
        reasons.append("OSINT baseline +18")
    elif platform == "x":
        score += 10
        reasons.append("X baseline +10")
    elif platform == "telegram":
        score += 8
        reasons.append("Telegram baseline +8")
    else:
        score += 15
        reasons.append("Web baseline +15")

    # primary source boost
    if flags.get("is_primary_source") is True:
        score += 12
        reasons.append("Primary +12")

    # original media boost
    if flags.get("has_original_media") is True:
        score += 12
        reasons.append("Original media +12")

    # repost penalty
    if flags.get("appears_repost") is True:
        score -= 15
        reasons.append("Repost -15")

    # timestamp/location hints (small boosts)
    if it.get("published_time"):
        score += 4
        reasons.append("Has time +4")
    if _as_list(it.get("location_hints")):
        score += 3
        reasons.append("Has location hints +3")

    # hard-signal tags boost (capped)
    tags = [t for t in _as_list(it.get("hard_signal_tags")) if isinstance(t, str)]
    tags = [t for t in tags if t in HARD_TAGS]
    hard_bonus = 0
    for t in tags:
        if t in ("official_document", "notam_flights", "satellite_imagery", "logistics_medical", "gps_jamming", "military_movements"):
            hard_bonus += 6
    hard_bonus = min(hard_bonus, 18)
    if hard_bonus:
        score += hard_bonus
        reasons.append(f"Hard-signal +{hard_bonus}")

    # URL sanity (if missing, force near-zero)
    if not url or not url.startswith("http"):
        score = 0
        reasons.append("Missing URL => score forced to 0")

    return _clamp(score, 0, 100), reasons

def _normalize_items(pkg: Dict[str, Any]) -> Dict[str, Any]:
    items = pkg.get("items_ranked")
    if not isinstance(items, list):
        items = []

    norm: List[Dict[str, Any]] = []
    for raw in items:
        if not isinstance(raw, dict):
            continue

        url = (raw.get("url") or "").strip()
        if not url or not url.startswith("http"):
            # enforce "No URL => no claim": keep it out of ranked list
            continue

        platform = (raw.get("platform") or "").strip().lower()
        if not platform:
            platform = _detect_platform_from_url(url)

        # normalize tags
        tags = [t for t in _as_list(raw.get("hard_signal_tags")) if isinstance(t, str)]
        tags = [t for t in tags if t in HARD_TAGS]
        if not tags:
            tags = ["other"]

        flags = raw.get("credibility_flags") or {}
        if not isinstance(flags, dict):
            flags = {}

        it = {
            "platform": platform,
            "url": url,
            "published_time": (raw.get("published_time") or ""),
            "author_or_channel": (raw.get("author_or_channel") or ""),
            "item_type": (raw.get("item_type") or "text"),
            "raw_excerpt": (raw.get("raw_excerpt") or "")[:420],
            "media_urls": [m for m in _as_list(raw.get("media_urls")) if isinstance(m, str) and m.startswith("http")][:10],
            "hard_signal_tags": tags,
            "location_hints": [x for x in _as_list(raw.get("location_hints")) if isinstance(x, str)][:6],
            "credibility_flags": {
                "is_primary_source": bool(flags.get("is_primary_source")),
                "has_original_media": bool(flags.get("has_original_media")),
                "appears_repost": bool(flags.get("appears_repost")),
            },
        }

        # score deterministically (override model if missing/invalid)
        score, reasons = _score_item(it)
        it["evidence_score"] = score
        it["evidence_reasons"] = reasons
        it["evidence_bucket"] = _bucket(score)

        norm.append(it)

    # sort by evidence_score desc
    norm.sort(key=lambda x: x.get("evidence_score", 0), reverse=True)

    # compute tag counts
    tag_counts: Dict[str, int] = {}
    for it in norm:
        for t in it.get("hard_signal_tags", []) or []:
            tag_counts[t] = tag_counts.get(t, 0) + 1

    pkg["items_ranked"] = norm[:30]  # keep top 30
    pkg["hard_signal_tag_counts"] = tag_counts
    return pkg

def _extract_all_urls(pkg: Dict[str, Any]) -> List[str]:
    urls: List[str] = []
    for it in pkg.get("items_ranked", []) or []:
        u = it.get("url")
        if u:
            urls.append(u)
        for mu in it.get("media_urls", []) or []:
            if mu:
                urls.append(mu)
    for u in pkg.get("verified_links", []) or []:
        if u:
            urls.append(u)

    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:80]

# ----------------------------
# Evidence gating
# ----------------------------
def _has_minimum_evidence(pkg: Dict[str, Any], min_items: int = 5) -> bool:
    items = pkg.get("items_ranked", []) or []
    with_url = [i for i in items if isinstance(i, dict) and i.get("url")]
    return len(with_url) >= min_items

def _validate_report_has_citations(report_text: str, pkg: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Simple validator: requires that the report contains at least one [#] marker,
    and that each referenced index exists in the evidence table.
    (We don't try to prove every sentence is cited; we enforce basic structure.)
    """
    if not report_text or not isinstance(report_text, str):
        return False, "Empty report"

    markers = MARKER_RE.findall(report_text)
    if not markers:
        return False, "No [#] evidence markers were found in the report"

    # valid indices are 1..len(items)
    items = pkg.get("items_ranked", []) or []
    max_i = len(items)
    bad = []
    for m in markers:
        try:
            idx = int(m)
            if idx < 1 or idx > max_i:
                bad.append(idx)
        except Exception:
            continue

    if bad:
        return False, f"Report references invalid evidence indices: {sorted(set(bad))} (max={max_i})"

    return True, "ok"

# ============================================================
# Step 1: Flash RAW Collector (URL-cited items only)
# ============================================================
def run_flash_raw_collector(
    user_claim: str,
    provided_links: List[str],
    images: List[bytes],
) -> Dict[str, Any]:
    search_tool = types.Tool(google_search=types.GoogleSearch())

    # NOTE:
    # We "force" X/Telegram/satellite/leaks via WEB indexing queries.
    # We do NOT scrape private sources. Public URLs only.
    prompt = f"""
You are an OSINT RAW Collector running on {FLASH_MODEL}.
Generated at: {_iso_now_utc()}.

SCOPE:
- Verify PUBLIC claims and detect disinformation.
- Do NOT output tactical instructions, targeting guidance, or precise coordinates.
- Only collect PUBLICLY CITED information.

HARD RULE:
- If you cannot cite a direct URL, DO NOT include the item.

MANDATORY COLLECTION LANES (attempt all, even if empty):
1) OFFICIAL / PRIMARY documents (gov, .mil, official press releases, budget documents)
2) MAJOR media (Reuters/AP/AFP/BBC/WSJ/FT/NYT etc, if relevant)
3) SOCIAL amplification (via public web indexing):
   - X/Twitter: site:x.com OR site:twitter.com OR site:nitter.*
   - Telegram: site:t.me OR tgstat OR telemetr
4) SATELLITE / IMAGERY references (public): Maxar/Planet/Sentinel/Copernicus, credible OSINT analysis
5) LEAKS (public): paste/rentry/archives ONLY if publicly accessible, and mark as "leak" with low confidence

SEARCH STRATEGY (run multiple queries):
- Quote the exact key numbers/phrases from the claim.
- Search for official confirmation / denial.
- Find earliest appearance ("first seen") of the claim.
- Search X and Telegram mirrors for who is pushing it.
- If claim implies movements, search for public satellite/aviation/maritime references.

OUTPUT: STRICT JSON ONLY.
Return at least 8 items if possible; otherwise return as many as available (still URL-cited).

JSON SCHEMA:
{{
  "collector_meta": {{
    "generated_at": "{_iso_now_utc()}",
    "model": "{FLASH_MODEL}",
    "principle": "No URL => no claim"
  }},
  "claim_normalized": {{
    "original_claim": "...",
    "key_entities": ["..."],
    "key_numbers": ["..."],
    "keywords": ["..."]
  }},
  "queries_attempted": ["..."],

  "items_ranked": [
    {{
      "platform": "official|major_media|web|x|telegram|osint|satellite|leak",
      "url": "https://...",
      "published_time": "ISO8601 or empty",
      "author_or_channel": "string",
      "item_type": "text|video|image|document|thread",
      "raw_excerpt": "short excerpt, max 280 chars",
      "media_urls": ["https://..."],
      "hard_signal_tags": ["military_movements","satellite_imagery","notam_flights","official_document","other"],
      "location_hints": ["..."],
      "credibility_flags": {{
        "is_primary_source": boolean,
        "has_original_media": boolean,
        "appears_repost": boolean
      }}
    }}
  ],

  "contradictions": ["..."],

  "known_hoax_check": {{
    "is_fake": boolean,
    "details": "If fake, cite which URLs debunk it"
  }}
}}

USER CLAIM:
{user_claim}

OPTIONAL provided links:
{provided_links}
"""

    parts = [types.Part(text=prompt)]

    # Attach up to 8 images (as evidence for reverse-checking via search tool)
    for img in (images or [])[:8]:
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
        pkg["verified_links"] = _extract_grounding_urls(resp)

        # Normalize + deterministic scoring + tag counts + sorting + URL gating
        pkg = _normalize_items(pkg)

        return pkg
    except Exception as e:
        return {
            "error": f"Flash RAW Collector error: {str(e)}",
            "verified_links": [],
            "items_ranked": [],
            "hard_signal_tag_counts": {},
        }

# ============================================================
# Step 2: Pro Analyst (Evidence Table + ACH)
# ============================================================
def run_pro_ach_report(pkg: Dict[str, Any]) -> str:
    system_instruction = (
        "You are a Senior Intelligence Assessment Officer. "
        "You MUST be evidence-first. "
        "Every factual claim must include a citation marker [#] referencing the Evidence Table row number, "
        "and include the URL next to it. "
        "Do NOT include operational/tactical guidance. No coordinates, no targeting, no 'what to do' instructions."
    )

    user_prompt = f"""
יש לך חבילת נתונים גולמיים (RAW OSINT). תייצר דו״ח הערכה בעברית מודיעינית, קרה ומדויקת.

חוקים:
1) כל טענה עובדתית חייבת לכלול ציטוט במבנה [#] + URL באותה שורה/משפט.
2) אם אין ראיות מספקות — תגיד "לא ניתן לאמת" ותסביר למה.
3) תבצע ACH (השערות מתחרות) + איפכא מסתברא.
4) אל תיתן שום הנחיה טקטית/מבצעית. אין נקודות ציון/מסלולים/יעדים.

מבנה חובה:
A) טבלת ראיות (Evidence Table) — Markdown:
| # | פלטפורמה | תגיות Hard Signal | Evidence Score | מקור (URL) | Excerpt קצר | הערת אמינות |
B) סטטוס אינדיקטורים קשיחים (Hard Signals Status):
- NOTAM/תעופה
- בתי חולים/בריאות
- שיבושי GPS
- תזוזות/פעילות צבאית
- לוויין/דימות
- הדלפות
(אם סעיף לא רלוונטי לטענה, כתוב "לא רלוונטי".)
C) ACH:
- השערה א׳: הטענה נכונה
- השערה ב׳: הטענה שגויה/פייק/קונפלציה
- הכרעה Evidence-based בלבד
D) מטריצת סבירות (Probability Matrix) — רק אם הטענה מתייחסת לעתיד/תרחיש
E) שורה תחתונה

RAW PACKAGE:
{json.dumps(pkg, ensure_ascii=False)}
"""

    resp = client.models.generate_content(
        model=PRO_MODEL,
        contents=[types.Content(role="user", parts=[types.Part(text=user_prompt)])],
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=0.2,
        ),
    )
    return resp.text or ""

# ============================================================
# Streamlit UI
# ============================================================

st.set_page_config(page_title="Gemini 3 OSINT War Room", layout="wide", page_icon="📡")

st.markdown(
    """
<style>
    .stTextArea textarea { font-size: 16px !important; }
    .stAlert { direction: rtl; }
    .rtl { direction: rtl; }
    code, pre { direction: ltr; }
</style>
""",
    unsafe_allow_html=True,
)

st.title("📡 Gemini 3 Advanced OSINT Engine")
st.caption(f"Engine: {FLASH_MODEL} (RAW Collector) → {PRO_MODEL} (Analyst) | Evidence-first + ACH")
st.markdown("**עיקרון:** בלי URL תומך — אין טענה. (המערכת תחסום דו״ח אם אין מספיק ראיות).")

with st.sidebar:
    st.header("מערך איסוף")
    st.info(
        "המערכת אוספת OSINT גולמי (RAW) ומכריחה ציטוטי URL לפני מסקנות.\n\n"
        "ניסיונות איסוף חובה (דרך אינדוקס רשת ציבורי):\n"
        "- Twitter/X\n"
        "- Telegram\n"
        "- Satellite / imagery (רק אזכורים ציבוריים)\n"
        "- Leaks (רק אם URL ציבורי)\n"
        "- Official reports + Major media\n"
    )
    st.divider()
    st.write("**מקורות אימות (רשימה תצוגתית):**")
    st.code(json.dumps(FACT_CHECK_SITES, ensure_ascii=False, indent=2))

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("📝 הזנת מידע")
    user_text = st.text_area(
        "נושא החקירה (טקסט חופשי / שמועה):",
        height=240,
        placeholder="כתוב פה טענה לבדיקה. קישור/כתבה/סקרינשוט - אופציונלי.",
    )
    user_links = st.text_area("קישורים ספציפיים (אופציונלי):", height=120)

with col2:
    st.subheader("📷 ראיות ויזואליות (אופציונלי)")
    uploaded = st.file_uploader(
        "העלה צילומי מסך/מפות:",
        type=["png", "jpg", "jpeg"],
        accept_multiple_files=True,
    )
    if uploaded:
        st.success(f"{len(uploaded)} קבצים נטענו לניתוח")

# Controls
colA, colB, colC = st.columns([1, 1, 1])
with colA:
    min_items = st.number_input("מינימום פריטי ראיות (URL) לפני דו״ח:", min_value=3, max_value=15, value=5, step=1)
with colB:
    top_n = st.number_input("כמה פריטים להציג בטבלת ראיות (Top N):", min_value=5, max_value=30, value=12, step=1)
with colC:
    strict_block = st.toggle("חסימה קשיחה אם דו״ח בלי ציטוטים [#] תקינים", value=True)

run_btn = st.button("🚀 הרץ", type="primary", use_container_width=True)

if run_btn:
    if not user_text and not uploaded:
        st.error("חובה להזין טקסט או להעלות תמונה.")
        st.stop()

    links = _clean_links(user_links)
    imgs = [f.read() for f in uploaded] if uploaded else []

    with st.status("מבצע איסוף וניתוח...", expanded=True) as status:
        st.write("📡 **Flash (RAW Collector):** איסוף פריטים עם URL בלבד + תיוג Hard Signals…")
        pkg = run_flash_raw_collector(user_text, links, imgs)

        if "error" in pkg:
            status.update(label="שגיאה באיסוף", state="error")
            st.error(pkg["error"])
            st.stop()

        items = pkg.get("items_ranked", []) or []
        tag_counts = pkg.get("hard_signal_tag_counts", {}) or {}

        st.write(f"Items (URL-cited): {len(items)} | Hard Signal tag counts: {tag_counts}")

        # Gate 1: minimum evidence items
        if not _has_minimum_evidence(pkg, min_items=int(min_items)):
            status.update(label="דו״ח נחסם: חסרים ציטוטים תומכים", state="error")
            st.error(f"דו״ח נחסם: לא נאספו מספיק פריטי ראיות עם URL (נדרש מינימום {int(min_items)}).")
            with st.expander("🔍 נתונים גולמיים (JSON)"):
                st.json(pkg)
            st.stop()

        st.write("🧠 **Pro (Analyst):** Evidence Table + ACH (כל טענה עם [#] + URL)…")
        report = run_pro_ach_report(pkg)

        # Gate 2: report structure + evidence markers
        ok, why = _validate_report_has_citations(report, pkg)
        if strict_block and not ok:
            status.update(label="הדו״ח נחסם: ציטוטים לא עומדים בכלל", state="error")
            st.error(f"הדו״ח נחסם: {why}")
            st.markdown("### 📄 דו״ח גולמי שהוחזר (לבדיקה)")
            st.markdown(report or "(empty)")
            with st.expander("🔍 נתונים גולמיים (JSON)"):
                st.json(pkg)
            st.stop()

        status.update(label="הערכת המצב הושלמה", state="complete")

    st.divider()

    # Hoax warning if present
    hoax = pkg.get("known_hoax_check") or {}
    if hoax.get("is_fake") is True:
        st.error(f"🚨 מדובר ככל הנראה בחדשות כזב: {hoax.get('details','')}")

    st.markdown("## 📊 דו\"ח מסכם")
    st.markdown(report)

    # Show ranked evidence table preview (UI-side), independent of Pro output
    st.markdown("## 🧾 Top Evidence (Preview)")
    show_items = (pkg.get("items_ranked", []) or [])[: int(top_n)]
    if not show_items:
        st.write("אין פריטים להצגה.")
    else:
        rows = []
        for i, it in enumerate(show_items, start=1):
            rows.append(
                {
                    "#": i,
                    "platform": it.get("platform", ""),
                    "tags": ", ".join(it.get("hard_signal_tags", []) or []),
                    "score": it.get("evidence_score", 0),
                    "url": it.get("url", ""),
                    "excerpt": it.get("raw_excerpt", "")[:160],
                    "bucket": it.get("evidence_bucket", ""),
                }
            )
        st.dataframe(rows, use_container_width=True)

    with st.expander("🔍 נתונים גולמיים (JSON)"):
        st.json(pkg)

    with st.expander("🔗 כל ה-URLs שנאספו"):
        urls = _extract_all_urls(pkg)
        if not urls:
            st.write("לא נמצאו URL-ים.")
        else:
            for u in urls:
                st.markdown(f"- {u}")