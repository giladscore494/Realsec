# app.py
# ==========================================
# Gemini Grounded Verifier (1 grounded call -> 1 Pro analysis call)
# Streamlit UI: user can paste text + links + upload screenshots
#
# Flow:
# 1) Gemini "Flash" WITH google_search tool (grounding) runs ONCE:
#    - reads user text + screenshots (vision) + links
#    - searches web (grounding) as needed
#    - returns STRICT JSON: claims, keywords, evidence bullets, and a compact "pro_prompt"
#    - (optionally) includes citations URLs extracted from groundingMetadata
# 2) Gemini "Pro" WITHOUT tools:
#    - receives the JSON package as input
#    - outputs up to ONE paragraph in Hebrew
#
# Requirements:
#   pip install streamlit google-genai
# Env:
#   export GEMINI_API_KEY="..."
# Optional:
#   export FLASH_MODEL="gemini-2.5-flash"
#   export PRO_MODEL="gemini-2.5-pro"
# ==========================================

import os
import json
import re
from typing import Any, Dict, List, Optional

import streamlit as st
from google import genai
from google.genai import types


# ----------------------------
# Config
# ----------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
FLASH_MODEL = os.getenv("FLASH_MODEL", "gemini-2.5-flash")
PRO_MODEL = os.getenv("PRO_MODEL", "gemini-2.5-pro")

if not GEMINI_API_KEY:
    raise RuntimeError("Missing GEMINI_API_KEY env var.")

client = genai.Client(api_key=GEMINI_API_KEY)


# ----------------------------
# Utilities
# ----------------------------
def _clean_links(raw: str) -> List[str]:
    if not raw.strip():
        return []
    # Extract URLs from any pasted text
    urls = re.findall(r"https?://[^\s)>\]]+", raw)
    # Dedup while preserving order
    out = []
    seen = set()
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:15]


def _safe_json_loads(s: str) -> Dict[str, Any]:
    # Strict JSON expected. If the model wraps it, try to extract.
    s = s.strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
        s = s.strip()
    # Extract first {...} block if needed
    if not s.startswith("{"):
        m = re.search(r"(\{.*\})", s, re.DOTALL)
        if m:
            s = m.group(1)
    return json.loads(s)


def _extract_grounding_urls(resp: Any) -> List[Dict[str, str]]:
    """
    Pull URLs/titles from groundingMetadata if present.
    The exact shape can vary; keep it defensive.
    """
    out: List[Dict[str, str]] = []
    try:
        cand0 = resp.candidates[0]
        gm = getattr(cand0, "grounding_metadata", None) or getattr(cand0, "groundingMetadata", None)
        if not gm:
            return out

        # groundingChunks often contains web entries
        chunks = getattr(gm, "grounding_chunks", None) or getattr(gm, "groundingChunks", None) or []
        for ch in chunks:
            web = getattr(ch, "web", None) or {}
            uri = getattr(web, "uri", None) or web.get("uri")
            title = getattr(web, "title", None) or web.get("title")
            if uri:
                out.append({"title": title or "", "url": uri})

        # Dedup
        dedup = []
        seen = set()
        for item in out:
            if item["url"] not in seen:
                seen.add(item["url"])
                dedup.append(item)
        return dedup[:20]
    except Exception:
        return []


# ----------------------------
# Gemini Calls
# ----------------------------
def flash_grounded_package(user_news: str, links: List[str], images: List[bytes]) -> Dict[str, Any]:
    grounding_tool = types.Tool(google_search=types.GoogleSearch())
    config = types.GenerateContentConfig(
        tools=[grounding_tool],
        temperature=0.2,
    )

    # Build multimodal parts: text + images
    parts: List[types.Part] = []

    # Core prompt: force JSON only
    prompt = f"""
You are a verification pipeline. Produce STRICT JSON only (no markdown).

Goal:
- Given: user-submitted "news items" about a security situation, plus optional links and screenshots.
- You may use Google Search grounding (enabled) inside THIS single call.
- Output a compact evidence package to be analyzed later by another model WITHOUT any browsing.

Hard rules:
- Output MUST be valid JSON.
- Do not include any extra keys outside the schema below.
- Use cautious language. If evidence is insufficient: mark as "unclear".
- Do NOT invent sources. Use only what you actually saw via grounding or user-provided links.
- If screenshots contain text, extract the text and treat it as a claim input (not as proof).

Schema:
{{
  "input_summary": {{
    "user_items_short": "...",
    "links_seen": ["..."],
    "screenshots_count": 0
  }},
  "claims": [
    {{
      "id": "c1",
      "claim": "1 sentence, checkable",
      "keywords": ["...","..."],
      "time_place_entities": {{
        "time": ["..."],
        "place": ["..."],
        "entities": ["..."]
      }},
      "grounded_evidence_bullets": [
        {{
          "support": "supports | contradicts | weak | unclear",
          "source_title": "...",
          "source_url": "...",
          "what_it_says": "short paraphrase (no long quotes)"
        }}
      ],
      "credibility_signals": {{
        "independent_sources_count": 0,
        "has_primary_or_official": true,
        "has_major_outlets": true,
        "conflicts_found": false
      }},
      "preliminary_likelihood": {{
        "label": "likely_true | unclear | likely_false",
        "confidence_0_100": 0,
        "why": "1-2 short sentences"
      }}
    }}
  ],
  "global_notes": {{
    "what_is_most_solid": ["..."],
    "what_is_most_uncertain": ["..."],
    "missing_checks": ["..."]
  }},
  "pro_prompt": {{
    "system": "You are an evidence-based analyst. Do not browse. Use only provided package.",
    "user": "A compact instruction + all evidence needed. Keep it short but complete."
  }}
}}

User news text:
{user_news}

User links (may be empty):
{links}
""".strip()

    parts.append(types.Part(text=prompt))

    for img_bytes in images[:8]:
        parts.append(
            types.Part(
                inline_data=types.Blob(mime_type="image/png", data=img_bytes)
            )
        )

    resp = client.models.generate_content(
        model=FLASH_MODEL,
        contents=[types.Content(role="user", parts=parts)],
        config=config,
    )

    pkg = _safe_json_loads(resp.text)
    # Optionally enrich with grounding URLs (not changing schema; so we only merge into links_seen if empty)
    grounding_urls = _extract_grounding_urls(resp)
    if grounding_urls:
        # Keep schema: links_seen is list[str]
        extra = [u["url"] for u in grounding_urls if u.get("url")]
        seen = set(pkg["input_summary"].get("links_seen", []))
        merged = pkg["input_summary"].get("links_seen", [])
        for u in extra:
            if u not in seen:
                seen.add(u)
                merged.append(u)
        pkg["input_summary"]["links_seen"] = merged[:25]
    return pkg


def pro_analyze_package(pkg: Dict[str, Any]) -> str:
    # Pro call WITHOUT tools: no google_search tool in config.
    config = types.GenerateContentConfig(
        temperature=0.2,
        # explicitly no tools here
    )

    pro_system = pkg["pro_prompt"]["system"]
    pro_user = pkg["pro_prompt"]["user"]

    # Make Pro's user message include the whole package (but compact).
    payload = {
        "instruction": pro_user,
        "package": {
            "input_summary": pkg.get("input_summary", {}),
            "claims": pkg.get("claims", []),
            "global_notes": pkg.get("global_notes", {}),
        },
        "output_requirements": {
            "language": "Hebrew",
            "format": "ONE paragraph only",
            "max_length": "about 6-8 lines",
            "must_include": [
                "overall likelihood summary",
                "top 1-2 strongest supports",
                "top 1-2 biggest uncertainties"
            ],
        },
    }

    resp = client.models.generate_content(
        model=PRO_MODEL,
        contents=[
            types.Content(role="system", parts=[types.Part(text=pro_system)]),
            types.Content(role="user", parts=[types.Part(text=json.dumps(payload, ensure_ascii=False))]),
        ],
        config=config,
    )
    return (resp.text or "").strip()


# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="Security Claim Verifier", layout="wide")

st.title("בודק אמינות ידיעות (Grounding פעם אחת -> ניתוח Pro בלי חיפוש)")

with st.expander("הגדרות (אופציונלי)"):
    st.write(f"Flash model: `{FLASH_MODEL}`")
    st.write(f"Pro model: `{PRO_MODEL}`")

col1, col2 = st.columns([1, 1])

with col1:
    user_news = st.text_area(
        "הדבק פה את הידיעות/טענות (טקסט חופשי):",
        height=220,
        placeholder="לדוגמה: 'מקור X טוען ש...'\n'דיווח נוסף אומר ש...'",
    )
    links_text = st.text_area(
        "הדבק פה קישורים לכתבות (אפשר גם יחד עם טקסט):",
        height=120,
        placeholder="https://...\nhttps://...",
    )

with col2:
    uploaded = st.file_uploader(
        "העלה תצלומי מסך (PNG/JPG) שמכילים טקסט/כותרות:",
        type=["png", "jpg", "jpeg"],
        accept_multiple_files=True,
    )
    st.caption("הסקרינשוטים משמשים כקלט לטענות. הם לא 'הוכחה' בפני עצמם.")

run_btn = st.button("בדוק אמינות", type="primary", use_container_width=True)

if run_btn:
    if not (user_news.strip() or links_text.strip() or uploaded):
        st.error("אין קלט. תדביק טקסט/קישורים או תעלה סקרינשוטים.")
        st.stop()

    links = _clean_links(links_text)
    images_bytes: List[bytes] = []
    if uploaded:
        for f in uploaded:
            images_bytes.append(f.read())

    with st.spinner("שלב 1/2: איסוף ראיות עם Grounding (Flash) ..."):
        try:
            pkg = flash_grounded_package(user_news=user_news, links=links, images=images_bytes)
        except Exception as e:
            st.error(f"שגיאה בשלב ה-Grounding: {e}")
            st.stop()

    with st.spinner("שלב 2/2: ניתוח ללא חיפוש (Pro) ..."):
        try:
            final_text = pro_analyze_package(pkg)
        except Exception as e:
            st.error(f"שגיאה בשלב הניתוח: {e}")
            st.stop()

    st.subheader("סיכום למשתמש")
    st.write(final_text)

    with st.expander("מה נאסף (JSON שנשלח ל-Pro)"):
        st.json(pkg)

    # Quick view of sources that were seen
    links_seen = pkg.get("input_summary", {}).get("links_seen", []) or []
    if links_seen:
        st.subheader("מקורות שנראו (לינקים)")
        for u in links_seen[:25]:
            st.write(f"- {u}")
