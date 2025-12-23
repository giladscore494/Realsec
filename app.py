import os
import json
import re
from typing import Any, Dict, List

import streamlit as st
from google import genai
from google.genai import types


# ----------------------------
# Config
# ----------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
FLASH_MODEL = os.getenv("FLASH_MODEL", "gemini-3-flash-preview")
PRO_MODEL = os.getenv("PRO_MODEL", "gemini-3-pro-preview")

if not GEMINI_API_KEY:
    raise RuntimeError("Missing GEMINI_API_KEY env var.")

client = genai.Client(api_key=GEMINI_API_KEY)


# ----------------------------
# Utilities
# ----------------------------
def _clean_links(raw: str) -> List[str]:
    urls = re.findall(r"https?://[^\s)>\]]+", raw or "")
    out, seen = [], set()
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:20]


def _safe_json_loads(s: str) -> Dict[str, Any]:
    s = (s or "").strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s).strip()
    if not s.startswith("{"):
        m = re.search(r"(\{.*\})", s, re.DOTALL)
        if m:
            s = m.group(1)
    return json.loads(s)


def _extract_grounding_urls(resp: Any) -> List[str]:
    urls: List[str] = []
    try:
        cand0 = resp.candidates[0]
        gm = getattr(cand0, "grounding_metadata", None) or getattr(cand0, "groundingMetadata", None)
        if not gm:
            return []
        chunks = getattr(gm, "grounding_chunks", None) or getattr(gm, "groundingChunks", None) or []
        for ch in chunks:
            web = getattr(ch, "web", None) or {}
            uri = getattr(web, "uri", None) or (web.get("uri") if isinstance(web, dict) else None)
            if uri:
                urls.append(uri)
    except Exception:
        return []
    # dedup
    out, seen = [], set()
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:30]


# ----------------------------
# Flash (Grounded) - OSINT package builder
# ----------------------------
def flash_grounded_osint_package(user_news: str, links: List[str], images: List[bytes]) -> Dict[str, Any]:
    grounding_tool = types.Tool(google_search=types.GoogleSearch())
    config = types.GenerateContentConfig(
        tools=[grounding_tool],
        temperature=0.2,
    )

    osint_buckets = [
        "official_primary",     # official statements, govt/military/police/emergency
        "major_media",          # Reuters/AP/BBC etc. + large national outlets
        "geoint",               # satellite imagery / geolocation corroboration if relevant
        "aviation",             # NOTAM/airspace closures/flight disruptions if relevant
        "maritime",             # port disruptions/AIS anomalies if relevant
        "event_monitors",       # incident trackers/monitor orgs
        "media_verification",   # prior appearance, edits, mismatch checks
        "expert_context"        # credible analysts/think tanks (flag as "analysis", not "fact")
    ]

    prompt = f"""
You are an OSINT verification engine. You have Google Search grounding enabled in THIS call.
You must search in BOTH Hebrew and English.

Goal:
- Extract distinct factual claims from user input (text + screenshots + links).
- For each claim, perform OSINT-style cross-checking using the buckets below,
  even if the user provided a low-quality source.

OSINT buckets (you MUST attempt coverage where relevant):
{osint_buckets}

Hard rules:
- Output STRICT JSON only (no markdown, no extra commentary).
- Do not invent sources. Only cite URLs you actually got from grounded search.
- User screenshots are INPUT (claims), not proof.
- For each claim, generate: (1) Hebrew queries list, (2) English queries list
  that explicitly target OSINT buckets (official/major media/etc.).
- If a bucket is not relevant to the claim, mark it "not_relevant" with a short reason.
- Evidence must be short paraphrases (no long quotes).
- If sources conflict, you must mark conflicts_found=true and describe the conflict.

Schema (output exactly this structure, no extra keys):
{{
  "input_summary": {{
    "user_items_short": "...",
    "user_links": ["..."],
    "screenshots_count": 0
  }},
  "claims": [
    {{
      "id": "c1",
      "claim": "1 sentence, checkable",
      "keywords": ["..."],
      "time_place_entities": {{
        "time": ["..."],
        "place": ["..."],
        "entities": ["..."]
      }},
      "osint_search_plan": {{
        "he_queries": ["..."],
        "en_queries": ["..."],
        "bucket_targets": {{
          "official_primary": "must_try | not_relevant",
          "major_media": "must_try | not_relevant",
          "geoint": "must_try | not_relevant",
          "aviation": "must_try | not_relevant",
          "maritime": "must_try | not_relevant",
          "event_monitors": "must_try | not_relevant",
          "media_verification": "must_try | not_relevant",
          "expert_context": "must_try | not_relevant"
        }}
      }},
      "evidence": [
        {{
          "bucket": "official_primary | major_media | geoint | aviation | maritime | event_monitors | media_verification | expert_context",
          "stance": "supports | contradicts | weak | unclear",
          "source_title": "...",
          "source_url": "...",
          "what_it_says": "short paraphrase",
          "is_fact_or_analysis": "fact | analysis"
        }}
      ],
      "credibility_signals": {{
        "independent_sources_count": 0,
        "has_primary_or_official": false,
        "has_major_outlets": false,
        "conflicts_found": false,
        "evidence_bucket_coverage": {{
          "official_primary": "covered | missing | not_relevant",
          "major_media": "covered | missing | not_relevant",
          "geoint": "covered | missing | not_relevant",
          "aviation": "covered | missing | not_relevant",
          "maritime": "covered | missing | not_relevant",
          "event_monitors": "covered | missing | not_relevant",
          "media_verification": "covered | missing | not_relevant",
          "expert_context": "covered | missing | not_relevant"
        }}
      }},
      "preliminary_likelihood": {{
        "label": "likely_true | unclear | likely_false",
        "confidence_0_100": 0,
        "why": "1-2 short sentences"
      }}
    }}
  ],
  "scenario_candidates": [
    {{
      "scenario": "a plausible scenario derived from the claims (neutral wording)",
      "key_drivers": ["..."],
      "what_would_confirm": ["..."],
      "what_would_falsify": ["..."]
    }}
  ],
  "global_notes": {{
    "what_is_most_solid": ["..."],
    "what_is_most_uncertain": ["..."],
    "missing_checks": ["..."]
  }},
  "pro_prompt": {{
    "system": "You are an evidence-based analyst. Do not browse. Use only the provided package.",
    "user": "Instructions for Pro: evaluate overall truth-likelihood AND estimate scenario probabilities by time horizon."
  }}
}}

User news text:
{user_news}

User links:
{links}
""".strip()

    parts: List[types.Part] = [types.Part(text=prompt)]
    for img_bytes in images[:8]:
        parts.append(types.Part(inline_data=types.Blob(mime_type="image/png", data=img_bytes)))

    resp = client.models.generate_content(
        model=FLASH_MODEL,
        contents=[types.Content(role="user", parts=parts)],
        config=config,
    )

    pkg = _safe_json_loads(resp.text)

    # merge extra grounded urls into input_summary.user_links (still within schema list[str])
    grounded_urls = _extract_grounding_urls(resp)
    if grounded_urls:
        existing = pkg["input_summary"].get("user_links", []) or []
        seen = set(existing)
        for u in grounded_urls:
            if u not in seen:
                seen.add(u)
                existing.append(u)
        pkg["input_summary"]["user_links"] = existing[:30]

    return pkg


# ----------------------------
# Pro (No tools) - final analysis + time-horizon probabilities
# ----------------------------
def pro_analyze_osint_package(pkg: Dict[str, Any]) -> str:
    config = types.GenerateContentConfig(temperature=0.2)

    # Force a specific output structure from Pro (text only displayed to user)
    payload = {
        "package": {
            "input_summary": pkg.get("input_summary", {}),
            "claims": pkg.get("claims", []),
            "scenario_candidates": pkg.get("scenario_candidates", []),
            "global_notes": pkg.get("global_notes", {}),
        },
        "output_rules": {
            "language": "Hebrew",
            "do_not_browse": True,
            "no_new_facts": True,
            "must_be_grounded_in_package": True,
            "format": {
                "part_1": "ONE paragraph summary (6-10 lines) about truth-likelihood & evidence quality",
                "part_2": "Time-horizon scenario probabilities table",
            },
            "probability_table": {
                "horizons": ["1_month", "3_months", "6_months", "12_months"],
                "scale": "0-100",
                "requirements": [
                    "give probabilities for each scenario in scenario_candidates",
                    "briefly justify with 1 short clause per scenario (based on evidence/drivers)",
                    "if evidence is weak -> keep probabilities conservative and say why"
                ]
            }
        }
    }

    resp = client.models.generate_content(
        model=PRO_MODEL,
        contents=[
            types.Content(role="system", parts=[types.Part(text=pkg["pro_prompt"]["system"])]),
            types.Content(role="user", parts=[types.Part(text=json.dumps(payload, ensure_ascii=False))]),
        ],
        config=config,
    )
    return (resp.text or "").strip()


# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="OSINT Verifier", layout="wide")
st.title("OSINT מנתח מקורות (Grounding פעם אחת → Pro בלי חיפוש + הסתברויות תרחישים)")

col1, col2 = st.columns([1, 1])

with col1:
    user_news = st.text_area("הדבק ידיעות/טענות:", height=220)
    links_text = st.text_area("הדבק קישורים (אפשר גם מעורב עם טקסט):", height=120)

with col2:
    uploaded = st.file_uploader(
        "העלה תצלומי מסך (PNG/JPG):",
        type=["png", "jpg", "jpeg"],
        accept_multiple_files=True,
    )
    st.caption("הסקרינשוטים משמשים כקלט לטענות; האימות נעשה מול OSINT באינטרנט.")

run_btn = st.button("הרץ ניתוח OSINT", type="primary", use_container_width=True)

if run_btn:
    if not (user_news.strip() or links_text.strip() or uploaded):
        st.error("אין קלט. תדביק טקסט/קישורים או תעלה סקרינשוטים.")
        st.stop()

    links = _clean_links(links_text)
    images = [f.read() for f in uploaded] if uploaded else []

    with st.spinner("שלב 1/2: Grounding + OSINT חיפוש דו-לשוני (Flash) ..."):
        try:
            pkg = flash_grounded_osint_package(user_news=user_news, links=links, images=images)
        except Exception as e:
            st.error(f"שגיאה בשלב ה-Grounding: {e}")
            st.stop()

    with st.spinner("שלב 2/2: ניתוח תרחישים והסתברויות (Pro ללא חיפוש) ..."):
        try:
            final_text = pro_analyze_osint_package(pkg)
        except Exception as e:
            st.error(f"שגיאה בשלב הניתוח: {e}")
            st.stop()

    st.subheader("תוצאה למשתמש")
    st.write(final_text)

    with st.expander("JSON שנשלח ל-Pro (Debug)"):
        st.json(pkg)

    # quick sources list
    srcs = pkg.get("input_summary", {}).get("user_links", []) or []
    if srcs:
        st.subheader("מקורות/לינקים שנאספו (Grounding)")
        for u in srcs[:30]:
            st.write(f"- {u}")
