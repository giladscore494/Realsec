import os
import json
import re
from typing import Any, Dict, List

import streamlit as st
from google import genai
from google.genai import types

# ----------------------------
# Config & Client
# ----------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# הגדרת המודלים בדיוק כפי שביקשת
FLASH_MODEL = os.getenv("FLASH_MODEL", "gemini-3-flash-preview")
PRO_MODEL   = os.getenv("PRO_MODEL",   "gemini-3-pro-preview")

if not GEMINI_API_KEY:
    st.error("Missing GEMINI_API_KEY. Please set it in your environment.")
    st.stop()

client = genai.Client(api_key=GEMINI_API_KEY)

# רשימת מקורות לניטור פייק ניוז
FACT_CHECK_SITES = [
    "FakeReporter.net", "Irrelevant.org.il", "TheWhistle (Globes)", 
    "Snopes", "Bellingcat", "CheckYourFact", "FullFact.org"
]

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
    # הסרת סממני Markdown אם קיימים
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s).strip()
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        # ניסיון חילוץ JSON מתוך טקסט חופשי
        m = re.search(r"(\{.*\})", s, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except:
                pass
        return {"error": "Failed to parse JSON", "raw": s}

def _extract_grounding_urls(resp: Any) -> List[str]:
    urls = []
    try:
        if resp.candidates:
            gm = resp.candidates[0].grounding_metadata
            if gm and gm.grounding_chunks:
                for chunk in gm.grounding_chunks:
                    if chunk.web and chunk.web.uri:
                        urls.append(chunk.web.uri)
    except Exception:
        pass
    return list(dict.fromkeys(urls))

# ----------------------------
# Step 1: Source Discovery (Flash Model)
# ----------------------------
def run_flash_source_discovery(user_news: str, links: List[str], images: List[bytes]) -> Dict[str, Any]:
    search_tool = types.Tool(google_search=types.GoogleSearch())

    prompt = f"""
You are the Search & Source Discovery Engine (Running on {FLASH_MODEL}).
Your goal is to find primary sources, verify claims, and check against disinformation databases.

TASKS:
1. IMAGE ANALYSIS: Extract text/OCR and describe visual evidence.
2. DUAL-LANGUAGE SEARCH: Search in Hebrew and English.
3. FAKE NEWS FILTER: Explicitly check if these claims appear on: {FACT_CHECK_SITES}.
4. BUCKET CLASSIFICATION: Group findings into: Official, Media, Geolocation, and Expert Analysis.

OUTPUT: Return a STRICT JSON object only.
"""

    parts = [types.Part(text=prompt), types.Part(text=f"Text: {user_news}\nLinks: {links}")]
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
        pkg["verified_links"] = _extract_grounding_urls(resp)
        return pkg
    except Exception as e:
        # החזרת שגיאה מפורטת במידה והמודל לא נמצא
        return {"error": f"Flash Model Error ({FLASH_MODEL}): {str(e)}", "verified_links": []}

# ----------------------------
# Step 2: Strategic Analysis (Pro Model)
# ----------------------------
def run_pro_strategic_analysis(pkg: Dict[str, Any]) -> str:
    system_instruction = "You are a Strategic Analyst. Use ONLY the provided search results to build your report."

    user_prompt = f"""
נתח את ה-Data Package הבא והפק דו"ח מודיעיני:
{json.dumps(pkg, ensure_ascii=False)}

הדו"ח חייב לכלול:
1. הערכת אמינות (Likelihood) בסולם 0-100.
2. זיהוי סתירות מובנות במידע (Contradiction Matrix).
3. ניתוח תרחישים עתידיים (1-12 חודשים).
4. ציון מפורש אם מדובר במידע כוזב (Disinformation) על בסיס הממצאים.

כתוב בעברית אנליטית ומקצועית.
"""
    try:
        resp = client.models.generate_content(
            model=PRO_MODEL,
            contents=[types.Content(role="user", parts=[types.Part(text=user_prompt)])],
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.2
            ),
        )
        return resp.text
    except Exception as e:
        return f"Pro Model Error ({PRO_MODEL}): {str(e)}"

# ----------------------------
# Streamlit Interface
# ----------------------------
st.set_page_config(page_title="Gemini 3 OSINT", layout="wide")

st.title("🛡️ Gemini 3 OSINT Engine")
st.caption(f"Configured Models: Flash='{FLASH_MODEL}' | Pro='{PRO_MODEL}'")

with st.sidebar:
    st.header("מקורות בדיקה")
    st.write(FACT_CHECK_SITES)
    st.divider()
    if st.button("בדוק מודלים זמינים בחשבון"):
        try:
            models = client.models.list_models()
            st.write([m.name for m in models])
        except Exception as e:
            st.error(f"Error listing models: {e}")

col1, col2 = st.columns([1, 1])

with col1:
    user_text = st.text_area("הכנס טקסט / ידיעה לבדיקה:", height=250)
    user_links = st.text_area("קישורים (אופציונלי):", height=100)

with col2:
    uploaded = st.file_uploader("העלה תמונות / סקרינשוטים:", type=["png", "jpg", "jpeg"], accept_multiple_files=True)

if st.button("בצע חקירה רב-שכבתית", type="primary", use_container_width=True):
    if not user_text and not uploaded:
        st.error("יש להזין קלט כלשהו.")
    else:
        links = _clean_links(user_links)
        imgs = [f.read() for f in uploaded] if uploaded else []

        with st.status(f"מפעיל את {FLASH_MODEL} ו-{PRO_MODEL}...") as status:
            
            # שלב 1: Flash
            st.write(f"🕵️ מפעיל Source Discovery ({FLASH_MODEL})...")
            data_package = run_flash_source_discovery(user_text, links, imgs)
            
            # בדיקת שגיאות קריטית
            if "error" in data_package and not data_package.get("verified_links"):
                st.error(f"תקלה בשלב ה-Flash: {data_package['error']}")
                st.stop()

            # שלב 2: Pro
            st.write(f"📊 מפעיל Strategic Analysis ({PRO_MODEL})...")
            final_report = run_pro_strategic_analysis(data_package)
            
            status.update(label="הניתוח הושלם", state="complete")

        # UI: התרעת פייק ניוז
        is_fake = data_package.get("known_hoax_check", {}).get("is_known_fake", False)
        if is_fake:
            st.error(f"🛑 **אזהרה:** המידע זוהה כפייק ניוז: {data_package['known_hoax_check'].get('details')}")

        # UI: הצגת הדו"ח
        st.markdown("### 📋 דו\"ח ניתוח סופי")
        st.markdown(final_report)

        # UI: הרחבות (Expanders)
        with st.expander("🔗 לינקים שאומתו בחיפוש"):
            for l in data_package.get("verified_links", []):
                st.write(f"- {l}")

        with st.expander("⚙️ נתוני גלם (JSON Package)"):
            st.json(data_package)
