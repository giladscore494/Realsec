import os
import json
import re
import datetime
from typing import Any, Dict, List

import streamlit as st
from google import genai
from google.genai import types

# ----------------------------
# Config & Client
# ----------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# מודלים
FLASH_MODEL = os.getenv("FLASH_MODEL", "gemini-3-flash-preview")
PRO_MODEL   = os.getenv("PRO_MODEL",   "gemini-3-pro-preview")

if not GEMINI_API_KEY:
    st.error("Missing GEMINI_API_KEY. Please set it in your environment.")
    st.stop()

client = genai.Client(api_key=GEMINI_API_KEY)

# רשימת מקורות לניטור פייק ניוז
FACT_CHECK_SITES = [
    "FakeReporter.net", "Irrelevant.org.il", "TheWhistle (Globes)", 
    "Snopes", "Bellingcat", "CheckYourFact", "FullFact.org", "Abu Ali Express"
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
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s).strip()
    try:
        return json.loads(s)
    except json.JSONDecodeError:
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
# Step 1: Source Discovery (Flash Model - HARD SIGNALS & OSINT)
# ----------------------------
def run_flash_source_discovery(user_news: str, links: List[str], images: List[bytes]) -> Dict[str, Any]:
    search_tool = types.Tool(google_search=types.GoogleSearch())
    
    current_date = datetime.datetime.now().strftime("%Y-%m-%d")

    # פרומפט משודרג עם התמקדות ב"סימנים מעידים" (Hard Indicators)
    prompt = f"""
You are an Elite Military Intelligence Collector (OSINT) running on {FLASH_MODEL}.
Current Date: {current_date}.

YOUR MISSION: Validate the event and collect "Hard Signals" (Indicators & Warnings).
Do not just look for headlines. Look for LOGISTICS and PHYSICAL movements.

SEARCH STRATEGY (Force these queries):
1.  **Social Media**: Use `site:twitter.com` and `site:t.me` to find real-time reports.
2.  **Hard Indicators**:
    -   GPS Jamming reports (Waze/Maps anomalies).
    -   Hospital preparations (transfer to underground wards).
    -   Flight restrictions (NOTAMs).
    -   Reserve call-ups (Tzav 8).
    -   Embassy warnings / Evacuations.

OUTPUT FORMAT (STRICT JSON):
{{
  "event_summary": "Concise summary of the situation",
  "hard_indicators": {{
      "logistics_status": "Description of supply/hospital/transport status found",
      "military_movements": "Description of any troop/tank/plane movements reported",
      "civilian_impact": "GPS jamming, school cancellations, etc."
  }},
  "social_media_intel": {{
      "telegram_chatter": ["Specific claims from Telegram"],
      "twitter_signals": ["Specific claims from X"]
  }},
  "source_reliability": "High/Medium/Low based on cross-referencing",
  "contradictions": ["List if official news contradicts social media"],
  "known_hoax_check": {{
      "is_fake": boolean,
      "details": "Explanation if fake"
  }}
}}
"""

    parts = [types.Part(text=prompt), types.Part(text=f"Subject to Investigate: {user_news}\nLinks provided: {links}")]
    for img in images[:8]:
        parts.append(types.Part(inline_data=types.Blob(mime_type="image/png", data=img)))

    config = types.GenerateContentConfig(
        tools=[search_tool],
        temperature=0.0, # אפס יצירתיות, רק עובדות
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
        return {"error": f"Flash Model Error: {str(e)}", "verified_links": []}

# ----------------------------
# Step 2: Strategic Analysis (Pro Model - ACH METHODOLOGY)
# ----------------------------
def run_pro_strategic_analysis(pkg: Dict[str, Any]) -> str:
    system_instruction = "You are a Senior Intelligence Assessment Officer using the 'Analysis of Competing Hypotheses' (ACH) method."

    user_prompt = f"""
נתח את ה-Data Package הבא והפק דו"ח הערכת מלחמה.
התבסס אך ורק על המידע שנאסף:
{json.dumps(pkg, ensure_ascii=False)}

עליך לבצע תהליך חשיבה של "איפכא מסתברא" (Devil's Advocate) לפני קביעת ההסתברות.

מבנה הדו"ח (חובה להקפיד על הסדר):

1. **סטטוס סימנים מעידים (Hard Signals Status)**:
   האם נמצאו הוכחות לוגיסטיות בשטח? (בתי חולים, גיוס מילואים, שיבושי GPS). אם לא נמצאו, ציין זאת בבירור.

2. **ניתוח השערות מתחרות (ACH Analysis)**:
   - *השערה א' (הסלמה למלחמה):* מה תומך בזה?
   - *השערה ב' (לוחמה פסיכולוגית/רעש):* מה תומך בזה?
   - *הכרעה:* איזה צד חזק יותר בראיות?

3. **טבלת סבירות למלחמה (The Probability Matrix)**:
   צור טבלת Markdown:
   | טווח זמן | סבירות (%) | נימוק מודיעיני (Evidence Based) | רמת ביטחון בהערכה |
   |---|---|---|---|
   | מיידי (עד חודש) | % | ... | ... |
   | קצר (3 חודשים) | % | ... | ... |
   | בינוני (6 חודשים) | % | ... | ... |
   | ארוך (שנה) | % | ... | ... |

   *כלל ברזל לקביעת אחוזים:* אם אין סימנים לוגיסטיים (דלק, בתי חולים, תחמושת) - הסבירות למלחמה מיידית חייבת להיות נמוכה, גם אם הרטוריקה בטוויטר גבוהה.

4. **מסקנה למקבל ההחלטות**: שורה תחתונה ברורה.

כתוב בעברית מודיעינית, קרה ומדויקת.
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
        return f"Pro Model Error: {str(e)}"

# ----------------------------
# Streamlit Interface
# ----------------------------
st.set_page_config(page_title="Gemini 3 OSINT War Room", layout="wide", page_icon="📡")

st.markdown("""
<style>
    .stTextArea textarea { font-size: 16px !important; }
    .stAlert { direction: rtl; }
</style>
""", unsafe_allow_html=True)

st.title("📡 Gemini 3 Advanced OSINT & War Predictor")
st.caption(f"Engine: {FLASH_MODEL} (Collector) -> {PRO_MODEL} (Analyst) | Method: ACH & Hard Signals")

with st.sidebar:
    st.header("מערך איסוף")
    st.info("המערכת סורקת באופן יזום: \n- Twitter/X \n- Telegram Channels \n- Official Reports \n- Fact Checkers")
    st.divider()
    st.write("**מקורות אימות:**", FACT_CHECK_SITES)

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("📝 הזנת מידע")
    user_text = st.text_area("נושא החקירה (טקסט חופשי / שמועה):", height=200, placeholder="לדוגמה: דיווחים בטלגרם על תנועת כוחות חריגה בגבול הצפון...")
    user_links = st.text_area("קישורים ספציפיים (אופציונלי):", height=100)

with col2:
    st.subheader("📷 ראיות ויזואליות")
    uploaded = st.file_uploader("העלה צילומי מסך/מפות:", type=["png", "jpg", "jpeg"], accept_multiple_files=True)
    if uploaded:
        st.success(f"{len(uploaded)} קבצים נטענו לניתוח")

if st.button("🚀 הרץ הערכת מודיעין מלאה", type="primary", use_container_width=True):
    if not user_text and not uploaded:
        st.error("חובה להזין טקסט או להעלות תמונה.")
    else:
        links = _clean_links(user_links)
        imgs = [f.read() for f in uploaded] if uploaded else []

        # קונטיינר לתהליך
        with st.status("מבצע נוהל קרב מודיעיני...", expanded=True) as status:
            
            # שלב 1
            st.write("📡 **Flash:** סריקת רשתות, איתור סימנים מעידים (GPS, לוגיסטיקה)...")
            data_package = run_flash_source_discovery(user_text, links, imgs)
            
            if "error" in data_package and not data_package.get("verified_links"):
                status.update(label="שגיאה באיסוף", state="error")
                st.error(f"תקלה: {data_package['error']}")
                st.stop()
            
            # הצגת ממצאי ביניים
            inds = data_package.get("hard_indicators", {})
            st.markdown(f"""
            - **ממצאים לוגיסטיים:** {len(inds.get('logistics_status', '')) > 5}
            - **שיח בטלגרם/טוויטר:** {len(data_package.get('social_media_intel', {}).get('telegram_chatter', []))} פריטים
            """)

            # שלב 2
            st.write("🧠 **Pro:** ביצוע ניתוח השערות מתחרות (ACH) וחישוב הסתברות...")
            final_report = run_pro_strategic_analysis(data_package)
            
            status.update(label="הערכת המצב הושלמה", state="complete")

        # הצגת תוצאות
        st.divider()
        
        # אזהרת פייק
        if data_package.get("known_hoax_check", {}).get("is_fake"):
            st.error(f"🚨 **מדובר בחדשות כזב (Fake News):** {data_package['known_hoax_check']['details']}")
        
        st.markdown("## 📊 דו\"ח מודיעין מסכם")
        st.markdown(final_report)

        # הרחבות
        with st.expander("🔍 נתונים גולמיים מהשטח (JSON)"):
            st.json(data_package)
            
        with st.expander("🔗 מקורות מידע שאומתו"):
            for link in data_package.get("verified_links", []):
                st.markdown(f"- [{link}]({link})")
