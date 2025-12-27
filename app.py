import streamlit as st
from google import genai
from google.genai import types

# --- הגדרת עמוד ---
st.set_page_config(layout="wide", page_title="OSINT AI - Gemini 3")

# --- עיצוב CSS לממשק עברית מלא ומקצועי ---
st.markdown("""
<style>
    .stTextInput > label, .stTextArea > label, .stSelectbox > label { 
        direction: rtl; text-align: right; font-weight: bold; font-size: 1.1rem; 
    }
    .stMarkdown, div[data-testid="stSidebar"], div[data-testid="stText"] { 
        direction: rtl; text-align: right; 
    }
    .stButton > button { 
        width: 100%; border-radius: 8px; font-weight: bold; height: 3em; 
        background-color: #4285F4; color: white; border: none;
        transition: background-color 0.3s;
    }
    .stButton > button:hover { background-color: #3367D6; color: white; }
    h1, h2, h3 { text-align: right; }
    .stAlert { direction: rtl; text-align: right; }
</style>
""", unsafe_allow_html=True)

st.title("👁️ מערכת OSINT: חיזוי ותמונת מודיעין")
st.caption("מופעל על ידי הדור החדש: **Gemini 3 Pro Preview**")

# --- סרגל צד להגדרות ---
with st.sidebar:
    st.header("⚙️ הגדרות מבצעיות")
    api_key = st.text_input("Google API Key", type="password")
    
    st.divider()
    st.subheader("🧠 מודל ניתוח")
    
    # רשימת ה-IDs המדויקים והמעודכנים
    model_id = st.selectbox(
        "בחר מנוע בינה מלאכותית:",
        [
            "gemini-3-pro-preview",    # המודל החזק ביותר (Reasoning)
            "gemini-3-flash-preview",  # מהיר מאוד לכמויות מידע גדולות
            "gemini-2.0-flash-exp",    # גרסה יציבה ומהירה (גיבוי)
            "gemini-1.5-pro-latest"    # גרסת המורשת היציבה
        ],
        index=0,
        help="Gemini 3 Pro Preview הוא המומלץ ביותר לניתוח הסתברותי וזיהוי דפוסים מורכבים."
    )
    
    st.info(f"מודל פעיל: {model_id}")

    st.divider()
    st.subheader("📡 אינדיקטורים קשיחים (Hard Indicators)")
    st.caption("סמן אם יש אימות חיצוני לנתונים אלו:")
    ext_gps = st.checkbox("שיבושי GPS (אזורי/נרחב)")
    ext_notam = st.checkbox("סגירת נתיבי טיסה (NOTAMs)")
    ext_usa = st.checkbox("תזוזת כוחות אמריקאים (CENTCOM)")

# --- ממשק קלט ראשי ---
col1, col2 = st.columns(2)

with col1:
    st.subheader("📚 נתוני עבר (Baseline)")
    st.markdown("הודעות מהתקופה שקדמה לתקיפה הקודמת (לצורכי השוואה):")
    base_text = st.text_area("הדבק היסטוריה כאן", height=400, key="base", label_visibility="collapsed")

with col2:
    st.subheader("🔥 נתוני אמת (Current Ops)")
    st.markdown("הודעות ודיווחים מה-24 שעות האחרונות:")
    current_text = st.text_area("הדבק דיווחים עכשיוויים כאן", height=400, key="curr", label_visibility="collapsed")

# --- בניית הפרומפט האנליטי ---
def build_intelligence_prompt(base, current, gps, notam, usa):
    return f"""
    Role: Elite Intelligence Analyst using the '{model_id}' reasoning engine.
    Mission: Predict imminent Iranian military action by comparing current signals against historical precursors.

    ### 1. Hard Indicators (Verified Facts):
    - GPS Jamming Active: {gps}
    - Airspace Closures (NOTAM): {notam}
    - US Force Posture Changes: {usa}

    ### 2. The Raw Data:
    [DATASET A - HISTORICAL BASELINE (PRE-ATTACK)]:
    {base}

    [DATASET B - CURRENT SITUATION (LIVE)]:
    {current}

    ### 3. Analysis Protocol (Chain of Thought):
    Execute this logic precisely:
    
    1. **Pattern Matching:** Identify semantic matches between A and B (e.g., specific threat phrasing, timing of "sources" leaks, movement of launchers).
    2. **Deviation Analysis:** What is MISSING today that was present then? (Or vice versa).
    3. **Red Team (Skeptic):** Argue why this is Psychological Warfare (PsyOps) or internal propaganda, not an attack.
    4. **Blue Team (Threat):** Argue why an attack is IMMINENT based on the convergence of indicators.
    5. **Synthesis:** Determine where we sit on the timeline relative to the previous event.

    ### 4. Required Output Report (Hebrew):
    
    ## 📊 דוח הערכת מצב (Gemini 3 Analysis)
    
    **1. הסתברות לתקיפה בטווח המיידי:** [0-100%]
    
    **2. סטטוס מערכת:** (שגרה / מתיחות הונאתית / התרעה חמורה)
    
    **3. ניתוח פערים (Delta Analysis):**
    הסבר מפורט: מה ההבדל המרכזי בין "התחושה" בטלגרם אז לבין היום?
    
    **4. מיקום על ציר הזמן (Estimated Timeline):**
    "על פי ההשוואה ההיסטורית, דפוס הדיווחים הנוכחי תואם לנקודת ה-[X שעות/ימים] לפני האירוע הקודם."
    
    **5. 3 הסימנים המעידים החזקים ביותר כרגע:**
    - [סימן 1] (רמת אמינות: נמוכה/גבוהה)
    - [סימן 2]
    - [סימן 3]
    """

# --- כפתור הפעלה ולוגיקה ---
if st.button("🚀 הרץ ניתוח חיזוי (Gemini 3 Pro)", type="primary"):
    if not api_key:
        st.error("⚠️ נא להזין Google API Key בסרגל הצד.")
    elif not base_text or not current_text:
        st.warning("⚠️ חסר תוכן לניתוח. נא להזין טקסט בשתי התיבות.")
    else:
        try:
            status_text = f"Gemini 3 Pro מבצע הצלבת נתונים וניתוח הסתברותי..."
            with st.spinner(status_text):
                
                # יצירת קליינט ב-SDK החדש
                client = genai.Client(api_key=api_key)
                
                # קונפיגורציה מחמירה לדיוק מקסימלי
                config = types.GenerateContentConfig(
                    temperature=0.1,        # מינימום הזיות, מקסימום לוגיקה
                    top_p=0.90,
                    max_output_tokens=2048,
                    # תמיכה במחשבה עמוקה למודלים החדשים אם זמין בחשבון שלך
                    # thinking_config=types.ThinkingConfig(include_thoughts=False) 
                )
                
                # בניית הפרומפט
                final_prompt = build_intelligence_prompt(base_text, current_text, ext_gps, ext_notam, ext_usa)

                # שליחה למודל
                response = client.models.generate_content(
                    model=model_id,
                    contents=final_prompt,
                    config=config
                )
                
                # הצגת התוצאה
                st.success("✅ הניתוח הושלם.")
                
                with st.container():
                    st.markdown("---")
                    st.markdown(response.text)
                    st.markdown("---")
                    st.caption(f"Model ID: {model_id} | Status: Online")

        except Exception as e:
            st.error(f"❌ שגיאה: {e}")
            if "404" in str(e):
                st.warning("שגיאת 404: המודל gemini-3-pro-preview לא נמצא בחשבון שלך. נסה לעבור ל-gemini-2.0-flash-exp ברשימה.")
            else:
                st.info("וודא שה-API Key תקין ושיש לך גישה למודלים החדשים ב-Google AI Studio.")
