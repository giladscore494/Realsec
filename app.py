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
    
    /* עיצוב מיוחד להודעת הצלחה בטעינת מפתח */
    .success-box {
        padding: 10px;
        background-color: #d4edda;
        color: #155724;
        border-radius: 5px;
        border: 1px solid #c3e6cb;
        text-align: right;
        margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

st.title("👁️ מערכת OSINT: חיזוי ותמונת מודיעין")
st.caption("מופעל על ידי הדור החדש: **Gemini 3 Pro Preview**")

# --- סרגל צד להגדרות ---
with st.sidebar:
    st.header("⚙️ הגדרות מבצעיות")
    
    # --- לוגיקה חכמה לטעינת מפתח API ---
    api_key = None
    
    # בדיקה האם המפתח קיים ב-Secrets
    if "GOOGLE_API_KEY" in st.secrets:
        api_key = st.secrets["GOOGLE_API_KEY"]
        st.markdown('<div class="success-box">✅ מפתח API נטען מהסודות</div>', unsafe_allow_html=True)
    else:
        # אם לא, בקש מהמשתמש להזין ידנית
        api_key = st.text_input("Google API Key", type="password")
        if not api_key:
            st.warning("⚠️ לא נמצא מפתח ב-Secrets. נא להזין ידנית.")
    
    st.divider()
    st.subheader("🧠 מודל ניתוח")
    
    # רשימת המודלים
    model_id = st.selectbox(
        "בחר מנוע בינה מלאכותית:",
        [
            "gemini-3-pro-preview",    # המודל החזק ביותר
            "gemini-3-flash-preview",  # מודל מהיר
            "gemini-2.0-flash-exp",    # גרסה יציבה ומהירה (גיבוי)
            "gemini-1.5-pro-latest"    # גרסת המורשת
        ],
        index=0
    )
    
    st.info(f"מודל פעיל: {model_id}")

    st.divider()
    st.subheader("📡 אינדיקטורים קשיחים (Hard Indicators)")
    ext_gps = st.checkbox("שיבושי GPS (אזורי/נרחב)")
    ext_notam = st.checkbox("סגירת נתיבי טיסה (NOTAMs)")
    ext_usa = st.checkbox("תזוזת כוחות אמריקאים (CENTCOM)")

# --- ממשק קלט ראשי ---
col1, col2 = st.columns(2)

with col1:
    st.subheader("📚 נתוני עבר (Baseline)")
    st.markdown("הודעות מהתקופה שקדמה לתקיפה הקודמת:")
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
    
    1. **Pattern Matching:** Identify semantic matches between A and B (phrasing, timing, source types).
    2. **Deviation Analysis:** What is MISSING today that was present then?
    3. **Red Team (Skeptic):** Argue why this is Psychological Warfare (PsyOps), not an attack.
    4. **Blue Team (Threat):** Argue why an attack is IMMINENT based on convergence of indicators.
    5. **Synthesis:** Determine timeline relative to the previous event.

    ### 4. Required Output Report (Hebrew):
    
    ## 📊 דוח הערכת מצב (Gemini 3 Analysis)
    
    **1. הסתברות לתקיפה בטווח המיידי:** [0-100%]
    
    **2. סטטוס מערכת:** (שגרה / מתיחות הונאתית / התרעה חמורה)
    
    **3. ניתוח פערים (Delta Analysis):**
    הסבר מפורט: מה ההבדל המרכזי בין "התחושה" בטלגרם אז לבין היום?
    
    **4. מיקום על ציר הזמן (Timeline):**
    "על פי ההשוואה ההיסטורית, דפוס הדיווחים תואם לנקודת ה-[X שעות/ימים] לפני האירוע הקודם."
    
    **5. 3 הסימנים המעידים החזקים ביותר כרגע:**
    - [סימן 1] (רמת אמינות: נמוכה/גבוהה)
    - [סימן 2]
    - [סימן 3]
    """

# --- כפתור הפעלה ולוגיקה ---
if st.button("🚀 הרץ ניתוח חיזוי (Gemini 3 Pro)", type="primary"):
    if not api_key:
        st.error("⚠️ לא זוהה מפתח API. נא להגדיר ב-Secrets או להזין ידנית.")
    elif not base_text or not current_text:
        st.warning("⚠️ חסר תוכן לניתוח. נא להזין טקסט בשתי התיבות.")
    else:
        try:
            status_text = f"Gemini 3 Pro מבצע הצלבת נתונים וניתוח הסתברותי..."
            with st.spinner(status_text):
                
                # יצירת קליינט עם המפתח שנמצא
                client = genai.Client(api_key=api_key)
                
                # קונפיגורציה
                config = types.GenerateContentConfig(
                    temperature=0.1,
                    top_p=0.90,
                    max_output_tokens=2048,
                )
                
                # בניית הפרומפט ושליחה
                final_prompt = build_intelligence_prompt(base_text, current_text, ext_gps, ext_notam, ext_usa)

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
                st.warning("המודל שנבחר אינו זמין בחשבון זה. נסה לבחור מודל אחר (כמו Flash 2.0).")
