import streamlit as st
import google.generative_ai as genai

st.set_page_config(layout="wide", page_title="OSINT AI - Predictive Analysis")

# עיצוב מתקדם
st.markdown("""
<style>
    .stTextInput > label, .stTextArea > label { direction: rtl; text-align: right; font-weight: bold; }
    .stMarkdown, div[data-testid="stSidebar"] { direction: rtl; text-align: right; }
    .stButton > button { width: 100%; border-radius: 10px; font-weight: bold; }
    div[data-testid="stMetricValue"] { font-size: 1.5rem; }
</style>
""", unsafe_allow_html=True)

st.title("👁️ מערכת OSINT: חיזוי מבצעי מבוסס טקסט")
st.caption("Powered by Gemini 3 | כולל מנגנון Red-Teaming וניתוח אינדיקטורים קשיחים")

# --- סרגל צד ---
with st.sidebar:
    st.header("⚙️ הגדרות מבצעיות")
    api_key = st.text_input("Google API Key", type="password")
    
    model_type = st.selectbox(
        "מנוע ניתוח:",
        ["gemini-3-pro", "gemini-3-deep-think"], 
        index=0
    )
    
    st.divider()
    st.subheader("פרמטרים נוספים לחיזוי")
    # הוספת מידע חיצוני שהטקסט אולי מפספס
    ext_gps = st.checkbox("האם יש דיווחים על שיבושי GPS חריגים?")
    ext_notam = st.checkbox("האם יצאו NOTAMs (סגירת מרחב אווירי)?")
    ext_usa = st.checkbox("האם יש תזוזת כוחות אמריקאים באזור?")

# --- קלט ---
col1, col2 = st.columns(2)
with col1:
    st.subheader("📚 טקסט בסיס (Reference)")
    base_text = st.text_area("הדבק היסטוריה (לפני אירוע עבר)", height=350, key="base")
    if base_text:
        st.info(f"אורך טקסט: {len(base_text.split())} מילים")

with col2:
    st.subheader("🔥 טקסט נוכחי (Live Feed)")
    current_text = st.text_area("הדבק נתונים מהשעות האחרונות", height=350, key="curr")
    if current_text:
        st.warning(f"אורך טקסט: {len(current_text.split())} מילים")

# --- הפרומפט המקצועי (הסוד לדיוק) ---
def build_advanced_prompt(base, current, gps, notam, usa):
    return f"""
    You are a Senior Intelligence Analyst utilizing the 'Gemini 3' engine.
    Your goal is to predict an Iranian military strike with maximum precision by analyzing Open Source Intelligence (OSINT).

    ### 1. The Hard Data (Indicators)
    User Reporting:
    - GPS Jamming Present: {gps}
    - Airspace Closures (NOTAMs): {notam}
    - US Force Movement: {usa}

    ### 2. The Textual Data
    [HISTORICAL BASELINE (PRE-ATTACK)]:
    {base}

    [CURRENT SITUATION]:
    {current}

    ### 3. Analysis Protocol (Chain of Thought)
    You must follow this exact 4-step reasoning process:

    **Step 1: Indicator Extraction**
    Scan the [CURRENT SITUATION] text for these specific Hard Indicators:
    - Keywords: "Ballistic", "Launchers", "IRGC Official Statement", "Shelters", "Cyber Attack".
    - Ignore generic threats ("We will crush you") unless accompanied by specific operational details.

    **Step 2: The 'Red Team' Challenge (Devil's Advocate)**
    Formulate an argument for why *NO* attack is imminent.
    - Could this be Psychological Warfare (PsyOps)?
    - Are the sources bots or reliable reporters?
    - Compare the volume/panic level to the [HISTORICAL BASELINE]. Is it actually quieter/noisier than the real attack pre-conditions?

    **Step 3: The 'Blue Team' Assessment**
    Formulate an argument for why an attack *IS* imminent.
    - Does the timeline match the previous attack's buildup?
    - Do the User Reported Indicators (GPS/NOTAM) corroborate the text?

    **Step 4: Final Synthesis & Prediction**
    Weigh Step 2 vs Step 3.

    ### 4. Required Output Format (Hebrew)
    
    ## 📊 דוח הערכת מצב
    
    **1. מדד הסתברות לתקיפה (0-100%):** [מספר]%
    
    **2. ניתוח פערים (Delta Analysis):**
    הסבר מנומק: מה ההבדל הקריטי בין הטקסטים של אז להיום? (למשל: "אז דיברו על הזזת כוחות, היום מדברים רק על נקמה כללית").

    **3. אימות צוות אדום (Red Team Check):**
    "הסיבה המרכזית לחשוב שזו רק לוחמה פסיכולוגית היא: [הסיבה]"

    **4. מיקום על ציר הזמן:**
    "על פי ההשוואה ההיסטורית, אנו נמצאים כרגע בנקודה המקבילה ל-[X] שעות לפני האירוע." (או: "אין התאמה לציר הזמן של תקיפה").

    **5. המלצת האנליסט:**
    משפט אחד תכליתי לדרג המקבל החלטות.
    """

# --- כפתור הפעלה ---
if st.button("🚀 הרץ ניתוח מודיעיני משולב", type="primary"):
    if not api_key or not base_text or not current_text:
        st.error("חסרים נתונים (API Key או טקסטים).")
    else:
        try:
            with st.spinner('מפעיל פרוטוקול ניתוח מתקדם (כולל Red Teaming)...'):
                genai.configure(api_key=api_key)
                
                # הגדרות מחמירות לדיוק
                generation_config = {"temperature": 0.1, "top_p": 0.85} 
                model = genai.GenerativeModel(model_type, generation_config=generation_config)
                
                prompt = build_advanced_prompt(base_text, current_text, ext_gps, ext_notam, ext_usa)
                response = model.generate_content(prompt)
                
                st.success("הניתוח הסתיים.")
                st.markdown(response.text)
                
        except Exception as e:
            st.error(f"שגיאה: {e}")