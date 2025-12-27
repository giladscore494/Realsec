import streamlit as st
import datetime
import pandas as pd
import time
from google import genai
from google.genai import types

# --- הגדרת עמוד ---
st.set_page_config(layout="wide", page_title="OSINT Time-Loop Agent")

# --- עיצוב CSS ---
st.markdown("""
<style>
    .stTextInput > label, .stSelectbox > label, .stDateInput > label, .stSlider > label { 
        direction: rtl; text-align: right; font-weight: bold; font-size: 1.1rem; 
    }
    .stMarkdown, div[data-testid="stSidebar"], div[data-testid="stText"], .stAlert { 
        direction: rtl; text-align: right; 
    }
    h1, h2, h3, h4 { text-align: right; }
    
    /* עיצוב לוגים */
    .log-line {
        font-family: monospace; font-size: 0.8em; color: #333;
        border-bottom: 1px solid #eee; padding: 2px; direction: ltr; text-align: left;
    }
</style>
""", unsafe_allow_html=True)

st.title("🕵️‍♂️ סוכן לולאת-זמן (Trend Hunter)")
st.caption("ניתוח מגמות יומי: סריקה כרונולוגית לזיהוי תבניות הסלמה")

# --- סרגל צד ---
with st.sidebar:
    st.header("⚙️ הגדרות סריקה")
    
    # טעינת מפתח
    api_key = st.secrets.get("GOOGLE_API_KEY")
    if not api_key:
        api_key = st.text_input("Google API Key", type="password")

    st.divider()
    
    # הגדרת תאריכי יעד
    st.subheader("📆 הגדרת זמנים")
    
    # תקופת העבר (האירוע)
    attack_date = st.date_input("תאריך התקיפה (בעבר):", value=datetime.date(2025, 6, 15))
    
    # תקופת ההווה
    today_date = st.date_input("תאריך היום (הווה):", value=datetime.date(2025, 12, 28))
    
    # כמה ימים אחורה לסרוק?
    scan_window = st.slider("חלון סריקה (ימים אחורה):", min_value=5, max_value=20, value=7)
    
    st.divider()
    
    model_id = st.selectbox(
        "מודל סריקה:",
        ["gemini-2.0-flash-exp", "gemini-1.5-flash"], # Flash מומלץ ללולאות מהירות
        help="מומלץ להשתמש ב-Flash בגלל כמות הקריאות הגדולה"
    )

    keywords = st.text_input("מילות מפתח:", value='איראן, ישראל, משמרות המהפכה, תקיפה, נשק, דיפלומטיה')

# --- פונקציה לניתוח יום בודד ---
def analyze_single_day(client, date_obj, keywords):
    """
    מבצע חיפוש וניתוח עבור תאריך ספציפי אחד.
    מחזיר: ציון (0-100) וסיכום קצר.
    """
    date_str = date_obj.strftime('%Y-%m-%d')
    
    # השאילתה לגוגל
    query = f"News Israel Iran conflict on {date_str}. Keywords: {keywords}"
    
    prompt = f"""
    Analyze news from this specific date: {date_str}.
    Query results provided by tool.
    
    Task:
    1. Determine the "Escalation Level" (Stress/Threats) on this specific day on a scale of 0 to 100.
    2. Provide a 1-sentence summary of the main event that day.
    
    Output format: JSON
    {{ "score": int, "summary": "string" }}
    """
    
    try:
        response = client.models.generate_content(
            model=model_id,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.0,
                response_mime_type="application/json",
                tools=[{'google_search': {}}] # חיפוש ליום ספציפי
            )
        )
        import json
        return json.loads(response.text)
    except Exception as e:
        return {"score": 0, "summary": f"Error: {str(e)}"}

# --- לוגיקה ראשית ---
if st.button("🚀 הפעל לולאת סריקה (Past vs Present)", type="primary"):
    if not api_key:
        st.error("חסר מפתח API")
    else:
        client = genai.Client(api_key=api_key)
        
        # הכנת מבני הנתונים
        past_data = []
        curr_data = []
        
        # יצירת המכולות לתצוגה
        status_col1, status_col2 = st.columns(2)
        
        # --- לולאה 1: העבר (Reference Loop) ---
        with status_col1:
            st.subheader("סריקת העבר (Baseline)")
            prog_bar1 = st.progress(0)
            log_area1 = st.empty()
            
            for i in range(scan_window, -1, -1): # ספירה לאחור
                current_loop_date = attack_date - datetime.timedelta(days=i)
                
                # עדכון ויזואלי
                prog = (scan_window - i) / scan_window
                prog_bar1.progress(min(prog, 1.0))
                log_area1.markdown(f"⏳ סורק: {current_loop_date.strftime('%d/%m/%Y')}...")
                
                # הפעלת המודל ליום זה
                result = analyze_single_day(client, current_loop_date, keywords)
                
                past_data.append({
                    "date": current_loop_date.strftime('%d/%m'),
                    "day_index": scan_window - i, # ימים לפני ה-0
                    "score": result['score'],
                    "summary": result['summary']
                })
                time.sleep(1) # מניעת חסימת API
            
            st.success("הושלם!")

        # --- לולאה 2: ההווה (Current Loop) ---
        with status_col2:
            st.subheader("סריקת ההווה (Live)")
            prog_bar2 = st.progress(0)
            log_area2 = st.empty()
            
            for i in range(scan_window, -1, -1):
                current_loop_date = today_date - datetime.timedelta(days=i)
                
                prog = (scan_window - i) / scan_window
                prog_bar2.progress(min(prog, 1.0))
                log_area2.markdown(f"⏳ סורק: {current_loop_date.strftime('%d/%m/%Y')}...")
                
                result = analyze_single_day(client, current_loop_date, keywords)
                
                curr_data.append({
                    "date": current_loop_date.strftime('%d/%m'),
                    "day_index": scan_window - i,
                    "score": result['score'],
                    "summary": result['summary']
                })
                time.sleep(1)
            
            st.success("הושלם!")

        # --- ויזואליזציה וניתוח ---
        st.divider()
        st.header("📈 השוואת מגמות (Trend Analysis)")
        
        # המרת נתונים לגרף
        df_past = pd.DataFrame(past_data).rename(columns={"score": "Past Escalation"})
        df_curr = pd.DataFrame(curr_data).rename(columns={"score": "Current Escalation"})
        
        # איחוד לפי האינדקס (יום 1 בסריקה, יום 2 בסריקה...)
        chart_data = pd.DataFrame({
            "Day Index": range(len(past_data)),
            "June 2025 (Past)": df_past["Past Escalation"],
            "Dec 2025 (Current)": df_curr["Current Escalation"]
        }).set_index("Day Index")
        
        st.line_chart(chart_data, color=["#FF0000", "#0000FF"]) # אדום לעבר, כחול להווה
        
        # הצגת טבלה מפורטת
        with st.expander("📄 צפה בנתונים הגולמיים לכל יום"):
            c1, c2 = st.columns(2)
            with c1:
                st.write("היסטוריה:")
                st.dataframe(df_past)
            with c2:
                st.write("הווה:")
                st.dataframe(df_curr)

        # --- סיכום המפקד (Gemini Pro Synthesis) ---
        st.subheader("🧠 ניתוח דפוסים סופי (Gemini Pro)")
        
        with st.spinner("מנתח את הגרפים ומזהה קורלציות..."):
            # כאן אנחנו שולחים את כל הנתונים המעובדים למודל החזק
            final_prompt = f"""
            You are a Military Intelligence Analyst.
            I have performed a day-by-day scan of two periods.
            
            PERIOD A (Past - Leading to Attack):
            {past_data}
            
            PERIOD B (Current - Now):
            {curr_data}
            
            TASK:
            Look at the TRENDS (Slope of escalation).
            1. In Period A, notice how the score changed day by day.
            2. Compare it to the trajectory of Period B.
            
            QUESTION:
            Are we following the same mathematical trajectory towards an attack?
            
            OUTPUT (Hebrew):
            1. **ניתוח המגמה:** האם הגרף הנוכחי "תלול" כמו הגרף של העבר?
            2. **זיהוי אנומליות:** האם יש יום ספציפי השבוע ששבר את השגרה?
            3. **מסקנה:** האם אנחנו לקראת התנגשות?
            """
            
            # שימוש במודל חזק לסיכום (אפשר להחליף ל-Pro)
            final_resp = client.models.generate_content(
                model="gemini-1.5-pro-latest", 
                contents=final_prompt
            )
            
            st.markdown(final_resp.text)
