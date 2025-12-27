import streamlit as st
import datetime
import pandas as pd
import time
import plotly.graph_objects as go
from google import genai
from google.genai import types
import json

# --- הגדרת עמוד ---
st.set_page_config(layout="wide", page_title="OSINT Gemini 3 - Deep Scan")

# --- עיצוב CSS ---
st.markdown("""
<style>
    .stTextInput > label, .stSelectbox > label, .stDateInput > label, .stSlider > label { 
        direction: rtl; text-align: right; font-weight: bold; font-size: 1.1rem; 
    }
    .stMarkdown, div[data-testid="stSidebar"], div[data-testid="stText"], .stAlert, .stExpander { 
        direction: rtl; text-align: right; 
    }
    h1, h2, h3, h4 { text-align: right; }
    
    .source-link {
        font-size: 0.8em; color: #4285f4; text-decoration: none; display: block;
    }
    .source-link:hover { text-decoration: underline; }
    
    .day-card-risk-high { border-right: 5px solid #ff4444; padding-right: 10px; }
    .day-card-risk-med { border-right: 5px solid #ffa500; padding-right: 10px; }
    .day-card-risk-low { border-right: 5px solid #00c851; padding-right: 10px; }
</style>
""", unsafe_allow_html=True)

st.title("🕵️‍♂️ מערכת OSINT: השוואת דפוסים (Gemini 3 Engine)")
st.caption("סריקה יומית כירורגית עם חשיפת מקורות מלאה")

# --- סרגל צד ---
with st.sidebar:
    st.header("⚙️ הגדרות מנוע")
    
    api_key = st.secrets.get("GOOGLE_API_KEY")
    if not api_key:
        api_key = st.text_input("Google API Key", type="password")

    st.divider()
    st.subheader("📆 הגדרת זמנים")

    # עוגן עבר: 15 ביוני 2025
    attack_date = st.date_input("תאריך התקיפה (עבר):", value=datetime.date(2025, 6, 15))
    
    # עוגן הווה: היום
    today_date = st.date_input("תאריך נוכחי (הווה):", value=datetime.date(2025, 12, 27))
    
    # חלון סריקה - ברירת מחדל 33 יום
    scan_window = st.slider("טווח סריקה לאחור (ימים):", 10, 60, 33)

    st.divider()
    
    # בחירת המודל ללולאה (המהיר)
    loop_model = st.selectbox(
        "מודל סריקה יומית (Loop):",
        ["gemini-3-flash-preview", "gemini-2.0-flash-exp"],
        index=0,
        help="Gemini 3 Flash הוא המהיר והחזק ביותר לניתוח כמויות מידע."
    )
    
    # בחירת המודל לסיכום (החכם)
    reasoning_model = st.selectbox(
        "מודל סיכום והסקה (Brain):",
        ["gemini-3-pro-preview", "gemini-1.5-pro-latest"],
        index=0,
        help="Gemini 3 Pro הוא בעל יכולות ההסקה הגבוהות ביותר כרגע."
    )

    keywords = st.text_input("מילות מפתח:", value='Iran Israel conflict military tension attack')
    alert_threshold = st.slider("סף התראה (ציון):", 60, 95, 80)

# --- פונקציה לניתוח יום בודד + חילוץ מקורות ---
def analyze_single_day(client, date_obj, keywords, model):
    date_str = date_obj.strftime('%Y-%m-%d')
    
    prompt = f"""You are an intelligence analyst. 
    MANDATORY: Use Google Search to find news from exactly {date_str} about: {keywords}.
    Ignore news from other dates.

    Output JSON:
    {{
        "score": <0-100 escalation level>,
        "summary": "<1 sentence summary of the specific events of that day>",
        "key_event": "<Short title of main event>"
    }}
    """
    
    result = {"score": 0, "summary": "No data", "key_event": "-", "sources": []}
    
    try:
        response = client.models.generate_content(
            model=model,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.1,
                response_mime_type="application/json",
                tools=[{'google_search': {}}] # מחייב חיפוש
            )
        )
        
        # 1. חילוץ המידע הסמנטי
        try:
            data = json.loads(response.text)
            result.update(data)
        except:
            # Fallback ידני אם ה-JSON נשבר
            import re
            score_match = re.search(r'"score":\s*(\d+)', response.text)
            if score_match: result['score'] = int(score_match.group(1))
            result['summary'] = "Manual extraction from raw text"

        # 2. חילוץ מקורות (Grounding Metadata)
        # בודקים איפה Gemini החביא את הלינקים
        if response.candidates and response.candidates[0].grounding_metadata:
            chunks = response.candidates[0].grounding_metadata.grounding_chunks
            if chunks:
                for chunk in chunks:
                    if chunk.web:
                        result['sources'].append({
                            "title": chunk.web.title or "Source",
                            "url": chunk.web.uri
                        })
                        
    except Exception as e:
        result['summary'] = f"Error: {str(e)[:50]}"
        
    return result

# --- פונקציית עזר להצגת כרטיסייה יומית ---
def render_day_card(data):
    color_class = "day-card-risk-low"
    if data['score'] > 80: color_class = "day-card-risk-high"
    elif data['score'] > 50: color_class = "day-card-risk-med"
    
    with st.expander(f"{data['date']} | ציון: {data['score']} | {data['key_event']}", expanded=False):
        st.markdown(f"<div class='{color_class}'>{data['summary']}</div>", unsafe_allow_html=True)
        
        if data['sources']:
            st.markdown("---")
            st.caption("מקורות מידע:")
            for src in data['sources']:
                st.markdown(f"🔗 [{src['title']}]({src['url']})", unsafe_allow_html=True)
        else:
            st.caption("לא נמצאו מקורות דיגיטליים מאומתים.")

# --- לוגיקה ראשית ---
if st.button("🚀 הפעל סריקת עומק (Gemini 3)", type="primary"):
    if not api_key:
        st.error("חסר מפתח API")
    else:
        client = genai.Client(api_key=api_key)
        
        past_data = []
        curr_data = []
        
        col_past, col_curr = st.columns(2)
        
        # --- לולאת העבר ---
        with col_past:
            st.subheader(f"📜 יוני 2025 (לפני הפיצוץ)")
            prog1 = st.progress(0)
            status1 = st.empty()
            
            for i in range(scan_window, -1, -1):
                curr_date = attack_date - datetime.timedelta(days=i)
                status1.text(f"סורק: {curr_date.strftime('%d/%m/%Y')}...")
                prog1.progress((scan_window - i) / (scan_window + 1))
                
                res = analyze_single_day(client, curr_date, keywords, loop_model)
                res['date'] = curr_date.strftime('%d/%m')
                res['day_index'] = -(scan_window - i)
                past_data.append(res)
                
                # הצגה בזמן אמת
                render_day_card(res)
                # time.sleep(0.1) # אופציונלי: למנוע חסימה אם יש הרבה בקשות
            
            st.success("סריקת עבר הושלמה")

        # --- לולאת ההווה ---
        with col_curr:
            st.subheader(f"🔴 דצמבר 2025 (המצב כרגע)")
            prog2 = st.progress(0)
            status2 = st.empty()
            
            for i in range(scan_window, -1, -1):
                curr_date = today_date - datetime.timedelta(days=i)
                status2.text(f"סורק: {curr_date.strftime('%d/%m/%Y')}...")
                prog2.progress((scan_window - i) / (scan_window + 1))
                
                res = analyze_single_day(client, curr_date, keywords, loop_model)
                res['date'] = curr_date.strftime('%d/%m')
                res['day_index'] = -(scan_window - i)
                curr_data.append(res)
                
                render_day_card(res)
                
            st.success("סריקת הווה הושלמה")

        # --- גרף השוואתי ---
        st.divider()
        st.header("📈 גרף הלימה (Correlation Graph)")
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=[d['day_index'] for d in past_data], y=[d['score'] for d in past_data],
            mode='lines+markers', name='יוני 2025 (עבר)', line=dict(color='#ff4444', width=3)
        ))
        fig.add_trace(go.Scatter(
            x=[d['day_index'] for d in curr_data], y=[d['score'] for d in curr_data],
            mode='lines+markers', name='דצמבר 2025 (הווה)', line=dict(color='#33b5e5', width=3)
        ))
        fig.add_hline(y=alert_threshold, line_dash="dash", line_color="orange")
        st.plotly_chart(fig, use_container_width=True)
        
        # --- סיכום Gemini 3 Pro ---
        st.divider()
        st.header(f"🧠 מוח על ({reasoning_model})")
        
        with st.spinner("Gemini 3 Pro מחשב את ההסתברות למלחמה..."):
            # הכנת נתונים מצומצמים לניתוח כדי לא לחרוג מ-Token Limit
            min_past = [{'day': d['day_index'], 'score': d['score'], 'event': d['key_event']} for d in past_data]
            min_curr = [{'day': d['day_index'], 'score': d['score'], 'event': d['key_event']} for d in curr_data]
            
            prompt = f"""
            Role: Chief Intelligence Officer.
            Task: Compare two timelines to predict war.
            
            Timeline A (The buildup to the June 2025 Attack):
            {json.dumps(min_past, ensure_ascii=False)}
            
            Timeline B (The Current Situation - Dec 2025):
            {json.dumps(min_curr, ensure_ascii=False)}
            
            Question:
            Does Timeline B mathematically and thematically match the slope of Timeline A?
            
            Output (Hebrew):
            1. **Match Score:** (0-100% similarity).
            2. **Analysis:** Compare the daily escalation pace.
            3. **Verdict:** Are we X days away from an attack like in June?
            """
            
            resp = client.models.generate_content(
                model=reasoning_model, # שימוש במודל הפרו החזק
                contents=prompt,
                config=types.GenerateContentConfig(temperature=0.2)
            )
            st.markdown(resp.text)
