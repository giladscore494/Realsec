
import streamlit as st
import datetime
import pandas as pd
import time
import plotly.graph_objects as go
from google import genai
from google.genai import types
import json

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
    
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        text-align: center;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    
    .alert-box {
        background-color: #ff4444;
        color: white;
        padding: 15px;
        border-radius: 8px;
        font-weight: bold;
        text-align: center;
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.7; }
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
    attack_date = st.date_input("תאריך התקיפה (בעבר):", value=datetime.date(2024, 4, 13))
    
    # תקופת ההווה
    today_date = st.date_input("תאריך היום (הווה):", value=datetime.date.today())
    
    # כמה ימים אחורה לסרוק?
    scan_window = st.slider("חלון סריקה (ימים אחורה):", min_value=3, max_value=14, value=7)
    
    st.divider()
    
    model_id = st.selectbox(
        "מודל סריקה:",
        ["gemini-2.0-flash-exp", "gemini-1.5-flash"],
        help="מומלץ להשתמש ב-Flash בגלל כמות הקריאות הגדולה"
    )

    keywords = st.text_input("מילות מפתח:", value='Iran Israel conflict military tension attack')
    
    st.divider()
    st.subheader("🎯 סף התראה")
    alert_threshold = st.slider("הפעל התראה אם הציון עובר:", 60, 95, 80)

# --- פונקציה לניתוח יום בודד ---
def analyze_single_day(client, date_obj, keywords, model):
    """מבצע חיפוש וניתוח עבור תאריך ספציפי"""
    date_str = date_obj.strftime('%Y-%m-%d')
    
    prompt = f"""You are an intelligence analyst. Analyze news from {date_str} about: {keywords}

Rate the escalation level (0-100) where:
- 0-30: Normal diplomatic activity
- 31-60: Elevated tensions/rhetoric
- 61-80: Serious threats/military posturing
- 81-100: Imminent conflict indicators

Return ONLY valid JSON:
{{"score": <number>, "summary": "<one sentence>"}}"""
    
    try:
        response = client.models.generate_content(
            model=model,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.1,
                response_mime_type="application/json",
                tools=[{'google_search': {}}]
            )
        )
        
        # ניסיון לפרסר JSON
        result = json.loads(response.text)
        
        # ולידציה
        if not isinstance(result.get('score'), (int, float)):
            result['score'] = 0
        if not isinstance(result.get('summary'), str):
            result['summary'] = "No data available"
            
        return result
        
    except json.JSONDecodeError:
        # אם הJSON לא תקין, נסה לחלץ ציון מהטקסט
        try:
            text = response.text
            score = 0
            if '"score":' in text:
                score = int(text.split('"score":')[1].split(',')[0].strip())
            return {"score": score, "summary": "Parse error - using extracted score"}
        except:
            return {"score": 0, "summary": "Error parsing response"}
    except Exception as e:
        return {"score": 0, "summary": f"API Error: {str(e)[:50]}"}

# --- חישוב מטריקות ---
def calculate_metrics(data):
    """מחשב מדדים סטטיסטיים"""
    scores = [d['score'] for d in data]
    
    avg = sum(scores) / len(scores) if scores else 0
    max_score = max(scores) if scores else 0
    
    # חישוב שיפוע (Slope) - האם יש מגמת עלייה?
    if len(scores) >= 2:
        slope = (scores[-1] - scores[0]) / len(scores)
    else:
        slope = 0
    
    # זיהוי קפיצות חדות (Spike Detection)
    spikes = []
    for i in range(1, len(scores)):
        if scores[i] - scores[i-1] > 20:
            spikes.append(i)
    
    return {
        'avg': round(avg, 1),
        'max': max_score,
        'slope': round(slope, 2),
        'spikes': spikes,
        'trend': 'עולה 📈' if slope > 2 else 'יורדת 📉' if slope < -2 else 'יציבה ➡️'
    }

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
        
        # --- לולאה 1: העבר ---
        with status_col1:
            st.subheader("📜 סריקת העבר (Baseline)")
            prog_bar1 = st.progress(0)
            log_area1 = st.empty()
            
            for i in range(scan_window, -1, -1):
                current_loop_date = attack_date - datetime.timedelta(days=i)
                
                prog = (scan_window - i) / (scan_window + 1)
                prog_bar1.progress(min(prog, 1.0))
                log_area1.markdown(f"⏳ {current_loop_date.strftime('%d/%m/%Y')}...")
                
                result = analyze_single_day(client, current_loop_date, keywords, model_id)
                
                past_data.append({
                    "date": current_loop_date.strftime('%d/%m'),
                    "full_date": current_loop_date,
                    "day_index": -(scan_window - i),
                    "score": result['score'],
                    "summary": result['summary']
                })
                time.sleep(0.5)
            
            st.success(f"✅ {len(past_data)} ימים נסרקו")

        # --- לולאה 2: ההווה ---
        with status_col2:
            st.subheader("🔴 סריקת ההווה (Live)")
            prog_bar2 = st.progress(0)
            log_area2 = st.empty()
            
            for i in range(scan_window, -1, -1):
                current_loop_date = today_date - datetime.timedelta(days=i)
                
                prog = (scan_window - i) / (scan_window + 1)
                prog_bar2.progress(min(prog, 1.0))
                log_area2.markdown(f"⏳ {current_loop_date.strftime('%d/%m/%Y')}...")
                
                result = analyze_single_day(client, current_loop_date, keywords, model_id)
                
                curr_data.append({
                    "date": current_loop_date.strftime('%d/%m'),
                    "full_date": current_loop_date,
                    "day_index": -(scan_window - i),
                    "score": result['score'],
                    "summary": result['summary']
                })
                time.sleep(0.5)
            
            st.success(f"✅ {len(curr_data)} ימים נסרקו")

        # --- חישוב מטריקות ---
        past_metrics = calculate_metrics(past_data)
        curr_metrics = calculate_metrics(curr_data)

        # --- תצוגת מטריקות ---
        st.divider()
        st.header("📊 מטריקות השוואתיות")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("ממוצע - עבר", f"{past_metrics['avg']}", 
                     delta=None, delta_color="off")
        with col2:
            st.metric("ממוצע - הווה", f"{curr_metrics['avg']}", 
                     delta=f"{curr_metrics['avg'] - past_metrics['avg']:+.1f}")
        with col3:
            st.metric("שיפוע - עבר", past_metrics['trend'])
        with col4:
            st.metric("שיפוע - הווה", curr_metrics['trend'])

        # --- אזהרה אם עברנו סף ---
        if curr_metrics['max'] >= alert_threshold:
            st.markdown(f"""
            <div class="alert-box">
                ⚠️ התראה: זוהה ציון {curr_metrics['max']} (מעל הסף {alert_threshold})
            </div>
            """, unsafe_allow_html=True)

        # --- גרף אינטראקטיבי ---
        st.divider()
        st.header("📈 השוואת מגמות (Interactive)")
        
        fig = go.Figure()
        
        # קו עבר
        fig.add_trace(go.Scatter(
            x=[d['day_index'] for d in past_data],
            y=[d['score'] for d in past_data],
            mode='lines+markers',
            name=f'התקיפה ב-{attack_date.strftime("%d/%m/%Y")}',
            line=dict(color='red', width=3),
            marker=dict(size=8),
            hovertemplate='<b>יום %{x}</b><br>ציון: %{y}<extra></extra>'
        ))
        
        # קו הווה
        fig.add_trace(go.Scatter(
            x=[d['day_index'] for d in curr_data],
            y=[d['score'] for d in curr_data],
            mode='lines+markers',
            name=f'מצב נוכחי ({today_date.strftime("%d/%m/%Y")})',
            line=dict(color='blue', width=3),
            marker=dict(size=8),
            hovertemplate='<b>יום %{x}</b><br>ציון: %{y}<extra></extra>'
        ))
        
        # קו סף התראה
        fig.add_hline(y=alert_threshold, line_dash="dash", 
                     line_color="orange", annotation_text="סף התראה")
        
        fig.update_layout(
            title="השוואת דפוסי הסלמה",
            xaxis_title="ימים לפני האירוע (0 = יום התקיפה/היום)",
            yaxis_title="רמת הסלמה (0-100)",
            hovermode='x unified',
            height=500,
            showlegend=True
        )
        
        st.plotly_chart(fig, use_container_width=True)

        # --- טבלה מפורטת ---
        with st.expander("📄 נתונים גולמיים"):
            c1, c2 = st.columns(2)
            with c1:
                st.subheader("עבר")
                df_past = pd.DataFrame(past_data)[['date', 'score', 'summary']]
                st.dataframe(df_past, use_container_width=True)
            with c2:
                st.subheader("הווה")
                df_curr = pd.DataFrame(curr_data)[['date', 'score', 'summary']]
                st.dataframe(df_curr, use_container_width=True)

        # --- ניתוח מפקד סופי ---
        st.divider()
        st.header("🧠 ניתוח דפוסים סופי (AI Synthesis)")
        
        with st.spinner("מנתח קורלציות ומזהה חריגות..."):
            
            final_prompt = f"""אתה אנליסט מודיעין בכיר. נערכה סריקה יומית של שתי תקופות:

תקופה A (עבר - הובילה לתקיפה ב-{attack_date}):
ממוצע: {past_metrics['avg']}, שיפוע: {past_metrics['slope']}, מקסימום: {past_metrics['max']}
נתונים יומיים: {json.dumps([{{'יום': d['day_index'], 'ציון': d['score']}} for d in past_data], ensure_ascii=False)}

תקופה B (הווה - עד {today_date}):
ממוצע: {curr_metrics['avg']}, שיפוע: {curr_metrics['slope']}, מקסימום: {curr_metrics['max']}
נתונים יומיים: {json.dumps([{{'יום': d['day_index'], 'ציון': d['score']}} for d in curr_data], ensure_ascii=False)}

שאלות מרכזיות:
1. האם המגמה הנוכחית דומה למגמה שהובילה לתקיפה?
2. האם קצב ההסלמה (שיפוע) דומה?
3. האם יש ימים חריגים שבולטים?
4. לפי התבנית ההיסטורית, היכן אנחנו על ציר הזמן?

ענה בעברית, בפורמט:
### 📌 השוואת מגמות
[ניתוח]

### ⚠️ זיהוי אנומליות
[ימים חריגים ומדוע]

### 🎯 מסקנה
[האם אנחנו על מסלול דומה? מהי רמת הסיכון?]

### 🕐 מיקום על ציר הזמן
[אם נשווה לעבר, היכן אנחנו בתהליך?]"""

            final_resp = client.models.generate_content(
                model="gemini-1.5-pro-latest",
                contents=final_prompt,
                config=types.GenerateContentConfig(temperature=0.2)
            )
            
            st.markdown(final_resp.text)
            
        # --- הורדת דוח ---
        st.divider()
        report = f"""דוח סריקת OSINT - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}

תקופות שנבדקו:
- עבר: {scan_window} ימים לפני {attack_date}
- הווה: {scan_window} ימים לפני {today_date}

מטריקות:
{json.dumps({'past': past_metrics, 'current': curr_metrics}, ensure_ascii=False, indent=2)}

ניתוח AI:
{final_resp.text}

נתונים גולמיים:
PAST: {json.dumps(past_data, ensure_ascii=False, indent=2)}
CURRENT: {json.dumps(curr_data, ensure_ascii=False, indent=2)}
"""
        
        st.download_button(
            "💾 הורד דוח מלא",
            report,
            file_name=f"osint_timeloop_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.txt",
            mime="text/plain"
        )