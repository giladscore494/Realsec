import streamlit as st
import datetime
import pandas as pd
import numpy as np
import time
import json
import sqlite3
import hashlib
import plotly.graph_objects as go
from google import genai
from google.genai import types
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# --- הגדרת עמוד ---
st.set_page_config(layout="wide", page_title="OSINT Sentinel: Gemini 3")

# --- עיצוב CSS ---
st.markdown("""
<style>
    .stTextInput > label, .stSelectbox > label, .stDateInput > label, .stSlider > label { 
        direction: rtl; text-align: right; font-weight: bold; 
    }
    .stMarkdown, div[data-testid="stSidebar"], div[data-testid="stText"], .stExpander { 
        direction: rtl; text-align: right; 
    }
    h1, h2, h3, h4 { text-align: right; }
    
    .cluster-card {
        border-right: 3px solid #4285f4; padding-right: 10px; margin-bottom: 10px;
        background-color: #ffffff; padding: 8px; border-radius: 4px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ OSINT Sentinel: מנוע Gemini 3")
st.caption("מערכת התרעה דטרמיניסטית המופעלת על ידי Gemini 3 Flash & Pro")

# --- 1. ניהול Cache (SQLite) ---
DB_FILE = "osint_cache_v3.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS daily_scans
                 (scan_date TEXT, query_hash TEXT, raw_json TEXT, updated_at TIMESTAMP)''')
    conn.commit()
    conn.close()

def get_from_cache(date_str, query_hash):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT raw_json FROM daily_scans WHERE scan_date=? AND query_hash=?", (date_str, query_hash))
    data = c.fetchone()
    conn.close()
    return json.loads(data[0]) if data else None

def save_to_cache(date_str, query_hash, data):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM daily_scans WHERE scan_date=? AND query_hash=?", (date_str, query_hash))
    c.execute("INSERT INTO daily_scans VALUES (?, ?, ?, ?)", 
              (date_str, query_hash, json.dumps(data), datetime.datetime.now()))
    conn.commit()
    conn.close()

init_db()

# --- 2. הגדרות צד ---
with st.sidebar:
    st.header("⚙️ הגדרות סנסור")
    api_key = st.secrets.get("GOOGLE_API_KEY") or st.text_input("Google API Key", type="password")
    
    st.divider()
    st.subheader("📡 טווחי זמן")
    attack_date = st.date_input("תאריך אירוע עבר (Reference):", datetime.date(2025, 6, 15))
    today_date = st.date_input("תאריך נוכחי (Live):", datetime.date(2025, 12, 28))
    window = st.slider("חלון סריקה (ימים):", 7, 45, 20)
    
    st.divider()
    st.subheader("🎛️ מודלים ופרמטרים")
    st.info("Scanner: Gemini 3 Flash Preview")
    st.info("Analyst: Gemini 3 Pro Preview")
    
    tier1_domains = st.text_area("מקורות איכות (Tier 1):", 
                                 "reuters.com, apnews.com, bbc.com, ynet.co.il, haaretz.co.il, isna.ir, tasnimnews.com",
                                 height=70)
    keywords = st.text_input("מילות חיפוש:", "Iran Israel military conflict missile attack nuclear")

# --- 3. מנוע איסוף (Gemini 3 Flash) ---
def fetch_day_data(client, date_obj, keywords):
    date_str = date_obj.strftime('%Y-%m-%d')
    query_hash = hashlib.md5((date_str + keywords).encode()).hexdigest()
    
    cached = get_from_cache(date_str, query_hash)
    if cached: return cached, True

    # שאילתת תאריך קשיחה
    search_query = f"{keywords} after:{date_obj - datetime.timedelta(days=1)} before:{date_obj + datetime.timedelta(days=1)}"
    
    prompt = f"""
    ROLE: OSINT Data Extractor.
    TASK: Use Google Search to find specific news items for DATE: {date_str}.
    QUERY: "{search_query}"
    
    INSTRUCTIONS:
    1. Retrieve a list of distinct news items / reports from that specific day.
    2. Ignore generic opinion pieces; focus on factual events.
    3. Return ONLY a JSON object with this schema:
    
    {{
      "items": [
        {{
          "title": "Headline",
          "source": "Publisher Name",
          "url": "Link",
          "snippet": "Short summary",
          "published_date": "YYYY-MM-DD"
        }}
      ]
    }}
    """
    
    try:
        # שימוש במודל Gemini 3 Flash Preview לאיסוף מהיר
        response = client.models.generate_content(
            model="gemini-3-flash-preview", 
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.0,
                response_mime_type="application/json",
                tools=[{'google_search': {}}]
            )
        )
        
        data = json.loads(response.text)
        save_to_cache(date_str, query_hash, data)
        return data, False
        
    except Exception as e:
        return {"items": [], "error": str(e)}, False

# --- 4. מנוע אנליטי (Python Deterministic) ---
def analyze_data_points(items, tier1_list):
    """חישוב מדדים מתמטי ללא AI"""
    if not items:
        return {"volume": 0, "clusters": 0, "tier1_ratio": 0, "escalation_score": 0, "top_clusters": []}
    
    df = pd.DataFrame(items)
    df['text'] = df['title'] + " " + df['snippet'].fillna("")
    
    # Clustering (Deduplication)
    if len(df) > 1:
        vectorizer = TfidfVectorizer(stop_words='english')
        tfidf_matrix = vectorizer.fit_transform(df['text'])
        cosine_sim = cosine_similarity(tfidf_matrix)
        
        clusters = []
        visited = set()
        
        for i in range(len(df)):
            if i in visited: continue
            cluster_indices = [i]
            visited.add(i)
            for j in range(i+1, len(df)):
                if j in visited: continue
                if cosine_sim[i][j] > 0.6: # סף דמיון
                    cluster_indices.append(j)
                    visited.add(j)
            
            cluster_items = df.iloc[cluster_indices]
            clusters.append({
                "main_title": cluster_items.iloc[0]['title'],
                "count": len(cluster_items),
                "sources": cluster_items['source'].unique().tolist()
            })
    else:
        clusters = [{"main_title": df.iloc[0]['title'], "count": 1, "sources": [df.iloc[0]['source']]}]

    # חישוב ציון דטרמיניסטי
    unique_stories = len(clusters)
    tier1_sources = [s.strip().lower() for s in tier1_list.split(',')]
    tier1_count = df['source'].astype(str).apply(lambda x: any(t in x.lower() for t in tier1_sources)).sum()
    tier1_ratio = round(tier1_count / len(df), 2) if len(df) > 0 else 0
    avg_sources = len(df) / unique_stories if unique_stories > 0 else 0
    
    # הנוסחה המתמטית
    score = (unique_stories * 4) + (tier1_ratio * 30) + (avg_sources * 5)
    
    return {
        "volume": len(df),
        "clusters": unique_stories,
        "escalation_score": min(score, 100),
        "top_clusters": sorted(clusters, key=lambda x: x['count'], reverse=True)[:3]
    }

# --- 5. לוגיקה ראשית ---
if st.button("🚀 הפעל ניתוח (Gemini 3 Engine)", type="primary"):
    if not api_key:
        st.error("חסר מפתח API")
    else:
        client = genai.Client(api_key=api_key)
        
        status_text = st.empty()
        prog_bar = st.progress(0)
        
        total_steps = (window + 1) * 2
        step_counter = 0
        
        def scan_timeline(anchor_date, label):
            timeline_data = []
            nonlocal step_counter
            for i in range(window, -1, -1):
                target_date = anchor_date - datetime.timedelta(days=i)
                status_text.markdown(f"**{label}**: סורק את {target_date.strftime('%d/%m/%Y')}...")
                
                raw_data, is_cached = fetch_day_data(client, target_date, keywords)
                analytics = analyze_data_points(raw_data.get('items', []), tier1_domains)
                
                timeline_data.append({
                    "day_offset": -i,
                    "date": target_date.strftime('%d/%m'),
                    "score": analytics['escalation_score'],
                    "top_stories": analytics['top_clusters']
                })
                
                step_counter += 1
                prog_bar.progress(step_counter / total_steps)
                if not is_cached: time.sleep(0.5)
            return timeline_data

        col1, col2 = st.columns(2)
        with col1: past_timeline = scan_timeline(attack_date, "Reference")
        with col2: curr_timeline = scan_timeline(today_date, "Current")
            
        status_text.empty()
        
        # --- ויזואליזציה ---
        st.divider()
        st.subheader("📈 השוואת מדד חריגות (Escalation Index)")
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=[x['day_offset'] for x in past_timeline], y=[x['score'] for x in past_timeline],
            name="Reference (Past)", line=dict(color='#ef5350', width=3, dash='dot')
        ))
        fig.add_trace(go.Scatter(
            x=[x['day_offset'] for x in curr_timeline], y=[x['score'] for x in curr_timeline],
            name="Live (Current)", line=dict(color='#4285f4', width=4)
        ))
        st.plotly_chart(fig, use_container_width=True)
        
        # --- סיכום מנהלים (Gemini 3 Pro) ---
        st.divider()
        st.subheader("🧠 סיכום אנליסט (Gemini 3 Pro)")
        
        past_vec = np.array([x['score'] for x in past_timeline])
        curr_vec = np.array([x['score'] for x in curr_timeline])
        correlation = np.corrcoef(past_vec, curr_vec)[0, 1] if np.std(past_vec) > 0 and np.std(curr_vec) > 0 else 0
        
        with st.spinner("Gemini 3 Pro מבצע הערכת מצב..."):
            summary_prompt = f"""
            Act as a Senior Intelligence Officer.
            
            DATASET A (Past Conflict): Correlation: {correlation:.2f}. Scores: {[x['score'] for x in past_timeline]}
            DATASET B (Current): Scores: {[x['score'] for x in curr_timeline]}
            
            Key Themes Past: {[x['top_stories'][0]['main_title'] for x in past_timeline if x['top_stories']]}
            Key Themes Current: {[x['top_stories'][0]['main_title'] for x in curr_timeline if x['top_stories']]}
            
            TASK:
            1. Analyze mathematical similarity. Is the current slope steeper?
            2. Compare Themes. Are we seeing similar military indicators?
            3. Verdict: Is the anomaly resembling the pre-attack indicators?
            
            Output in Hebrew.
            """
            
            # שימוש במודל Gemini 3 Pro Preview לסיכום
            response = client.models.generate_content(
                model="gemini-3-pro-preview",
                contents=summary_prompt,
                config=types.GenerateContentConfig(temperature=0.2)
            )
            
            st.markdown(response.text)
