import streamlit as st
import datetime
import pandas as pd
import numpy as np
import time
import json
import sqlite3
import hashlib
import plotly.graph_objects as go
from urllib.parse import urlparse
from google import genai
from google.genai import types
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# --- הגדרת עמוד ---
st.set_page_config(layout="wide", page_title="OSINT Sentinel: Grounded")

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
    .risk-badge {
        padding: 3px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; color: white;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ OSINT Sentinel: מנוע מאומת (Grounded)")
st.caption("מערכת התרעה דטרמיניסטית עם אימות מקורות קשיח (Fail-Closed)")

# --- 1. ניהול Cache (SQLite) ---
DB_FILE = "osint_cache_v4_grounded.db"

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

# --- 2. עזרים: חילוץ Grounding ודומיינים ---
def _extract_grounded_urls(response) -> set:
    """מחלץ את ה-URLs האמיתיים שגוגל החזיר ב-Grounding Metadata"""
    urls = set()
    try:
        if not response.candidates: return urls
        gm = response.candidates[0].grounding_metadata
        if not gm: return urls
        
        chunks = getattr(gm, "grounding_chunks", [])
        for ch in chunks:
            if hasattr(ch, "web") and ch.web:
                uri = ch.web.uri
                if uri and uri.startswith("http"):
                    urls.add(uri)
    except Exception:
        pass
    return urls

def _get_domain(url: str) -> str:
    """מחלץ דומיין נקי (בלי www)"""
    try:
        d = urlparse(url).netloc.lower()
        return d[4:] if d.startswith("www.") else d
    except:
        return ""

# --- 3. הגדרות צד ---
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
    st.info("Scanner: Gemini 3 Flash (Grounded)")
    st.info("Analyst: Gemini 3 Pro (Inference)")
    
    tier1_domains = st.text_area("מקורות איכות (Tier 1 Domains):", 
                                 "reuters.com, apnews.com, bbc.com, ynet.co.il, haaretz.co.il, isna.ir, tasnimnews.com, jpost.com, timesofisrael.com",
                                 height=100)
    keywords = st.text_input("מילות חיפוש:", "Iran Israel military conflict missile attack nuclear")

# --- 4. מנוע איסוף (Fail-Closed) ---
def fetch_day_data(client, date_obj, keywords):
    date_str = date_obj.strftime('%Y-%m-%d')
    query_hash = hashlib.md5((date_str + keywords).encode()).hexdigest()
    
    cached = get_from_cache(date_str, query_hash)
    if cached: return cached, True

    # נעילת תאריך קשיחה (24 שעות)
    after = date_obj
    before = date_obj + datetime.timedelta(days=1)
    search_query = f"{keywords} after:{after} before:{before}"
    
    prompt = f"""
    ROLE: OSINT Data Extractor.
    TASK: Find specific news items for DATE: {date_str}.
    QUERY: "{search_query}"
    
    MANDATORY: Return a JSON object with a list of news items found.
    Each item must have: title, source, url, snippet.
    Use the provided Google Search tool.
    
    JSON Schema:
    {{
      "items": [
        {{ "title": "...", "source": "...", "url": "...", "snippet": "..." }}
      ]
    }}
    """
    
    try:
        # שימוש ב-Tool הרשמי החדש
        google_search_tool = types.Tool(google_search=types.GoogleSearch())
        
        response = client.models.generate_content(
            model="gemini-3-flash-preview", 
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.0,
                response_mime_type="application/json",
                tools=[google_search_tool]
            )
        )
        
        # 1. חילוץ ה-Grounding האמיתי
        grounded_urls = _extract_grounded_urls(response)
        
        # Fail-Closed: אם אין מקורות מאומתים - אין דאטה
        if not grounded_urls:
            empty_data = {"items": [], "error": "NO_GROUNDING_SOURCES"}
            save_to_cache(date_str, query_hash, empty_data)
            return empty_data, False
            
        # 2. סינון ה-JSON לפי המקורות
        try:
            raw_data = json.loads(response.text)
            validated_items = []
            
            for item in raw_data.get("items", []):
                item_url = item.get("url")
                # הוספנו פריט רק אם ה-URL שלו מופיע ברשימת ה-Grounding
                if item_url and item_url in grounded_urls:
                    validated_items.append(item)
            
            final_data = {"items": validated_items}
            save_to_cache(date_str, query_hash, final_data)
            return final_data, False
            
        except json.JSONDecodeError:
            return {"items": [], "error": "JSON_DECODE_ERROR"}, False
            
    except Exception as e:
        return {"items": [], "error": str(e)}, False

# --- 5. מנוע אנליטי (Deterministic) ---
def analyze_data_points(items, tier1_list):
    """חישוב מדדים מתמטי ללא AI עם Clustering משופר"""
    if not items:
        return {"volume": 0, "clusters": 0, "tier1_ratio": 0, "escalation_score": 0, "top_clusters": []}
    
    df = pd.DataFrame(items)
    df["title"] = df["title"].fillna("").astype(str)
    df["snippet"] = df["snippet"].fillna("").astype(str)
    df["url"] = df["url"].fillna("").astype(str)
    
    # הוספת דומיין וטקסט מלא
    df["domain"] = df["url"].apply(_get_domain)
    df["text"] = (df["title"] + " " + df["snippet"]).str.strip()
    
    # 1. Clustering אגנוסטי (Char N-grams)
    if len(df) > 1 and df["text"].str.len().sum() > 0:
        # שימוש ב-Character N-grams (3-5 תווים) עובד מעולה לשפות שמיות
        vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
        tfidf = vectorizer.fit_transform(df["text"])
        sim = cosine_similarity(tfidf)
        
        clusters = []
        visited = set()
        
        for i in range(len(df)):
            if i in visited: continue
            idxs = [i]
            visited.add(i)
            
            for j in range(i+1, len(df)):
                if j in visited: continue
                if sim[i][j] > 0.55: # סף דמיון
                    idxs.append(j)
                    visited.add(j)
            
            part = df.iloc[idxs]
            clusters.append({
                "main_title": part.iloc[0]["title"],
                "count": len(part),
                "domains": sorted(set(part["domain"].tolist()))
            })
    else:
        clusters = [{"main_title": df.iloc[0]["title"], "count": 1, "domains": [df.iloc[0]["domain"]]}]

    # 2. חישוב Tier 1 לפי דומיין
    tier1_set = {x.strip().lower().replace("www.", "") for x in tier1_list.split(",") if x.strip()}
    tier1_ratio = float(df["domain"].isin(tier1_set).mean()) if len(df) else 0.0

    # 3. חישוב ציון דטרמיניסטי
    unique_stories = len(clusters)
    avg_sources = (len(df) / unique_stories) if unique_stories else 0
    
    # הנוסחה: נפח ייחודי + בונוס איכות + בונוס עקביות
    score = (unique_stories * 4) + (tier1_ratio * 30) + (avg_sources * 5)
    
    return {
        "volume": int(len(df)),
        "clusters": int(unique_stories),
        "tier1_ratio": round(tier1_ratio, 2),
        "escalation_score": float(min(score, 100)),
        "top_clusters": sorted(clusters, key=lambda x: x["count"], reverse=True)[:3]
    }

# --- 6. לוגיקה ראשית ---
if st.button("🚀 הפעל ניתוח מאומת (Run Grounded Scan)", type="primary"):
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
        with col1: past_timeline = scan_timeline(attack_date, "Reference (Past)")
        with col2: curr_timeline = scan_timeline(today_date, "Live (Current)")
            
        status_text.empty()
        
        # --- ויזואליזציה ---
        st.divider()
        st.subheader("📈 מדד חריגות (Verified Sources Only)")
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=[x['day_offset'] for x in past_timeline], y=[x['score'] for x in past_timeline],
            name="Reference", line=dict(color='#ef5350', width=3, dash='dot')
        ))
        fig.add_trace(go.Scatter(
            x=[x['day_offset'] for x in curr_timeline], y=[x['score'] for x in curr_timeline],
            name="Current", line=dict(color='#4285f4', width=4)
        ))
        st.plotly_chart(fig, use_container_width=True)
        
        # --- סיכום מנהלים (Gemini 3 Pro - No Prediction) ---
        st.divider()
        st.subheader("🧠 הערכת מצב (Gemini 3 Pro)")
        
        past_vec = np.array([x['score'] for x in past_timeline])
        curr_vec = np.array([x['score'] for x in curr_timeline])
        correlation = np.corrcoef(past_vec, curr_vec)[0, 1] if np.std(past_vec) > 0 and np.std(curr_vec) > 0 else 0
        
        with st.spinner("Gemini 3 Pro מנתח חריגות..."):
            summary_prompt = f"""
            Act as a Senior Intelligence Officer.
            
            DATASET A (Reference Period): Correlation: {correlation:.2f}. Scores: {[x['score'] for x in past_timeline]}
            DATASET B (Current Period): Scores: {[x['score'] for x in curr_timeline]}
            
            Key Themes Past: {[x['top_stories'][0]['main_title'] for x in past_timeline if x['top_stories']]}
            Key Themes Current: {[x['top_stories'][0]['main_title'] for x in curr_timeline if x['top_stories']]}
            
            TASK:
            1. Analyze Anomaly Level: Is the current activity structurally similar to the reference period?
            2. Identify Drivers: What are the main clusters driving the score today?
            3. Certainty Assessment: Based on cluster density and Tier 1 sources coverage.
            
            DO NOT predict attacks or give dates. Focus on structural similarity of the signals.
            Output in Hebrew.
            """
            
            response = client.models.generate_content(
                model="gemini-3-pro-preview",
                contents=summary_prompt,
                config=types.GenerateContentConfig(temperature=0.2)
            )
            
            st.markdown(response.text)
