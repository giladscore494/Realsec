import streamlit as st
import datetime
import pandas as pd
import numpy as np
import time
import json
import sqlite3
import hashlib
import plotly.graph_objects as go
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from google import genai
from google.genai import types
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# --- הגדרת עמוד ---
st.set_page_config(layout="wide", page_title="OSINT Sentinel: Production")

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
        border-right: 3px solid #4285f4; padding-right: 10px; margin-bottom: 8px;
        background-color: #f8f9fa; padding: 8px; border-radius: 4px; font-size: 0.9em;
    }
    .debug-info {
        font-size: 0.75em; color: #666; margin-top: -10px; margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ OSINT Sentinel: מנוע מבצעי")
st.caption("מערכת I&W דטרמיניסטית: נרמול מקורות, דה-דופליקציה ומדדי ביטחון")

# --- 1. ניהול Cache (SQLite Upsert) ---
DB_FILE = "osint_prod_v1.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # שימוש ב-PRIMARY KEY מורכב למניעת כפילויות וביצועים מהירים
    c.execute('''CREATE TABLE IF NOT EXISTS daily_scans
                 (scan_date TEXT, query_hash TEXT, raw_json TEXT, updated_at TIMESTAMP,
                  PRIMARY KEY (scan_date, query_hash))''')
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
    # UPSERT יעיל
    c.execute("""
        INSERT OR REPLACE INTO daily_scans (scan_date, query_hash, raw_json, updated_at)
        VALUES (?, ?, ?, ?)
    """, (date_str, query_hash, json.dumps(data), datetime.datetime.now()))
    conn.commit()
    conn.close()

init_db()

# --- 2. עזרים: נרמול URL ודומיינים ---
def _get_domain(url: str) -> str:
    try:
        if not url: return ""
        d = urlparse(url).netloc.lower()
        return d[4:] if d.startswith("www.") else d
    except:
        return ""

def _normalize_url(u: str) -> str:
    """נרמול אגרסיבי להשוואה חכמה"""
    try:
        if not u: return ""
        p = urlparse(u.strip())
        netloc = p.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        
        path = p.path.rstrip("/")
        
        # הסרת פרמטרים של מעקב בלבד
        q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
             if not k.lower().startswith(("utm_", "fbclid", "gclid", "ref"))]
        query = urlencode(q, doseq=True)
        
        return urlunparse((p.scheme.lower() or "https", netloc, path, "", query, ""))
    except:
        return u or ""

def _extract_grounded_urls(response) -> tuple[set, set]:
    """מחזיר שני סטים: URLs מנורמלים ודומיינים (ל-Relaxed Matching)"""
    urls_norm = set()
    domains = set()
    try:
        if not response.candidates: return urls_norm, domains
        gm = response.candidates[0].grounding_metadata
        if not gm: return urls_norm, domains
        
        chunks = getattr(gm, "grounding_chunks", [])
        for ch in chunks:
            if hasattr(ch, "web") and ch.web:
                uri = ch.web.uri
                if uri and uri.startswith("http"):
                    urls_norm.add(_normalize_url(uri))
                    domains.add(_get_domain(uri))
    except Exception:
        pass
    return urls_norm, domains

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
                                 "reuters.com, apnews.com, bbc.com, ynet.co.il, haaretz.co.il, isna.ir, tasnimnews.com, jpost.com, timesofisrael.com, cnn.com, aljazeera.com",
                                 height=100)
    keywords = st.text_input("מילות חיפוש:", "Iran Israel military conflict missile attack nuclear")

# --- 4. מנוע איסוף (Smart Filter & Debug) ---
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
        
        # 1. חילוץ המקורות המאומתים (נרמול + דומיינים)
        grounded_norm, grounded_domains = _extract_grounded_urls(response)
        
        # דיבאג: מה המודל החזיר ב-JSON הגולמי?
        try:
            raw_data = json.loads(response.text)
            raw_items = raw_data.get("items", [])
        except:
            raw_items = []

        validated_items = []
        
        # 2. סינון חכם (Exact Norm -> Domain Relaxed)
        for item in raw_items:
            u = item.get("url", "")
            if not u: continue
            
            u_norm = _normalize_url(u)
            u_domain = _get_domain(u)
            
            # בדיקה מדויקת (מנורמלת)
            if u_norm in grounded_norm:
                validated_items.append(item)
            # בדיקה רכה (דומיין בלבד)
            elif u_domain in grounded_domains:
                validated_items.append(item)
        
        # שמירת מטא-דאטה לדיבאג
        debug_stats = {
            "fetched": len(raw_items),
            "grounded_sources": len(grounded_norm),
            "validated": len(validated_items)
        }
        
        final_data = {"items": validated_items, "debug": debug_stats}
        
        # אם אין ולידציה - שומרים ריק אבל עם סטטוס
        if not validated_items and raw_items:
            final_data["error"] = "VALIDATION_FAILED"
            
        save_to_cache(date_str, query_hash, final_data)
        return final_data, False
            
    except Exception as e:
        return {"items": [], "error": str(e), "debug": {}}, False

# --- 5. מנוע אנליטי (Confidence + Anti-Syndication) ---
def analyze_data_points(items, tier1_list):
    if not items:
        return {"volume": 0, "clusters": 0, "tier1_ratio": 0, "escalation_score": 0, "confidence": 0, "top_clusters": []}
    
    df = pd.DataFrame(items)
    df["title"] = df["title"].fillna("").astype(str)
    df["snippet"] = df["snippet"].fillna("").astype(str)
    df["url"] = df["url"].fillna("").astype(str)
    
    df["domain"] = df["url"].apply(_get_domain)
    df["text"] = (df["title"] + " " + df["snippet"]).str.strip()
    
    # 1. Clustering אגנוסטי (Char N-grams)
    if len(df) > 1 and df["text"].str.len().sum() > 0:
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
                if sim[i][j] > 0.55:
                    idxs.append(j)
                    visited.add(j)
            
            part = df.iloc[idxs]
            # חישוב דומיינים ייחודיים באשכול למניעת סינדיקציה
            unique_domains_in_cluster = part["domain"].nunique()
            
            clusters.append({
                "main_title": part.iloc[0]["title"],
                "count": len(part),
                "unique_domains": unique_domains_in_cluster,
                "domains": sorted(set(part["domain"].tolist()))
            })
    else:
        clusters = [{"main_title": df.iloc[0]["title"], "count": 1, "unique_domains": 1, "domains": [df.iloc[0]["domain"]]}]

    # 2. חישובים
    tier1_set = {x.strip().lower().replace("www.", "") for x in tier1_list.split(",") if x.strip()}
    tier1_ratio = float(df["domain"].isin(tier1_set).mean()) if len(df) else 0.0
    unique_stories = len(clusters)
    
    # חישוב עקביות חכם (מוגבל תקרה 4)
    # סופרים כמה דומיינים שונים בממוצע יש לכל סיפור, לא כמה פריטים
    total_unique_domains = sum(c['unique_domains'] for c in clusters)
    avg_sources_per_story = min((total_unique_domains / unique_stories), 4) if unique_stories else 0

    # נוסחת Escalation Index
    score = (unique_stories * 4) + (tier1_ratio * 30) + (avg_sources_per_story * 5)
    
    # 3. מדד ביטחון (Confidence Score) דטרמיניסטי
    # גבוה אם: יש קלאסטרים, יחס Tier1 גבוה, ונפח סביר
    raw_vol_factor = min(1.0, len(df) / 8) # מנורמל ל-8 כתבות
    clusters_factor = min(1.0, unique_stories / 5)
    
    confidence = (0.35 * clusters_factor) + (0.45 * tier1_ratio) + (0.20 * raw_vol_factor)
    confidence = round(min(confidence, 1.0), 2)

    return {
        "volume": int(len(df)),
        "clusters": int(unique_stories),
        "tier1_ratio": round(tier1_ratio, 2),
        "escalation_score": float(min(score, 100)),
        "confidence": confidence,
        "top_clusters": sorted(clusters, key=lambda x: x["count"], reverse=True)[:3]
    }

# --- 6. לוגיקה ראשית ---
if st.button("🚀 הפעל ניתוח מבצעי (Production Scan)", type="primary"):
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
                
                # אנליטיקה
                analytics = analyze_data_points(raw_data.get('items', []), tier1_domains)
                
                # שמירת נתונים לגרף ולדוח
                timeline_data.append({
                    "day_offset": -i,
                    "date": target_date.strftime('%d/%m'),
                    "score": analytics['escalation_score'],
                    "confidence": analytics['confidence'],
                    "top_stories": analytics['top_clusters'],
                    "debug": raw_data.get("debug", {}),
                    "error": raw_data.get("error", None)
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
        st.subheader("📈 מדד חריגות (Escalation Index)")
        
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
        
        # --- חקר נתונים (Evidence Locker) ---
        st.divider()
        st.subheader("🔍 חקר נתונים ודיבאג")
        
        c1, c2 = st.columns(2)
        
        def render_day_list(timeline):
            for day in timeline:
                # כותרת עם צבע לפי ביטחון
                conf_icon = "🟢" if day['confidence'] > 0.6 else "🟠" if day['confidence'] > 0.3 else "🔴"
                
                with st.expander(f"{day['date']} | ציון: {day['score']} | ודאות: {day['confidence']} {conf_icon}"):
                    # דיבאג שקוף
                    dbg = day.get('debug', {})
                    if dbg:
                        st.markdown(f"""
                        <div class='debug-info'>
                        Fetch: {dbg.get('fetched',0)} | Grounded: {dbg.get('grounded_sources',0)} | Valid: {dbg.get('validated',0)}
                        </div>
                        """, unsafe_allow_html=True)
                    
                    if day.get('error'):
                        st.error(f"Error: {day['error']}")
                    
                    # הצגת קלאסטרים
                    for story in day['top_stories']:
                        st.markdown(f"""
                        <div class="cluster-card">
                            <b>{story['main_title']}</b><br>
                            מקורות ({story['count']}): {', '.join(story['domains'][:3])}
                        </div>
                        """, unsafe_allow_html=True)

        with c1: 
            st.markdown("### Reference Timeline")
            render_day_list(past_timeline)
        with c2: 
            st.markdown("### Current Timeline")
            render_day_list(curr_timeline)

        # --- סיכום מנהלים (Gemini 3 Pro) ---
        st.divider()
        st.subheader("🧠 הערכת מצב (Gemini 3 Pro)")
        
        past_scores = [x['score'] for x in past_timeline]
        curr_scores = [x['score'] for x in curr_timeline]
        past_conf = np.mean([x['confidence'] for x in past_timeline])
        curr_conf = np.mean([x['confidence'] for x in curr_timeline])
        
        correlation = np.corrcoef(past_scores, curr_scores)[0, 1] if (np.std(past_scores) > 0 and np.std(curr_scores) > 0) else 0
        
        with st.spinner("Gemini 3 Pro מנתח חריגות ורמת ביטחון..."):
            summary_prompt = f"""
            Act as a Senior Intelligence Officer.
            
            DATASET A (Reference): Correlation: {correlation:.2f}. Avg Confidence: {past_conf:.2f}
            DATASET B (Current): Avg Confidence: {curr_conf:.2f}
            
            TASK:
            1. Anomaly Analysis: Compare structural similarity of the escalation curves.
            2. Reliability Check: Based on the Confidence scores, how reliable is the current signal?
            3. Bottom Line: Are the current drivers (clusters) similar to the reference period?
            
            Output in Hebrew.
            """
            
            response = client.models.generate_content(
                model="gemini-3-pro-preview",
                contents=summary_prompt,
                config=types.GenerateContentConfig(temperature=0.2)
            )
            
            st.markdown(response.text)
