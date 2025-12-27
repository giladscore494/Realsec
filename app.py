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
st.set_page_config(layout="wide", page_title="OSINT Sentinel: Final Ops")

# --- עיצוב CSS ---
st.markdown("""
<style>
    .stTextInput > label, .stSelectbox > label, .stDateInput > label, .stSlider > label, .stRadio > label { 
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
        font-size: 0.75em; color: #666; margin-top: -5px; margin-bottom: 5px;
        border-bottom: 1px dashed #ccc; padding-bottom: 2px;
    }
    .evidence-link {
        font-size: 0.85em; display: block; margin-bottom: 3px;
        text-decoration: none; color: #0066cc;
    }
    .evidence-link:hover { text-decoration: underline; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ OSINT Sentinel: מנוע מבצעי (v2.0)")
st.caption("I&W System: אימות קשיח, ניהול סיכונים וראיות ויזואליות")

# --- 1. ניהול Cache (SQLite) ---
DB_FILE = "osint_ops_v2.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
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
    c.execute("""
        INSERT OR REPLACE INTO daily_scans (scan_date, query_hash, raw_json, updated_at)
        VALUES (?, ?, ?, ?)
    """, (date_str, query_hash, json.dumps(data), datetime.datetime.now()))
    conn.commit()
    conn.close()

init_db()

# --- 2. עזרים: נרמול ודומיינים ---
def _get_domain(url: str) -> str:
    try:
        if not url: return ""
        d = urlparse(url).netloc.lower()
        return d[4:] if d.startswith("www.") else d
    except:
        return ""

def _normalize_url(u: str) -> str:
    try:
        if not u: return ""
        p = urlparse(u.strip())
        netloc = p.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        
        path = p.path.rstrip("/")
        
        # ניקוי פרמטרים ספציפי
        DROP_KEYS = {"fbclid", "gclid", "ref", "ref_src", "utm_source", "utm_medium", "utm_campaign"}
        q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
             if k.lower() not in DROP_KEYS and not k.lower().startswith("utm_")]
        query = urlencode(q, doseq=True)
        
        return urlunparse((p.scheme.lower() or "https", netloc, path, "", query, ""))
    except:
        return u or ""

def _extract_grounded_urls(response) -> tuple[set, set]:
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

def _is_tier1(domain: str, tier1_set: set[str]) -> bool:
    """בודק האם הדומיין (או דומיין האב שלו) נמצא ברשימת האיכות"""
    if not domain: return False
    # בדיקה ישירה או בדיקת סיומת (למשל m.ynet.co.il מול ynet.co.il)
    if domain in tier1_set: return True
    return any(domain.endswith("." + t) for t in tier1_set)

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
    st.subheader("🛡️ בקרת אימות")
    validation_mode = st.radio("רמת אימות (Validation Mode):", ["Strict", "Relaxed"], index=1,
                               help="Strict: URL מדויק בלבד. Relaxed: מספיק דומיין תואם.")
    
    tier1_domains = st.text_area("מקורות איכות (Tier 1):", 
                                 "reuters.com, apnews.com, bbc.com, ynet.co.il, haaretz.co.il, isna.ir, tasnimnews.com, jpost.com, timesofisrael.com, cnn.com, aljazeera.com",
                                 height=100)
    keywords = st.text_input("מילות חיפוש:", "Iran Israel military conflict missile attack nuclear")

# --- 4. מנוע איסוף (Retry + Toggle) ---
def fetch_day_data(client, date_obj, keywords, mode="Relaxed"):
    date_str = date_obj.strftime('%Y-%m-%d')
    # ההאש כולל גם את המוד, כדי שאם נשנה הגדרות לא נקבל cache ישן
    query_hash = hashlib.md5((date_str + keywords + mode).encode()).hexdigest()
    
    cached = get_from_cache(date_str, query_hash)
    if cached: return cached, True

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
    
    # Retry Logic: 3 ניסיונות במקרה של שגיאת רשת
    for attempt in range(3):
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
            
            # חילוץ Grounding
            grounded_norm, grounded_domains = _extract_grounded_urls(response)
            
            # Fail-Closed
            if not grounded_norm and not grounded_domains:
                empty_data = {"items": [], "error": "NO_GROUNDING_SOURCES", "debug": {"attempts": attempt+1}}
                save_to_cache(date_str, query_hash, empty_data)
                return empty_data, False
                
            try:
                raw_data = json.loads(response.text)
                raw_items = raw_data.get("items", [])
            except:
                raw_items = []

            validated_items = []
            strict_hits = 0
            relaxed_hits = 0
            
            for item in raw_items:
                u = item.get("url", "")
                if not u: continue
                
                u_norm = _normalize_url(u)
                u_domain = _get_domain(u)
                
                is_valid = False
                
                # בדיקה מדויקת
                if u_norm in grounded_norm:
                    is_valid = True
                    strict_hits += 1
                # בדיקה רכה (רק אם המשתמש בחר Relaxed)
                elif mode == "Relaxed" and u_domain in grounded_domains:
                    is_valid = True
                    relaxed_hits += 1
                
                if is_valid:
                    validated_items.append(item)
            
            debug_stats = {
                "fetched": len(raw_items),
                "grounded_sources": len(grounded_norm),
                "validated": len(validated_items),
                "strict_hits": strict_hits,
                "relaxed_hits": relaxed_hits,
                "attempts": attempt + 1
            }
            
            final_data = {"items": validated_items, "debug": debug_stats}
            save_to_cache(date_str, query_hash, final_data)
            return final_data, False

        except Exception as e:
            if attempt == 2: # נכשל סופית
                return {"items": [], "error": str(e), "debug": {"attempts": 3}}, False
            time.sleep(1 + attempt) # Backoff: 1s, 2s...

# --- 5. מנוע אנליטי (Corrected Confidence) ---
def analyze_data_points(items, tier1_list):
    if not items:
        return {"volume": 0, "clusters": 0, "tier1_ratio": 0, "escalation_score": 0, "confidence": 0, "top_clusters": [], "evidence": []}
    
    df = pd.DataFrame(items)
    df["title"] = df["title"].fillna("").astype(str)
    df["snippet"] = df["snippet"].fillna("").astype(str)
    df["url"] = df["url"].fillna("").astype(str)
    
    df["domain"] = df["url"].apply(_get_domain)
    df["text"] = (df["title"] + " " + df["snippet"]).str.strip()
    
    # 1. Clustering
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
            clusters.append({
                "main_title": part.iloc[0]["title"],
                "count": len(part),
                "unique_domains": part["domain"].nunique(),
                "domains": sorted(set(part["domain"].tolist()))
            })
    else:
        clusters = [{"main_title": df.iloc[0]["title"], "count": 1, "unique_domains": 1, "domains": [df.iloc[0]["domain"]]}]

    # 2. חישובים משופרים (Tier 1 על דומיינים ייחודיים)
    tier1_set = {x.strip().lower().replace("www.", "") for x in tier1_list.split(",") if x.strip()}
    
    # חישוב Tier 1 על בסיס דומיינים ייחודיים בלבד (נגד ניפוח)
    unique_domains_today = set(df["domain"].unique()) - {""}
    if unique_domains_today:
        tier1_hits = sum(1 for d in unique_domains_today if _is_tier1(d, tier1_set))
        tier1_ratio = tier1_hits / len(unique_domains_today)
    else:
        tier1_ratio = 0.0

    unique_stories = len(clusters)
    total_unique_domains = sum(c['unique_domains'] for c in clusters)
    avg_sources = min((total_unique_domains / unique_stories), 4) if unique_stories else 0

    # 3. ציון דטרמיניסטי
    score = (unique_stories * 4) + (tier1_ratio * 30) + (avg_sources * 5)
    
    # 4. ביטחון (Confidence)
    clusters_factor = min(1.0, unique_stories / 5)
    volume_factor = min(1.0, len(unique_domains_today) / 6) # לפחות 6 מקורות שונים לביטחון מלא
    
    confidence = (0.40 * clusters_factor) + (0.40 * tier1_ratio) + (0.20 * volume_factor)
    confidence = round(min(confidence, 1.0), 2)

    # 5. הכנת רשימת ראיות (5 הלינקים הטובים ביותר להצגה)
    # עדיפות ל-Tier 1
    evidence = []
    seen_urls = set()
    
    # שלב א: מקורות איכות
    for _, row in df.iterrows():
        if _is_tier1(row['domain'], tier1_set) and row['url'] not in seen_urls:
            evidence.append({"title": row['title'], "url": row['url'], "domain": row['domain'], "tier1": True})
            seen_urls.add(row['url'])
    
    # שלב ב: השאר (עד 5)
    for _, row in df.iterrows():
        if len(evidence) >= 5: break
        if row['url'] not in seen_urls:
            evidence.append({"title": row['title'], "url": row['url'], "domain": row['domain'], "tier1": False})
            seen_urls.add(row['url'])

    return {
        "volume": int(len(df)),
        "clusters": int(unique_stories),
        "tier1_ratio": round(tier1_ratio, 2),
        "escalation_score": float(min(score, 100)),
        "confidence": confidence,
        "top_clusters": sorted(clusters, key=lambda x: x["count"], reverse=True)[:3],
        "evidence": evidence
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
                
                raw_data, is_cached = fetch_day_data(client, target_date, keywords, validation_mode)
                analytics = analyze_data_points(raw_data.get('items', []), tier1_domains)
                
                timeline_data.append({
                    "day_offset": -i,
                    "date": target_date.strftime('%d/%m'),
                    "score": analytics['escalation_score'],
                    "confidence": analytics['confidence'],
                    "top_stories": analytics['top_clusters'],
                    "evidence": analytics['evidence'], # <--- הוספנו ראיות
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
        st.subheader("🔍 חקר נתונים וראיות (Evidence Locker)")
        
        c1, c2 = st.columns(2)
        
        def render_day_list(timeline):
            for day in timeline:
                conf_icon = "🟢" if day['confidence'] > 0.6 else "🟠" if day['confidence'] > 0.3 else "🔴"
                
                with st.expander(f"{day['date']} | ציון: {day['score']} | ודאות: {day['confidence']} {conf_icon}"):
                    # דיבאג
                    dbg = day.get('debug', {})
                    if dbg:
                        st.markdown(f"""
                        <div class='debug-info'>
                        Strict: {dbg.get('strict_hits',0)} | Relaxed: {dbg.get('relaxed_hits',0)} | Valid: {dbg.get('validated',0)}
                        </div>
                        """, unsafe_allow_html=True)
                    
                    if day.get('error'): st.error(day['error'])
                    
                    # קלאסטרים
                    st.markdown("**נושאים מרכזיים:**")
                    for story in day['top_stories']:
                        st.markdown(f"""
                        <div class="cluster-card">
                            <b>{story['main_title']}</b><br>
                            <span style='color: #666;'>מקורות: {', '.join(story['domains'][:3])}</span>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    # ראיות (לינקים)
                    if day['evidence']:
                        st.markdown("**🔗 ראיות מאומתות (Top 5):**")
                        for ev in day['evidence']:
                            t1_mark = "⭐" if ev['tier1'] else ""
                            st.markdown(f"<a href='{ev['url']}' target='_blank' class='evidence-link'>{t1_mark} {ev['title']} ({ev['domain']})</a>", unsafe_allow_html=True)
                    else:
                        st.caption("אין ראיות מאומתות לתאריך זה.")

        with c1: 
            st.markdown("### Reference Timeline")
            render_day_list(past_timeline)
        with c2: 
            st.markdown("### Current Timeline")
            render_day_list(curr_timeline)

        # --- סיכום מנהלים ---
        st.divider()
        st.subheader("🧠 הערכת מצב (Gemini 3 Pro)")
        
        past_scores = [x['score'] for x in past_timeline]
        curr_scores = [x['score'] for x in curr_timeline]
        
        # חישוב קורלציה מוגן
        correlation = 0
        if len(past_scores) > 1 and len(curr_scores) > 1:
            if np.std(past_scores) > 0 and np.std(curr_scores) > 0:
                correlation = np.corrcoef(past_scores, curr_scores)[0, 1]

        avg_conf_curr = np.mean([x['confidence'] for x in curr_timeline])
        
        with st.spinner("Gemini 3 Pro מנתח חריגות ורמת ביטחון..."):
            summary_prompt = f"""
            Act as a Senior Intelligence Officer.
            
            DATASET A (Reference): Correlation: {correlation:.2f}.
            DATASET B (Current): Avg Confidence: {avg_conf_curr:.2f}
            
            TASK:
            1. Anomaly Analysis: Compare structural similarity of the escalation curves.
            2. Reliability Check: Based on Confidence={avg_conf_curr:.2f}, is the signal reliable?
            3. Bottom Line: Are the current drivers similar to the reference period?
            
            Output in Hebrew.
            """
            
            response = client.models.generate_content(
                model="gemini-3-pro-preview",
                contents=summary_prompt,
                config=types.GenerateContentConfig(temperature=0.2)
            )
            
            st.markdown(response.text)

