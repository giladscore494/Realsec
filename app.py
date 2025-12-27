import streamlit as st
import datetime
import pandas as pd
import numpy as np
import time
import json
import sqlite3
import hashlib
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from google import genai
from google.genai import types
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# --- הגדרת עמוד ---
st.set_page_config(layout="wide", page_title="OSINT Sentinel: Gold v1.1")

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
    .evidence-link {
        font-size: 0.85em; display: block; margin-bottom: 3px;
        text-decoration: none; color: #0066cc;
    }
    .metric-warning { color: #d9534f; font-weight: bold; font-size: 0.8em; }
    .status-ok { color: #00c851; font-weight: bold; }
    .status-err { color: #ff4444; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ OSINT Sentinel: Gold v1.1")
st.caption("מערכת I&W סופית: אימות חכם (Vertex/Redirects), State Management וראיות נקיות")

# --- 1. ניהול Cache (SQLite) ---
DB_FILE = "osint_gold_v1_1.db" # גרסה חדשה ל-DB

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
AGGREGATOR_SUFFIXES = {
    "news.google.com", "google.com", "msn.com", "yahoo.com", "bing.com",
    "vertexaisearch.cloud.google.com", "webcache.googleusercontent.com"
}

def _get_domain(url: str) -> str:
    try:
        if not url: return ""
        d = urlparse(url).netloc.lower()
        return d[4:] if d.startswith("www.") else d
    except:
        return ""

def _is_aggregator_domain(d: str) -> bool:
    if not d: return False
    d = d.lower().replace("www.", "")
    # בדיקת התאמה מלאה או סיומת (כדי לתפוס news.google.com וכו')
    return any(d == s or d.endswith("." + s) for s in AGGREGATOR_SUFFIXES)

def _normalize_url(u: str) -> str:
    try:
        if not u: return ""
        p = urlparse(u.strip())
        netloc = p.netloc.lower()
        if netloc.startswith("www."): netloc = netloc[4:]
        path = p.path.rstrip("/")
        # ניקוי פרמטרים
        DROP_KEYS = {"fbclid", "gclid", "ref", "ref_src", "utm_source", "utm_medium", "utm_campaign", "ocid"}
        q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
             if k.lower() not in DROP_KEYS and not k.lower().startswith("utm_")]
        query = urlencode(q, doseq=True)
        return urlunparse((p.scheme.lower() or "https", netloc, path, "", query, ""))
    except:
        return u or ""

def _extract_grounded_urls(response) -> tuple[set, set]:
    """חילוץ חכם כולל Title Fallback"""
    urls_norm = set()
    domains = set()
    try:
        if not response.candidates: return urls_norm, domains
        gm = response.candidates[0].grounding_metadata
        if not gm: return urls_norm, domains
        
        chunks = getattr(gm, "grounding_chunks", []) or []
        for ch in chunks:
            web = getattr(ch, "web", None)
            if not web: continue
            
            uri = getattr(web, "uri", None)
            title = getattr(web, "title", None)
            
            # 1. חילוץ מ-URI
            if uri and uri.startswith("http"):
                urls_norm.add(_normalize_url(uri))
                d = _get_domain(uri)
                if d and not _is_aggregator_domain(d):
                    domains.add(d)
            
            # 2. חילוץ מ-Title (אם נראה כמו דומיין)
            # לעיתים גוגל מחזיר את הדומיין האמיתי ב-Title כשה-URI הוא Redirect
            if title and "." in title and " " not in title:
                d2 = title.lower().replace("www.", "")
                # ולידציה בסיסית שזה דומיין
                if len(d2) > 3 and not _is_aggregator_domain(d2):
                    domains.add(d2)
                    
    except Exception:
        pass
    return urls_norm, domains

def _is_tier1(domain: str, tier1_set: set[str]) -> bool:
    if not domain: return False
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
    
    est_calls = (window + 1) * 2
    st.caption(f"📊 צפי קריאות API: {est_calls}")
    if est_calls > 60:
        st.markdown("<span class='metric-warning'>⚠️ כמות קריאות גבוהה!</span>", unsafe_allow_html=True)

    st.divider()
    validation_mode = st.radio("רמת אימות:", ["Strict", "Relaxed"], index=1)
    
    tier1_domains = st.text_area("מקורות איכות (Tier 1):", 
                                 "reuters.com, apnews.com, bbc.com, ynet.co.il, haaretz.co.il, isna.ir, tasnimnews.com, jpost.com, timesofisrael.com, cnn.com, aljazeera.com",
                                 height=100)
    keywords = st.text_input("מילות חיפוש:", "Iran Israel military conflict missile attack nuclear")

# --- 4. מנוע איסוף (Updated Logic) ---
def fetch_day_data(client, date_obj, keywords, mode="Relaxed"):
    date_str = date_obj.strftime('%Y-%m-%d')
    query_hash = hashlib.md5((date_str + keywords + mode + "v1.1").encode()).hexdigest()
    
    cached = get_from_cache(date_str, query_hash)
    if cached: return cached, True

    after = date_obj
    before = date_obj + datetime.timedelta(days=1)
    search_query = f"{keywords} after:{after} before:{before}"
    
    prompt = f"""
    ROLE: OSINT Data Extractor.
    TASK: Find specific news items for DATE: {date_str}.
    QUERY: "{search_query}"
    
    INSTRUCTIONS:
    1. Return the publisher’s CANONICAL URL.
    2. DO NOT return google.com, news.google.com, msn.com or redirect links.
    3. JSON Format Only.
    
    JSON Schema:
    {{
      "items": [
        {{ "title": "...", "source": "...", "url": "...", "snippet": "..." }}
      ]
    }}
    """
    
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
            
            grounded_norm, grounded_domains = _extract_grounded_urls(response)
            
            try:
                raw_data = json.loads(response.text)
                raw_items = raw_data.get("items", [])
            except:
                raw_items = []

            # ולידציה: אם יש גראונדינג אבל אין פריטים ב-JSON - משהו השתבש
            if (grounded_norm or grounded_domains) and not raw_items:
                err_data = {"items": [], "error": "EMPTY_ITEMS_WITH_GROUNDING", "debug": {"attempts": attempt+1}}
                save_to_cache(date_str, query_hash, err_data)
                return err_data, False
            
            # ולידציה: אם אין בכלל גראונדינג
            if not grounded_norm and not grounded_domains:
                empty_data = {"items": [], "error": "NO_GROUNDING_SOURCES", "debug": {"attempts": attempt+1}}
                save_to_cache(date_str, query_hash, empty_data)
                return empty_data, False

            validated_items = []
            
            for item in raw_items:
                u = item.get("url", "")
                if not u: continue
                
                u_norm = _normalize_url(u)
                u_domain = _get_domain(u)
                
                # סינון אגרגטורים חכם (כולל Vertex/Cloud)
                if _is_aggregator_domain(u_domain): continue
                
                is_valid = False
                if u_norm in grounded_norm: is_valid = True
                elif mode == "Relaxed" and u_domain in grounded_domains: is_valid = True
                
                if is_valid: validated_items.append(item)
            
            final_data = {
                "items": validated_items,
                "debug": {
                    "fetched": len(raw_items),
                    "grounded": len(grounded_norm),
                    "grounded_domains": len(grounded_domains),
                    "valid": len(validated_items),
                    "attempt": attempt + 1
                }
            }
            save_to_cache(date_str, query_hash, final_data)
            return final_data, False

        except Exception as e:
            if attempt == 2:
                return {"items": [], "error": str(e), "debug": {"attempts": 3}}, False
            time.sleep(1 + attempt)

# --- 5. מנוע אנליטי (Evidence Normalized) ---
def analyze_data_points(items, tier1_list):
    if not items:
        return {"volume": 0, "clusters": 0, "tier1_ratio": 0, "escalation_score": 0, "confidence": 0, "top_clusters": [], "evidence": []}
    
    df = pd.DataFrame(items)
    df["domain"] = df["url"].apply(_get_domain)
    # ניקוי אגרגטורים נוסף ליתר ביטחון (למקרה שזלג)
    df = df[~df["domain"].apply(_is_aggregator_domain)]
    
    if df.empty:
         return {"volume": 0, "clusters": 0, "tier1_ratio": 0, "escalation_score": 0, "confidence": 0, "top_clusters": [], "evidence": []}

    df["text"] = (df["title"] + " " + df["snippet"].fillna("")).str.strip()
    
    # Clustering
    clusters = []
    if len(df) > 1 and df["text"].str.len().sum() > 0:
        vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
        tfidf = vectorizer.fit_transform(df["text"])
        sim = cosine_similarity(tfidf)
        
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
                "indices": idxs
            })
    else:
        clusters = [{"main_title": df.iloc[0]["title"], "count": 1, "unique_domains": 1, "indices": [0]}]

    # Calculations
    tier1_set = {x.strip().lower().replace("www.", "") for x in tier1_list.split(",") if x.strip()}
    unique_domains_today = set(df["domain"].unique()) - {""}
    tier1_unique_count = sum(1 for d in unique_domains_today if _is_tier1(d, tier1_set))
    tier1_ratio = tier1_unique_count / max(1, len(unique_domains_today))
    
    unique_stories = len(clusters)
    total_domain_power = sum(c['unique_domains'] for c in clusters)
    avg_sources = min((total_domain_power / unique_stories), 4) if unique_stories else 0

    tier1_bonus = min(10, tier1_unique_count * 2)
    score = (unique_stories * 4) + (tier1_ratio * 30) + (avg_sources * 5) + tier1_bonus
    
    # Confidence
    conf_clusters = min(1.0, unique_stories / 5)
    conf_vol = min(1.0, len(unique_domains_today) / 6)
    confidence = (0.35 * conf_clusters) + (0.45 * tier1_ratio) + (0.20 * conf_vol)
    
    if len(unique_domains_today) < 3 or unique_stories < 2:
        confidence = min(confidence, 0.25)
    
    # Evidence Selection (Normalized)
    evidence = []
    top_clusters = sorted(clusters, key=lambda x: x["count"], reverse=True)[:5]
    seen_urls_norm = set()
    
    for cl in top_clusters:
        cluster_df = df.iloc[cl['indices']]
        best_row = None
        for _, row in cluster_df.iterrows():
            if _is_tier1(row['domain'], tier1_set):
                best_row = row
                break
        if best_row is None:
            best_row = cluster_df.iloc[0]
            
        u_norm = _normalize_url(best_row['url'])
        if u_norm not in seen_urls_norm:
            evidence.append({
                "title": best_row['title'],
                "url": best_row['url'],
                "domain": best_row['domain'],
                "tier1": _is_tier1(best_row['domain'], tier1_set)
            })
            seen_urls_norm.add(u_norm)

    return {
        "volume": int(len(df)),
        "clusters": int(unique_stories),
        "tier1_ratio": round(tier1_ratio, 2),
        "escalation_score": float(min(score, 100)),
        "confidence": round(confidence, 2),
        "top_clusters": top_clusters[:3],
        "evidence": evidence
    }

# --- 6. ניהול State ו-UI ראשי ---
if 'past_timeline' not in st.session_state: st.session_state.past_timeline = None
if 'curr_timeline' not in st.session_state: st.session_state.curr_timeline = None
if 'summary_text' not in st.session_state: st.session_state.summary_text = None

def run_scan():
    if not api_key:
        st.error("חסר מפתח API")
        return

    client = genai.Client(api_key=api_key)
    status_text = st.empty()
    prog_bar = st.progress(0)
    
    total_steps = (window + 1) * 2
    state = {"step": 0}
    
    def scan_timeline(anchor_date, label):
        timeline_data = []
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
                "evidence": analytics['evidence'],
                "debug": raw_data.get("debug", {}),
                "error": raw_data.get("error", None)
            })
            
            state["step"] += 1
            prog_bar.progress(state["step"] / total_steps)
            if not is_cached: time.sleep(0.5)
        return timeline_data

    # ביצוע הסריקה
    st.session_state.past_timeline = scan_timeline(attack_date, "Reference")
    st.session_state.curr_timeline = scan_timeline(today_date, "Live")
    status_text.empty()
    prog_bar.empty()
    
    # ביצוע הסיכום בסוף (פעם אחת)
    past_scores = [x['score'] for x in st.session_state.past_timeline]
    curr_scores = [x['score'] for x in st.session_state.curr_timeline]
    correlation = np.corrcoef(past_scores, curr_scores)[0, 1] if (len(past_scores)>1 and np.std(past_scores)>0 and np.std(curr_scores)>0) else 0
    avg_conf = np.mean([x['confidence'] for x in st.session_state.curr_timeline])
    
    with st.spinner("Gemini 3 Pro מנתח..."):
        summary_prompt = f"""
        Act as a Senior Intelligence Officer.
        STATS: Correlation: {correlation:.2f}. Avg Confidence: {avg_conf:.2f}
        TASK:
        1. Compare structural similarity of escalation.
        2. Reliability Assessment based on confidence.
        3. Bottom Line: Verified main drivers.
        Output in Hebrew.
        """
        response = client.models.generate_content(
            model="gemini-3-pro-preview",
            contents=summary_prompt,
            config=types.GenerateContentConfig(temperature=0.2)
        )
        st.session_state.summary_text = response.text

# כפתור הפעלה
if st.button("🚀 הפעל ניתוח מבצעי (Run)", type="primary"):
    run_scan()

# --- 7. רינדור התוצאות מה-State ---
if st.session_state.past_timeline and st.session_state.curr_timeline:
    
    past = st.session_state.past_timeline
    curr = st.session_state.curr_timeline
    
    # גרפים
    st.divider()
    st.subheader("📈 תמונת מודיעין")
    
    fig = make_subplots(specs=[[{"secondary_y": True}]])
    fig.add_trace(go.Scatter(x=[x['day_offset'] for x in past], y=[x['score'] for x in past], name="Ref Score", line=dict(color='#ef5350', width=2, dash='dot')), secondary_y=False)
    fig.add_trace(go.Scatter(x=[x['day_offset'] for x in curr], y=[x['score'] for x in curr], name="Live Score", line=dict(color='#4285f4', width=3)), secondary_y=False)
    fig.add_trace(go.Bar(x=[x['day_offset'] for x in curr], y=[x['confidence'] for x in curr], name="Confidence", marker_color='rgba(66, 133, 244, 0.2)'), secondary_y=True)
    
    fig.update_layout(title="Escalation vs Reliability", hovermode="x unified")
    fig.update_yaxes(title_text="Score", secondary_y=False)
    fig.update_yaxes(title_text="Conf", range=[0,1], secondary_y=True)
    st.plotly_chart(fig, use_container_width=True)
    
    # חקר נתונים
    st.divider()
    st.subheader("🔍 חקר ראיות (Evidence Locker)")
    c1, c2 = st.columns(2)
    
    def render_timeline(tl):
        for day in tl:
            conf_icon = "🟢" if day['confidence'] > 0.6 else "🟠" if day['confidence'] > 0.3 else "🔴"
            err_mark = "⚠️" if day.get('error') else ""
            
            with st.expander(f"{day['date']} | Score: {day['score']:.0f} | Conf: {day['confidence']} {conf_icon} {err_mark}"):
                if day.get('error'): st.error(day['error'])
                
                # ראיות
                if day['evidence']:
                    st.markdown("**🔗 ראיות נבחרות:**")
                    for ev in day['evidence']:
                        t1_mark = "⭐" if ev['tier1'] else ""
                        st.markdown(f"<a href='{ev['url']}' target='_blank' class='evidence-link'>{t1_mark} {ev['title']} <span style='color:#777'>({ev['domain']})</span></a>", unsafe_allow_html=True)
                else:
                    st.caption("אין ראיות מאומתות.")
                
                # דיבאג
                dbg = day.get('debug', {})
                if dbg:
                    st.markdown(f"<div class='debug-info'>Fetched: {dbg.get('fetched')} | Domains: {dbg.get('grounded_domains')} | Valid: {dbg.get('valid')}</div>", unsafe_allow_html=True)

    with c1: 
        st.markdown("### Reference")
        render_timeline(past)
    with c2: 
        st.markdown("### Live")
        render_timeline(curr)
        
    # סיכום
    if st.session_state.summary_text:
        st.divider()
        st.subheader("🧠 הערכת מצב")
        st.markdown(st.session_state.summary_text)


