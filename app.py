import streamlit as st
import datetime
import pandas as pd
import numpy as np
import time
import json
import sqlite3
import hashlib
import logging
import random
import concurrent.futures
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from contextlib import contextmanager

# 3rd Party
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from google import genai
from google.genai import types
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# --- Config & Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Config:
    APP_TITLE = "🛡️ OSINT Sentinel: Platinum v1.5"
    DB_FILE = "osint_plat_v1_5.db"
    MAX_WORKERS = 3  # מגבלת תהליכונים למניעת חסימת API
    MAX_RETRIES = 3
    
    # חסימת רעש ואתרי תעמולה
    BLACKLIST_DOMAINS = {
        "news.google.com", "google.com", "msn.com", "yahoo.com", "bing.com", 
        "vertexaisearch.cloud.google.com", "webcache.googleusercontent.com",
        "mronline.org", "alwaght.net", "presstv.ir", "sputniknews.com"
    }
    
    # סיומות של אגרגטורים לסינון
    AGGREGATOR_SUFFIXES = {
        "news.google.com", "google.com", "msn.com", "yahoo.com", "bing.com",
        "vertexaisearch.cloud.google.com"
    }
    
    # משקולות למקורות (1.0 = אמינות גבוהה, 0.35 = ברירת מחדל)
    DOMAIN_WEIGHTS = {
        "reuters.com": 1.0, "apnews.com": 1.0, "bbc.com": 1.0, "cnn.com": 0.9,
        "ynet.co.il": 0.85, "haaretz.co.il": 0.85, "timesofisrael.com": 0.85,
        "jpost.com": 0.80, "maariv.co.il": 0.75, "walla.co.il": 0.75,
        "aljazeera.com": 0.70, "tasnimnews.com": 0.60, "isna.ir": 0.60,
        "iranintl.com": 0.65
    }
    DEFAULT_WEIGHT = 0.35
    DEFAULT_TIER1_STR = ", ".join(DOMAIN_WEIGHTS.keys())

# --- Page Setup ---
st.set_page_config(layout="wide", page_title=Config.APP_TITLE)

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
    .evidence-link:hover { text-decoration: underline; }
    .metric-warning { color: #d9534f; font-weight: bold; font-size: 0.8em; }
    .debug-info {
        font-size: 0.75em; color: #666; margin-top: 6px;
        border-top: 1px dashed #ccc; padding-top: 4px;
    }
    .disclaimer-box {
        background-color: #fff3cd; border: 1px solid #ffeeba; color: #856404;
        padding: 15px; border-radius: 5px; margin-bottom: 20px; direction: rtl; text-align: right;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="disclaimer-box">
    ⚖️ <b>הצהרת אחריות</b><br>
    מערכת זו נועדה למחקר ואנליזה של מידע פומבי בלבד (OSINT).<br>
    אין להשתמש במידע למטרות בלתי חוקיות. המשתמש אחראי לציות לכל החוקים הרלוונטיים.<br>
    המערכת מציגה סטטיסטיקה של שיח תקשורתי ואינה מספקת התרעות צבאיות או נבואות.
</div>
""", unsafe_allow_html=True)

st.title(Config.APP_TITLE)
st.caption("Advanced I&W System: Weighted Analysis, Deduplication & Strict Grounding")

# --- Utilities ---

def retry_with_backoff(retries: int = Config.MAX_RETRIES, backoff_in_seconds: int = 1):
    def decorator(func):
        def wrapper(*args, **kwargs):
            x = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if x == retries:
                        logger.error(f"Failed after {retries} retries: {str(e)}")
                        raise e
                    sleep = (backoff_in_seconds * 2 ** x) + random.uniform(0, 1)
                    time.sleep(sleep)
                    x += 1
        return wrapper
    return decorator

def normalize_url(u: str) -> str:
    try:
        if not u: return ""
        p = urlparse(u.strip())
        netloc = p.netloc.lower()
        if netloc.startswith("www."): netloc = netloc[4:]
        path = p.path.rstrip("/")
        DROP_KEYS = {"fbclid", "gclid", "ref", "ref_src", "utm_source", "utm_medium", "utm_campaign", "ocid"}
        q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
             if k.lower() not in DROP_KEYS and not k.lower().startswith("utm_")]
        query = urlencode(q, doseq=True)
        return urlunparse((p.scheme.lower() or "https", netloc, path, "", query, ""))
    except:
        return u or ""

def get_domain(url: str) -> str:
    try:
        if not url: return ""
        d = urlparse(url).netloc.lower()
        return d[4:] if d.startswith("www.") else d
    except:
        return ""

def is_aggregator_domain(d: str) -> bool:
    if not d: return False
    d = d.lower().replace("www.", "")
    return any(d == s or d.endswith("." + s) for s in Config.AGGREGATOR_SUFFIXES)

# --- Database Manager ---
class DatabaseManager:
    def __init__(self, db_file: str):
        self.db_file = db_file
        self.init_db()

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_file, check_same_thread=False)
        try:
            yield conn
        finally:
            conn.close()

    def init_db(self):
        with self.get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute('''CREATE TABLE IF NOT EXISTS daily_scans
                         (scan_date TEXT, query_hash TEXT, raw_json TEXT, updated_at TIMESTAMP,
                          PRIMARY KEY (scan_date, query_hash))''')
            conn.commit()

    def get_data(self, date_str: str, query_hash: str) -> Optional[Dict]:
        with self.get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT raw_json FROM daily_scans WHERE scan_date=? AND query_hash=?", (date_str, query_hash))
            data = c.fetchone()
            return json.loads(data[0]) if data else None

    def save_data(self, date_str: str, query_hash: str, data: Dict):
        with self.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO daily_scans (scan_date, query_hash, raw_json, updated_at)
                VALUES (?, ?, ?, ?)
            """, (date_str, query_hash, json.dumps(data), datetime.datetime.now()))
            conn.commit()

db_manager = DatabaseManager(Config.DB_FILE)

# --- Gemini Scanner (Extraction) ---
class GeminiScanner:
    def __init__(self, api_key: str):
        self.client = genai.Client(api_key=api_key)

    def _extract_grounded_urls(self, response) -> Tuple[Set[str], Set[str]]:
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
                
                if uri and uri.startswith("http"):
                    urls_norm.add(normalize_url(uri))
                    d = get_domain(uri)
                    if d and not is_aggregator_domain(d):
                        domains.add(d)
                
                if title and "." in title and " " not in title:
                    d2 = title.lower().replace("www.", "")
                    if len(d2) > 3 and not is_aggregator_domain(d2):
                        domains.add(d2)
        except Exception:
            pass
        return urls_norm, domains

    @retry_with_backoff(retries=3)
    def fetch_day(self, date_obj: datetime.date, keywords: str, mode: str = "Relaxed") -> Tuple[Dict, bool]:
        date_str = date_obj.strftime('%Y-%m-%d')
        # Versioning in hash to invalidate old caches if logic changes
        query_hash = hashlib.md5((date_str + keywords + mode + "v1.5").encode()).hexdigest()
        
        cached = db_manager.get_data(date_str, query_hash)
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
        {{ "items": [ {{ "title": "...", "source": "...", "url": "...", "snippet": "..." }} ] }}
        """
        
        tool = types.Tool(google_search=types.GoogleSearch())
        
        try:
            response = self.client.models.generate_content(
                model="gemini-3-flash-preview", 
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.0,
                    response_mime_type="application/json",
                    tools=[tool]
                )
            )
            
            grounded_norm, grounded_domains = self._extract_grounded_urls(response)
            
            try:
                raw_data = json.loads(response.text)
                raw_items = raw_data.get("items", [])
            except:
                raw_items = []

            # Validations
            if (grounded_norm or grounded_domains) and not raw_items:
                err_data = {"items": [], "error": "EMPTY_ITEMS_WITH_GROUNDING"}
                db_manager.save_data(date_str, query_hash, err_data)
                return err_data, False
            
            if not grounded_norm and not grounded_domains:
                empty_data = {"items": [], "error": "NO_GROUNDING_SOURCES"}
                db_manager.save_data(date_str, query_hash, empty_data)
                return empty_data, False

            validated_items = []
            for item in raw_items:
                u = item.get("url", "")
                if not u: continue
                u_norm = normalize_url(u)
                u_domain = get_domain(u)
                
                if is_aggregator_domain(u_domain): continue
                
                is_valid = False
                if u_norm in grounded_norm: is_valid = True
                elif mode == "Relaxed" and u_domain in grounded_domains: is_valid = True
                
                if is_valid: validated_items.append(item)
            
            final_data = {
                "items": validated_items,
                "debug": {
                    "fetched": len(raw_items),
                    "grounded_sources": len(grounded_norm),
                    "valid": len(validated_items)
                }
            }
            db_manager.save_data(date_str, query_hash, final_data)
            return final_data, False

        except Exception as e:
            logger.error(f"Fetch failed for {date_str}: {e}")
            return {"items": [], "error": str(e)}, False

# --- Data Analyzer (Sophisticated Logic) ---
class DataAnalyzer:
    def _calculate_fingerprint(self, title: str, snippet: str) -> str:
        raw = (title.lower().strip() + "||" + snippet.lower().strip()).encode('utf-8')
        return hashlib.sha1(raw).hexdigest()

    def analyze(self, items: List[Dict]) -> Dict:
        if not items: return self._empty_result()
        
        df = pd.DataFrame(items)
        
        # 1. Sanitization
        for col in ["title", "snippet", "url"]:
            if col not in df.columns: df[col] = ""
            df[col] = df[col].fillna("").astype(str)
            
        df["domain"] = df["url"].apply(get_domain)
        
        # 2. Hard Filtering (Blacklist)
        df = df[~df["domain"].isin(Config.BLACKLIST_DOMAINS)]
        
        # 3. Content Deduplication (SHA1 Fingerprint)
        df["fp"] = df.apply(lambda row: self._calculate_fingerprint(row['title'], row['snippet']), axis=1)
        df = df.drop_duplicates("fp")
        
        if df.empty: return self._empty_result()

        # 4. Weight Assignment
        df["weight"] = df["domain"].map(Config.DOMAIN_WEIGHTS).fillna(Config.DEFAULT_WEIGHT)
        
        df["text"] = (df["title"] + " " + df["snippet"]).str.strip()
        
        # 5. Clustering
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
                    "max_weight": part["weight"].max(),
                    "indices": idxs
                })
        else:
            clusters = [{"main_title": df.iloc[0]["title"], "count": 1, "unique_domains": 1, "max_weight": df.iloc[0]["weight"], "indices": [0]}]

        # 6. Advanced Scoring
        unique_domains_valid = set(df["domain"].unique()) - {""}
        unique_stories = len(clusters)
        
        weighted_volume = df["weight"].sum()
        avg_cluster_quality = np.mean([c["max_weight"] for c in clusters]) if clusters else 0
        
        score = (unique_stories * 3) + (weighted_volume * 5) + (avg_cluster_quality * 20)
        
        # 7. Confidence Calibration (Continuous)
        confidence = avg_cluster_quality 
        domain_count = len(unique_domains_valid)
        scarcity_penalty = 1.0
        
        if domain_count < 4: scarcity_penalty *= (domain_count / 4)
        if unique_stories < 2: scarcity_penalty *= 0.6
            
        confidence = confidence * scarcity_penalty
        confidence = float(max(0.1, min(1.0, confidence)))

        # 8. Evidence Selection (Weighted)
        evidence = []
        top_clusters = sorted(clusters, key=lambda x: (x["max_weight"], x["count"]), reverse=True)[:5]
        seen_urls = set()
        
        for cl in top_clusters:
            cluster_df = df.iloc[cl['indices']]
            best_row = cluster_df.sort_values("weight", ascending=False).iloc[0]
                
            u_norm = normalize_url(best_row['url'])
            if u_norm not in seen_urls:
                evidence.append({
                    "title": best_row['title'],
                    "url": best_row['url'],
                    "domain": best_row['domain'],
                    "weight": best_row['weight'],
                    "is_tier1": best_row['weight'] >= 0.8
                })
                seen_urls.add(u_norm)

        return {
            "volume": int(len(df)),
            "clusters": int(unique_stories),
            "valid_unique_domains": int(len(unique_domains_valid)),
            "escalation_score": float(min(score, 100)),
            "confidence": round(confidence, 2),
            "top_clusters": top_clusters[:3],
            "evidence": evidence
        }

    def _empty_result(self):
        return {"volume": 0, "clusters": 0, "valid_unique_domains": 0, "escalation_score": 0, 
                "confidence": 0, "top_clusters": [], "evidence": []}

analyzer = DataAnalyzer()

# --- Sidebar ---
with st.sidebar:
    st.header("⚙️ הגדרות סנסור")
    
    api_key_input = st.secrets.get("GOOGLE_API_KEY")
    if not api_key_input:
        api_key_input = st.text_input("Google API Key", type="password")
    
    st.divider()
    st.subheader("📡 טווחי זמן")
    attack_date = st.date_input("תאריך אירוע עבר (Reference):", datetime.date(2025, 6, 15))
    today_date = st.date_input("תאריך נוכחי (Live):", datetime.date(2025, 12, 28))
    window = st.slider("חלון סריקה (ימים):", 7, 45, 20)
    
    est_calls = (window + 1) * 2
    st.caption(f"📊 צפי קריאות API: {est_calls}")
    if est_calls > 60:
        st.markdown("<span class='metric-warning'>⚠️ שים לב ל-Quota</span>", unsafe_allow_html=True)

    st.divider()
    validation_mode = st.radio("רמת אימות:", ["Strict", "Relaxed"], index=1)
    
    keywords = st.text_input("מילות חיפוש:", "Iran Israel military conflict missile attack nuclear")

# --- Execution & Logic ---
if 'scan_results' not in st.session_state: st.session_state.scan_results = None

def execute_scan():
    if not api_key_input:
        st.error("חסר מפתח API")
        return

    scanner = GeminiScanner(api_key_input)
    
    ref_dates = [attack_date - datetime.timedelta(days=i) for i in range(window, -1, -1)]
    live_dates = [today_date - datetime.timedelta(days=i) for i in range(window, -1, -1)]
    
    status_text = st.empty()
    prog_bar = st.progress(0)
    
    total_tasks = len(ref_dates) + len(live_dates)
    completed = 0
    results_map = {}

    def process_day(d):
        raw_data, cached = scanner.fetch_day(d, keywords, validation_mode)
        analytics = analyzer.analyze(raw_data.get('items', []))
        return {
            "date_obj": d,
            "date": d.strftime('%d/%m'),
            "raw": raw_data,
            "analytics": analytics,
            "cached": cached
        }

    all_dates = ref_dates + live_dates
    # שימוש ב-Thread Pool לביצועים מהירים
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
        future_to_date = {executor.submit(process_day, d): d for d in all_dates}
        
        for future in concurrent.futures.as_completed(future_to_date):
            d = future_to_date[future]
            try:
                res = future.result()
                if d in ref_dates:
                    delta = (attack_date - d).days
                    res['day_offset'] = -delta
                    res['type'] = 'Reference'
                else:
                    delta = (today_date - d).days
                    res['day_offset'] = -delta
                    res['type'] = 'Live'
                    
                results_map[f"{res['type']}_{d}"] = res
                completed += 1
                prog_bar.progress(completed / total_tasks)
                status_text.text(f"Processed: {d.strftime('%d/%m')} ({res['type']})")
                
            except Exception as exc:
                logger.error(f"{d} Exception: {exc}")

    past_timeline = sorted([v for k,v in results_map.items() if v['type'] == 'Reference'], key=lambda x: x['day_offset'])
    curr_timeline = sorted([v for k,v in results_map.items() if v['type'] == 'Live'], key=lambda x: x['day_offset'])

    # סיכום מנהלים (עם Prompt מוקשח)
    past_scores = [x['analytics']['escalation_score'] for x in past_timeline]
    curr_scores = [x['analytics']['escalation_score'] for x in curr_timeline]
    
    correlation = 0
    if len(past_scores) > 1 and len(curr_scores) > 1 and np.std(past_scores) > 0 and np.std(curr_scores) > 0:
        correlation = np.corrcoef(past_scores, curr_scores)[0, 1]
    
    avg_conf = np.mean([x['analytics']['confidence'] for x in curr_timeline]) if curr_timeline else 0
    
    last_evidence = []
    if curr_timeline:
        recent_days = sorted(curr_timeline, key=lambda x: x['date'], reverse=True)[:3]
        for day in recent_days:
            for ev in day['analytics']['evidence']:
                last_evidence.append(f"{ev['title']} ({ev['domain']})")

    summary_text = ""
    try:
        status_text.text("Generating Final Assessment...")
        summary_prompt = f"""
        אתה אנליסט OSINT מומחה.
        תפקידך: לסכם את מגמות הדיווח הפומבי בלבד.
        מגבלות קריטיות:
        1. אסור להזכיר SIGINT, HUMINT או מקורות מסווגים.
        2. אסור לתת המלצות אופרטיביות או לנבא תאריכי תקיפה.
        3. בצע ניתוח על בסיס הנתונים הסטטיסטיים והכותרות שסופקו להלן בלבד.

        נתונים:
        - מתאם לעבר (Correlation): {correlation:.2f}
        - רמת אמינות מידע נוכחית (Confidence): {avg_conf:.2f}
        
        כותרות בולטות מהימים האחרונים (Evidence):
        {json.dumps(last_evidence[:15], ensure_ascii=False)} 

        מבנה תשובה רצוי:
        1. **ניתוח העקומה:** האם רואים הלימה לדפוס ההסלמה בעבר?
        2. **אמינות הסיגנל:** האם המידע מגיע ממקורות חזקים או שיש מיעוט דיווחים? (התייחס ל-Confidence).
        3. **נושאים מובילים:** מהם הנרטיבים המרכזיים שחוזרים בכותרות?
        """
        resp = scanner.client.models.generate_content(
            model="gemini-3-pro-preview",
            contents=summary_prompt,
            config=types.GenerateContentConfig(temperature=0.1)
        )
        summary_text = resp.text
    except Exception as e:
        summary_text = f"Could not generate summary: {e}"

    st.session_state.scan_results = {
        "past": past_timeline,
        "curr": curr_timeline,
        "summary": summary_text
    }
    status_text.empty()
    prog_bar.empty()

if st.button("🚀 הפעל ניתוח מבצעי (Run Parallel)", type="primary"):
    execute_scan()

# --- Rendering ---
if st.session_state.scan_results:
    res = st.session_state.scan_results
    past = res['past']
    curr = res['curr']
    
    st.divider()
    st.subheader("📈 תמונת מודיעין")
    
    fig = make_subplots(specs=[[{"secondary_y": True}]])
    fig.add_trace(go.Scatter(x=[x['day_offset'] for x in past], y=[x['analytics']['escalation_score'] for x in past], name="Ref Score", line=dict(color='#ef5350', width=2, dash='dot')), secondary_y=False)
    fig.add_trace(go.Scatter(x=[x['day_offset'] for x in curr], y=[x['analytics']['escalation_score'] for x in curr], name="Live Score", line=dict(color='#4285f4', width=3)), secondary_y=False)
    fig.add_trace(go.Bar(x=[x['day_offset'] for x in curr], y=[x['analytics']['confidence'] for x in curr], name="Confidence", marker_color='rgba(66, 133, 244, 0.2)'), secondary_y=True)
    
    fig.update_layout(title="Escalation vs Reliability", hovermode="x unified")
    fig.update_yaxes(title_text="Score", secondary_y=False)
    fig.update_yaxes(title_text="Conf", range=[0,1], secondary_y=True)
    st.plotly_chart(fig, use_container_width=True)
    
    # Export
    st.divider()
    c_ex1, c_ex2 = st.columns(2)
    export_data = []
    for p in past + curr:
        export_data.append({
            "type": p['type'], "date": p['date'],
            "score": p['analytics']['escalation_score'],
            "confidence": p['analytics']['confidence'],
            "clusters": len(p['analytics']['top_clusters']),
            "error": p['raw'].get('error', '')
        })
    df_export = pd.DataFrame(export_data)
    with c_ex1: st.download_button("📥 הורד נתונים (CSV)", df_export.to_csv(index=False).encode('utf-8'), "report.csv", "text/csv")
    with c_ex2: st.download_button("📥 הורד נתונים (JSON)", json.dumps(export_data, default=str).encode('utf-8'), "report.json", "application/json")

    # Evidence Locker
    st.subheader("🔍 חקר ראיות")
    c1, c2 = st.columns(2)
    
    def render_timeline_col(timeline):
        for item in timeline:
            day = item['analytics']
            meta = item
            conf_icon = "🟢" if day['confidence'] > 0.6 else "🟠" if day['confidence'] > 0.3 else "🔴"
            err_mark = "⚠️" if meta['raw'].get('error') else ""
            
            with st.expander(f"{meta['date']} | Score: {day['escalation_score']:.0f} | Conf: {day['confidence']} {conf_icon} {err_mark}"):
                if meta['raw'].get('error'): st.error(meta['raw']['error'])
                
                if day['evidence']:
                    st.markdown("**🔗 ראיות נבחרות:**")
                    for ev in day['evidence']:
                        t1_mark = "⭐" if ev.get("is_tier1") else ""
                        st.markdown(f"<a href='{ev.get('url','')}' target='_blank' class='evidence-link'>{t1_mark} {ev.get('title','')} <span style='color:#777'>({ev.get('domain','')})</span></a>", unsafe_allow_html=True)
                else:
                    st.caption("אין ראיות מאומתות.")
                
                dbg = meta['raw'].get("debug", {})
                if dbg:
                    st.markdown(f"<div class='debug-info'>Fetched: {dbg.get('fetched',0)} | Valid: {dbg.get('valid',0)} | Cached: {meta.get('cached', False)}</div>", unsafe_allow_html=True)

    with c1: st.markdown("### Reference"); render_timeline_col(past)
    with c2: st.markdown("### Live"); render_timeline_col(curr)

    st.divider()
    st.subheader("🧠 הערכת מצב (Gemini 3 Pro)")
    if res.get('summary'): st.markdown(res['summary'])
    else: st.caption("No summary generated.")
