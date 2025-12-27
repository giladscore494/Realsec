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
import threading
import io
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


# =========================
# Config & Logging
# =========================
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class Config:
    APP_TITLE = "🛡️ OSINT Sentinel: Platinum v1.5.1"
    DB_FILE = "osint_plat_v1_5_1.db"

    # Concurrency
    MAX_WORKERS = 3
    MAX_RETRIES = 3

    # Rate limiting (shared across threads)
    # תכוון לפי ה-quota שלך. זה מונע burst.
    MAX_CALLS_PER_MINUTE = 25

    # חסימת רעש/אגרגטורים/תעמולה
    BLACKLIST_DOMAINS = {
        "news.google.com", "google.com", "msn.com", "yahoo.com", "bing.com",
        "vertexaisearch.cloud.google.com", "webcache.googleusercontent.com",
        "mronline.org", "alwaght.net", "presstv.ir", "sputniknews.com",
    }

    AGGREGATOR_SUFFIXES = {
        "news.google.com", "google.com", "msn.com", "yahoo.com", "bing.com",
        "vertexaisearch.cloud.google.com", "webcache.googleusercontent.com",
    }

    # משקולות למקורות
    DOMAIN_WEIGHTS = {
        "reuters.com": 1.0, "apnews.com": 1.0, "bbc.com": 1.0, "cnn.com": 0.9,
        "ynet.co.il": 0.85, "haaretz.co.il": 0.85, "timesofisrael.com": 0.85,
        "jpost.com": 0.80, "maariv.co.il": 0.75, "walla.co.il": 0.75,
        "aljazeera.com": 0.70, "tasnimnews.com": 0.60, "isna.ir": 0.60,
        "iranintl.com": 0.65,
    }
    DEFAULT_WEIGHT = 0.35


# =========================
# Page Setup
# =========================
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
    המערכת מציגה סטטיסטיקה של שיח תקשורתי ואינה מספקת התרעות צבאיות, תחזיות תקיפה או ייעוץ אופרטיבי.
</div>
""", unsafe_allow_html=True)

st.title(Config.APP_TITLE)
st.caption("Advanced OSINT I&W: Concurrency-safe, Rate-limited, Weighted Evidence + Trends/Anomalies")


# =========================
# Helpers
# =========================
def normalize_url(u: str) -> str:
    try:
        if not u:
            return ""
        p = urlparse(u.strip())
        netloc = p.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        path = p.path.rstrip("/")
        drop_keys = {"fbclid", "gclid", "ref", "ref_src", "utm_source", "utm_medium", "utm_campaign", "ocid"}
        q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
             if k.lower() not in drop_keys and not k.lower().startswith("utm_")]
        query = urlencode(q, doseq=True)
        return urlunparse((p.scheme.lower() or "https", netloc, path, "", query, ""))
    except Exception:
        return u or ""


def get_domain(url: str) -> str:
    try:
        if not url:
            return ""
        d = urlparse(url).netloc.lower()
        return d[4:] if d.startswith("www.") else d
    except Exception:
        return ""


def is_aggregator_domain(d: str) -> bool:
    if not d:
        return False
    d = d.lower().replace("www.", "")
    return any(d == s or d.endswith("." + s) for s in Config.AGGREGATOR_SUFFIXES)


def _looks_like_quota_error(e: Exception) -> bool:
    msg = str(e).lower()
    return any(k in msg for k in ["429", "resource_exhausted", "quota", "rate limit", "too many requests"])


def retry_with_backoff(
    retries: int = Config.MAX_RETRIES,
    base_backoff_sec: float = 1.0,
):
    def decorator(func):
        def wrapper(*args, **kwargs):
            for attempt in range(retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt >= retries:
                        logger.error(f"Failed after {retries} retries: {e}")
                        raise
                    # exponential backoff + jitter (יותר אגרסיבי ב-quota)
                    mult = 2.5 if _looks_like_quota_error(e) else 2.0
                    sleep = (base_backoff_sec * (mult ** attempt)) + random.uniform(0, 0.75)
                    time.sleep(min(sleep, 20))
            raise RuntimeError("Unreachable")
        return wrapper
    return decorator


class RateLimiter:
    """Leaky-bucket פשוט: מגביל מספר קריאות לדקה (משותף לכל הthreads)."""
    def __init__(self, max_calls_per_minute: int):
        self.max_calls = max_calls_per_minute
        self.lock = threading.Lock()
        self.calls: List[float] = []  # timestamps (monotonic)

    def acquire(self):
        with self.lock:
            now = time.monotonic()
            window_start = now - 60.0
            # drop old
            self.calls = [t for t in self.calls if t >= window_start]
            if len(self.calls) < self.max_calls:
                self.calls.append(now)
                return
            # need to wait until earliest expires
            earliest = min(self.calls) if self.calls else now
            wait = (earliest + 60.0) - now
        # sleep outside lock
        if wait > 0:
            time.sleep(wait + random.uniform(0, 0.25))
        # retry acquire
        self.acquire()


rate_limiter = RateLimiter(Config.MAX_CALLS_PER_MINUTE)


# =========================
# DB Manager + Audit
# =========================
class DatabaseManager:
    def __init__(self, db_file: str):
        self.db_file = db_file
        self._init_db()

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_file, check_same_thread=False, timeout=30)
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self.get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS daily_scans (
                    scan_date TEXT,
                    query_hash TEXT,
                    raw_json TEXT,
                    updated_at TIMESTAMP,
                    PRIMARY KEY (scan_date, query_hash)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    ts TIMESTAMP,
                    keywords TEXT,
                    validation_mode TEXT,
                    window_days INTEGER,
                    ref_date TEXT,
                    live_date TEXT
                )
            """)
            conn.commit()

    def get_data(self, date_str: str, query_hash: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT raw_json FROM daily_scans WHERE scan_date=? AND query_hash=?",
                (date_str, query_hash),
            )
            row = cur.fetchone()
            return json.loads(row[0]) if row else None

    def save_data(self, date_str: str, query_hash: str, data: Dict[str, Any]) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO daily_scans (scan_date, query_hash, raw_json, updated_at)
                VALUES (?, ?, ?, ?)
            """, (date_str, query_hash, json.dumps(data), datetime.datetime.now()))
            conn.commit()

    def audit(self, keywords: str, validation_mode: str, window_days: int, ref_date: str, live_date: str) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO audit_log (ts, keywords, validation_mode, window_days, ref_date, live_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (datetime.datetime.now(), keywords, validation_mode, window_days, ref_date, live_date))
            conn.commit()


db_manager = DatabaseManager(Config.DB_FILE)


# =========================
# Gemini Scanner (thread-safe)
# =========================
class GeminiScanner:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self._local = threading.local()

    def _client(self):
        if not hasattr(self._local, "client"):
            self._local.client = genai.Client(api_key=self.api_key)
        return self._local.client

    def _extract_grounded_urls(self, response) -> Tuple[Set[str], Set[str]]:
        urls_norm: Set[str] = set()
        domains: Set[str] = set()
        try:
            if not response.candidates:
                return urls_norm, domains
            gm = response.candidates[0].grounding_metadata
            if not gm:
                return urls_norm, domains

            chunks = getattr(gm, "grounding_chunks", []) or []
            for ch in chunks:
                web = getattr(ch, "web", None)
                if not web:
                    continue

                uri = getattr(web, "uri", None)
                title = getattr(web, "title", None)

                if uri and uri.startswith("http"):
                    urls_norm.add(normalize_url(uri))
                    d = get_domain(uri)
                    if d and not is_aggregator_domain(d):
                        domains.add(d)

                # title fallback: לפעמים זה דומיין אמיתי
                if title and "." in title and " " not in title:
                    d2 = title.lower().replace("www.", "")
                    if len(d2) > 3 and not is_aggregator_domain(d2):
                        domains.add(d2)

        except Exception:
            pass
        return urls_norm, domains

    @retry_with_backoff(retries=Config.MAX_RETRIES, base_backoff_sec=1.0)
    def fetch_day(self, date_obj: datetime.date, keywords: str, mode: str = "Relaxed") -> Tuple[Dict[str, Any], bool]:
        date_str = date_obj.strftime("%Y-%m-%d")
        query_hash = hashlib.md5((date_str + keywords + mode + "v1.5.1").encode()).hexdigest()

        cached = db_manager.get_data(date_str, query_hash)
        if cached:
            return cached, True

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

        # global rate limiter
        rate_limiter.acquire()

        response = self._client().models.generate_content(
            model="gemini-3-flash-preview",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.0,
                response_mime_type="application/json",
                tools=[tool],
            ),
        )

        grounded_norm, grounded_domains = self._extract_grounded_urls(response)

        try:
            raw_data = json.loads(response.text)
            raw_items = raw_data.get("items", [])
        except Exception:
            raw_items = []

        if (grounded_norm or grounded_domains) and not raw_items:
            err_data = {"items": [], "error": "EMPTY_ITEMS_WITH_GROUNDING"}
            db_manager.save_data(date_str, query_hash, err_data)
            return err_data, False

        if not grounded_norm and not grounded_domains:
            empty_data = {"items": [], "error": "NO_GROUNDING_SOURCES"}
            db_manager.save_data(date_str, query_hash, empty_data)
            return empty_data, False

        validated_items: List[Dict[str, Any]] = []
        for item in raw_items:
            u = item.get("url", "")
            if not u:
                continue
            u_norm = normalize_url(u)
            u_domain = get_domain(u)

            if is_aggregator_domain(u_domain):
                continue
            if u_domain in Config.BLACKLIST_DOMAINS:
                continue

            is_valid = False
            if u_norm in grounded_norm:
                is_valid = True
            elif mode == "Relaxed" and u_domain in grounded_domains:
                is_valid = True

            if is_valid:
                validated_items.append(item)

        final_data = {
            "items": validated_items,
            "debug": {
                "fetched": len(raw_items),
                "grounded_sources": len(grounded_norm),
                "grounded_domains": len(grounded_domains),
                "valid": len(validated_items),
            },
        }
        db_manager.save_data(date_str, query_hash, final_data)
        return final_data, False


# =========================
# Analyzer
# =========================
class DataAnalyzer:
    def _fingerprint(self, title: str, snippet: str) -> str:
        raw = (title.lower().strip() + "||" + snippet.lower().strip()).encode("utf-8")
        return hashlib.sha1(raw).hexdigest()

    def analyze(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not items:
            return self._empty()

        df = pd.DataFrame(items)

        for col in ["title", "snippet", "url"]:
            if col not in df.columns:
                df[col] = ""
            df[col] = df[col].fillna("").astype(str)

        df["domain"] = df["url"].apply(get_domain)
        df = df[~df["domain"].isin(Config.BLACKLIST_DOMAINS)]
        df = df[~df["domain"].apply(is_aggregator_domain)]

        # content dedup
        df["fp"] = df.apply(lambda r: self._fingerprint(r["title"], r["snippet"]), axis=1)
        df = df.drop_duplicates("fp")

        # url dedup
        df["url_norm"] = df["url"].apply(normalize_url)
        df = df.drop_duplicates("url_norm")

        if df.empty:
            return self._empty()

        df["weight"] = df["domain"].map(Config.DOMAIN_WEIGHTS).fillna(Config.DEFAULT_WEIGHT)
        df["text"] = (df["title"] + " " + df["snippet"]).str.strip()

        # clustering (נשאר TF-IDF כי זה "קל ליישום", אבל עטוף ובטוח)
        clusters: List[Dict[str, Any]] = []
        if len(df) > 1 and df["text"].str.len().sum() > 0:
            vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
            tfidf = vectorizer.fit_transform(df["text"])
            sim = cosine_similarity(tfidf)

            visited: Set[int] = set()
            for i in range(len(df)):
                if i in visited:
                    continue
                idxs = [i]
                visited.add(i)
                for j in range(i + 1, len(df)):
                    if j in visited:
                        continue
                    if sim[i][j] > 0.55:
                        idxs.append(j)
                        visited.add(j)

                part = df.iloc[idxs]
                clusters.append({
                    "main_title": part.iloc[0]["title"],
                    "count": int(len(part)),
                    "unique_domains": int(part["domain"].nunique()),
                    "max_weight": float(part["weight"].max()),
                    "indices": idxs,
                })
        else:
            clusters = [{
                "main_title": df.iloc[0]["title"],
                "count": 1,
                "unique_domains": 1,
                "max_weight": float(df.iloc[0]["weight"]),
                "indices": [0],
            }]

        unique_domains = set(df["domain"].unique()) - {""}
        unique_stories = len(clusters)

        weighted_volume = float(df["weight"].sum())
        avg_cluster_quality = float(np.mean([c["max_weight"] for c in clusters])) if clusters else 0.0

        score = (unique_stories * 3.0) + (weighted_volume * 5.0) + (avg_cluster_quality * 20.0)
        score = float(min(score, 100))

        # confidence continuous
        domain_count = len(unique_domains)
        scarcity_penalty = 1.0
        if domain_count < 4:
            scarcity_penalty *= (domain_count / 4)
        if unique_stories < 2:
            scarcity_penalty *= 0.6

        confidence = float(max(0.1, min(1.0, avg_cluster_quality * scarcity_penalty)))

        # evidence
        evidence: List[Dict[str, Any]] = []
        top_clusters = sorted(clusters, key=lambda x: (x["max_weight"], x["count"]), reverse=True)[:5]
        seen_urls: Set[str] = set()

        for cl in top_clusters:
            cluster_df = df.iloc[cl["indices"]]
            best_row = cluster_df.sort_values("weight", ascending=False).iloc[0]
            u_norm = best_row["url_norm"]
            if u_norm in seen_urls:
                continue
            evidence.append({
                "title": best_row["title"],
                "url": best_row["url"],
                "domain": best_row["domain"],
                "weight": float(best_row["weight"]),
                "is_tier1": float(best_row["weight"]) >= 0.8,
            })
            seen_urls.add(u_norm)

        return {
            "volume": int(len(df)),
            "clusters": int(unique_stories),
            "valid_unique_domains": int(len(unique_domains)),
            "escalation_score": score,
            "confidence": round(confidence, 2),
            "top_clusters": top_clusters[:3],
            "evidence": evidence,
        }

    def _empty(self) -> Dict[str, Any]:
        return {
            "volume": 0,
            "clusters": 0,
            "valid_unique_domains": 0,
            "escalation_score": 0.0,
            "confidence": 0.0,
            "top_clusters": [],
            "evidence": [],
        }


analyzer = DataAnalyzer()


# =========================
# Sidebar (secrets only)
# =========================
with st.sidebar:
    st.header("⚙️ הגדרות סנסור")

    api_key = st.secrets.get("GOOGLE_API_KEY")
    if not api_key:
        st.error("חסר GOOGLE_API_KEY ב-st.secrets (אין הזנה ידנית מטעמי אבטחה).")
        st.stop()

    st.divider()
    st.subheader("📡 טווחי זמן")
    attack_date = st.date_input("תאריך אירוע עבר (Reference):", datetime.date(2025, 6, 15))
    today_date = st.date_input("תאריך נוכחי (Live):", datetime.date(2025, 12, 28))
    window = st.slider("חלון סריקה (ימים):", 7, 45, 20)

    est_calls = (window + 1) * 2
    st.caption(f"📊 צפי קריאות API: {est_calls} (במקביליות: {Config.MAX_WORKERS})")
    if est_calls > 60:
        st.markdown("<span class='metric-warning'>⚠️ שים לב ל-Quota</span>", unsafe_allow_html=True)

    st.divider()
    validation_mode = st.radio("רמת אימות:", ["Strict", "Relaxed"], index=1)
    keywords = st.text_input("מילות חיפוש:", "Iran Israel military conflict missile attack nuclear")

    st.divider()
    run_btn = st.button("🚀 הפעל סריקה", type="primary")


# =========================
# Scan Execution
# =========================
if "results" not in st.session_state:
    st.session_state.results = None
if "summary" not in st.session_state:
    st.session_state.summary = None


def _build_summary_prompt(correlation: float, avg_conf: float, live_days: List[Dict[str, Any]]) -> str:
    # רק ראיות — בלי הזיות על HUMINT/SIGINT ובלי תחזיות/עצות
    lines = []
    for d in live_days[-7:]:
        ev = d.get("analytics", {}).get("evidence", [])[:3]
        lines.append(f"- {d.get('date','')}: score={d.get('analytics',{}).get('escalation_score',0):.1f}, conf={d.get('analytics',{}).get('confidence',0)}")
        for e in ev:
            lines.append(f"  • {e.get('domain','')}: {e.get('title','')} | {e.get('url','')}")
    evidence_block = "\n".join(lines)

    return f"""
אתה אנליסט OSINT. אתה רשאי להשתמש אך ורק בראיות שסופקו (כותרות+דומיינים+URL).
אסור להזכיר או להניח שימוש במקורות מסווגים (HUMINT/SIGINT) או לתת ייעוץ אופרטיבי.
אסור לתת תחזיות תקיפה/תאריכים. מותר רק לתאר מגמות בשיח והוודאות שלהן.

מדדים:
- Correlation(ref, live) = {correlation:.2f}
- Avg confidence (live) = {avg_conf:.2f}

ראיות (7 ימים אחרונים):
{evidence_block}

תוציא בעברית, במבנה:
1) מה מאומת (עם הפניות לדומיינים מהראיות)
2) מה לא מאומת/רעש
3) מגמות קצרות טווח בשיח (ללא ניבוי)
4) שאלות מעקב לאיסוף (מה עוד לחפש)
""".strip()


def execute_scan() -> None:
    scanner = GeminiScanner(api_key)

    ref_dates = [attack_date - datetime.timedelta(days=i) for i in range(window, -1, -1)]
    live_dates = [today_date - datetime.timedelta(days=i) for i in range(window, -1, -1)]
    all_dates = ref_dates + live_dates

    db_manager.audit(
        keywords=keywords,
        validation_mode=validation_mode,
        window_days=int(window),
        ref_date=str(attack_date),
        live_date=str(today_date),
    )

    status = st.empty()
    prog = st.progress(0)

    total = len(all_dates)
    done = 0
    results: List[Dict[str, Any]] = []

    def process_day(d: datetime.date) -> Dict[str, Any]:
        raw_data, cached = scanner.fetch_day(d, keywords, validation_mode)
        analytics = analyzer.analyze(raw_data.get("items", []))
        return {
            "date_obj": d,
            "date": d.strftime("%d/%m"),
            "raw": raw_data,
            "analytics": analytics,
            "cached": cached,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as ex:
        future_to_date = {ex.submit(process_day, d): d for d in all_dates}
        for fut in concurrent.futures.as_completed(future_to_date):
            d = future_to_date[fut]
            try:
                res = fut.result()
                if d in ref_dates:
                    delta = (attack_date - d).days
                    res["day_offset"] = -delta
                    res["type"] = "Reference"
                else:
                    delta = (today_date - d).days
                    res["day_offset"] = -delta
                    res["type"] = "Live"

                results.append(res)
            except Exception as e:
                logger.error(f"Day failed {d}: {e}")
            finally:
                done += 1
                prog.progress(done / total)
                status.text(f"Processed {done}/{total} | {d.strftime('%d/%m')}")

    status.empty()
    prog.empty()

    past = sorted([r for r in results if r["type"] == "Reference"], key=lambda x: x["day_offset"])
    live = sorted([r for r in results if r["type"] == "Live"], key=lambda x: x["day_offset"])

    # Trend + anomaly on live
    live_scores = np.array([x["analytics"]["escalation_score"] for x in live], dtype=float)
    live_conf = np.array([x["analytics"]["confidence"] for x in live], dtype=float)

    def moving_avg(arr: np.ndarray, n: int) -> np.ndarray:
        if len(arr) < n:
            return np.full(len(arr), np.nan)
        s = pd.Series(arr)
        return s.rolling(n).mean().to_numpy()

    ma3 = moving_avg(live_scores, 3)
    ma7 = moving_avg(live_scores, 7)

    # z-score anomalies vs MA7
    baseline = pd.Series(live_scores).rolling(7).mean()
    std = pd.Series(live_scores).rolling(7).std(ddof=0)
    z = ((pd.Series(live_scores) - baseline) / std.replace(0, np.nan)).fillna(0).to_numpy()
    anomaly = np.abs(z) >= 2.0

    for i, r in enumerate(live):
        r["trend"] = {
            "ma3": None if np.isnan(ma3[i]) else float(ma3[i]),
            "ma7": None if np.isnan(ma7[i]) else float(ma7[i]),
            "z": float(z[i]),
            "anomaly": bool(anomaly[i]),
        }

    # similarity metric
    past_scores = [x["analytics"]["escalation_score"] for x in past]
    corr = 0.0
    if len(past_scores) > 1 and len(live_scores) > 1:
        if np.std(past_scores) > 0 and np.std(live_scores) > 0:
            corr = float(np.corrcoef(past_scores, live_scores)[0, 1])

    avg_conf = float(np.mean(live_conf)) if len(live_conf) else 0.0

    # Summary with Pro
    with st.spinner("Gemini Pro מסכם (OSINT בלבד)..."):
        pro_client = genai.Client(api_key=api_key)
        summary_prompt = _build_summary_prompt(corr, avg_conf, live)
        resp = pro_client.models.generate_content(
            model="gemini-3-pro-preview",
            contents=summary_prompt,
            config=types.GenerateContentConfig(temperature=0.2),
        )
        summary_text = getattr(resp, "text", "") or ""

    st.session_state.results = {"past": past, "live": live, "corr": corr, "avg_conf": avg_conf}
    st.session_state.summary = summary_text


if run_btn:
    execute_scan()


# =========================
# Render
# =========================
res = st.session_state.results
if res:
    past = res["past"]
    live = res["live"]
    corr = res["corr"]
    avg_conf = res["avg_conf"]

    st.divider()
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Correlation (Ref↔Live)", f"{corr:.2f}")
    k2.metric("Avg Confidence (Live)", f"{avg_conf:.2f}")
    k3.metric("Live Max Score", f"{max([x['analytics']['escalation_score'] for x in live] + [0]):.0f}")
    k4.metric("Live Anomalies (|z|≥2)", str(sum(1 for x in live if x.get("trend", {}).get("anomaly"))))

    # chart
    st.subheader("📈 תמונת מודיעין (Score + Confidence + Trend)")
    fig = make_subplots(specs=[[{"secondary_y": True}]])

    fig.add_trace(go.Scatter(
        x=[x["day_offset"] for x in past],
        y=[x["analytics"]["escalation_score"] for x in past],
        name="Ref Score",
        line=dict(dash="dot"),
    ), secondary_y=False)

    fig.add_trace(go.Scatter(
        x=[x["day_offset"] for x in live],
        y=[x["analytics"]["escalation_score"] for x in live],
        name="Live Score",
    ), secondary_y=False)

    fig.add_trace(go.Bar(
        x=[x["day_offset"] for x in live],
        y=[x["analytics"]["confidence"] for x in live],
        name="Confidence",
        opacity=0.25,
    ), secondary_y=True)

    # Moving averages
    ma3 = [x.get("trend", {}).get("ma3") for x in live]
    ma7 = [x.get("trend", {}).get("ma7") for x in live]
    fig.add_trace(go.Scatter(
        x=[x["day_offset"] for x in live],
        y=[v if v is not None else np.nan for v in ma3],
        name="MA(3)",
    ), secondary_y=False)
    fig.add_trace(go.Scatter(
        x=[x["day_offset"] for x in live],
        y=[v if v is not None else np.nan for v in ma7],
        name="MA(7)",
    ), secondary_y=False)

    fig.update_layout(hovermode="x unified")
    fig.update_yaxes(title_text="Score", secondary_y=False)
    fig.update_yaxes(title_text="Conf", range=[0, 1], secondary_y=True)

    st.plotly_chart(fig, use_container_width=True)

    # evidence explorers
    st.divider()
    st.subheader("🔍 חקר ראיות (Evidence Locker)")
    c1, c2 = st.columns(2)

    def render_timeline(tl: List[Dict[str, Any]]):
        for day in tl:
            a = day["analytics"]
            conf = float(a.get("confidence", 0))
            conf_icon = "🟢" if conf > 0.6 else "🟠" if conf > 0.3 else "🔴"
            err = day.get("raw", {}).get("error")
            err_mark = "⚠️" if err else ""
            anom = "🚨" if day.get("trend", {}).get("anomaly") else ""

            title = f"{day.get('date','')} | Score: {a.get('escalation_score',0):.0f} | Conf: {conf:.2f} {conf_icon} {err_mark} {anom}"
            with st.expander(title):
                if err:
                    st.error(err)

                ev = a.get("evidence", [])
                if ev:
                    st.markdown("**🔗 ראיות נבחרות:**")
                    for e in ev:
                        t1 = "⭐" if e.get("is_tier1") else ""
                        st.markdown(
                            f"<a href='{e.get('url','')}' target='_blank' class='evidence-link'>"
                            f"{t1} [{e.get('weight',0):.2f}] {e.get('title','')} "
                            f"<span style='color:#777'>({e.get('domain','')})</span></a>",
                            unsafe_allow_html=True
                        )
                else:
                    st.caption("אין ראיות מאומתות.")

                dbg = day.get("raw", {}).get("debug", {}) or {}
                if dbg:
                    st.markdown(
                        f"<div class='debug-info'>"
                        f"Fetched: {dbg.get('fetched',0)} | "
                        f"GroundedDomains: {dbg.get('grounded_domains',0)} | "
                        f"Valid: {dbg.get('valid',0)} | "
                        f"UniqueDomains: {a.get('valid_unique_domains',0)}"
                        f"</div>",
                        unsafe_allow_html=True
                    )

    with c1:
        st.markdown("### Reference")
        render_timeline(past)

    with c2:
        st.markdown("### Live")
        render_timeline(live)

    # summary
    st.divider()
    st.subheader("🧠 הערכת מצב (OSINT בלבד)")
    st.write(st.session_state.summary or "")

    # exports
    st.divider()
    st.subheader("⬇️ יצוא דו״ח")
    export_obj = {
        "meta": {
            "ref_date": str(attack_date),
            "live_date": str(today_date),
            "window_days": int(window),
            "keywords": keywords,
            "validation_mode": validation_mode,
            "correlation": corr,
            "avg_confidence_live": avg_conf,
        },
        "reference": past,
        "live": live,
        "summary": st.session_state.summary or "",
    }

    st.download_button(
        "Download JSON",
        data=json.dumps(export_obj, ensure_ascii=False, indent=2).encode("utf-8"),
        file_name="osint_sentinel_report.json",
        mime="application/json",
    )

    # Flatten to CSV
    flat_rows = []
    for day in past + live:
        a = day["analytics"]
        flat_rows.append({
            "type": day["type"],
            "date": day["date"],
            "day_offset": day["day_offset"],
            "score": a.get("escalation_score", 0),
            "confidence": a.get("confidence", 0),
            "valid_unique_domains": a.get("valid_unique_domains", 0),
            "anomaly": day.get("trend", {}).get("anomaly", False),
            "z": day.get("trend", {}).get("z", 0.0),
        })
    csv_df = pd.DataFrame(flat_rows)
    st.download_button(
        "Download CSV (daily metrics)",
        data=csv_df.to_csv(index=False).encode("utf-8"),
        file_name="osint_sentinel_daily.csv",
        mime="text/csv",
    )
