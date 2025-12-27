# app.py
import streamlit as st
import datetime as dt
import time
import json
import sqlite3
import hashlib
import logging
import random
import threading
import queue
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from io import BytesIO

import numpy as np
import pandas as pd

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from google import genai
from google.genai import types

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN

# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("osint_sentinel")

# -----------------------------
# Config
# -----------------------------
@dataclass(frozen=True)
class Config:
    APP_TITLE: str = "🛡️ OSINT Sentinel: Platinum v1.5.2"
    DB_FILE: str = "osint_plat_v1_5_2.db"

    MAX_WORKERS: int = 3
    MAX_RETRIES: int = 3

    # Rate limiting (token bucket)
    RATE_PER_SEC: float = 0.8     # ~48/min
    BURST: float = 2.0            # allow small bursts

    # Strict mode: allow domain-match only if weight >= threshold
    STRICT_DOMAIN_WEIGHT_THRESHOLD: float = 0.80
    STRICT_FALLBACK_MAX_ITEMS: int = 2  # if strict yields 0, salvage top-weight domain matches

    # similarity clustering
    DBSCAN_EPS: float = 0.45      # cosine distance for tfidf (tune if needed)
    DBSCAN_MIN_SAMPLES: int = 2

    # Noise / propaganda / aggregators
    AGGREGATOR_SUFFIXES: Set[str] = frozenset({
        "news.google.com", "google.com", "msn.com", "yahoo.com", "bing.com",
        "vertexaisearch.cloud.google.com", "webcache.googleusercontent.com"
    })

    BLACKLIST_DOMAINS: Set[str] = frozenset({
        "news.google.com", "google.com", "msn.com", "yahoo.com", "bing.com",
        "vertexaisearch.cloud.google.com", "webcache.googleusercontent.com",
        # examples of noisy/low-signal sources you flagged
        "mronline.org", "alwaght.net", "presstv.ir", "sputniknews.com"
    })

    # Source weights (tune freely)
    DOMAIN_WEIGHTS: Dict[str, float] = None
    DEFAULT_WEIGHT: float = 0.35

    FLASH_MODEL: str = "gemini-3-flash-preview"
    PRO_MODEL: str = "gemini-3-pro-preview"

    # Trend/anomaly
    ROLLING_WIN: int = 3
    ANOM_Z: float = 2.0

# fill dict after dataclass creation
Config.DOMAIN_WEIGHTS = {
    "reuters.com": 1.0, "apnews.com": 1.0, "bbc.com": 1.0, "cnn.com": 0.9,
    "ynet.co.il": 0.85, "haaretz.co.il": 0.85, "timesofisrael.com": 0.85,
    "jpost.com": 0.80, "maariv.co.il": 0.75, "walla.co.il": 0.75,
    "aljazeera.com": 0.70, "tasnimnews.com": 0.60, "isna.ir": 0.60,
    "iranintl.com": 0.65
}

# -----------------------------
# UI setup
# -----------------------------
st.set_page_config(layout="wide", page_title=Config.APP_TITLE)

# Mandatory disclaimer (as requested)
st.warning("""
⚖️ **הצהרת אחריות**
מערכת זו נועדה למחקר ואנליזה של מידע פומבי בלבד.
אין להשתמש במידע למטרות בלתי חוקיות.
המשתמש אחראי לציות לכל החוקים הרלוונטיים.
""")

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
        font-size: 0.9em; display: block; margin-bottom: 4px;
        text-decoration: none; color: #0066cc;
    }
    .evidence-link:hover { text-decoration: underline; }
    .debug-info {
        font-size: 0.78em; color: #666; margin-top: 8px;
        border-top: 1px dashed #ccc; padding-top: 6px;
    }
    .metric-warning { color: #d9534f; font-weight: bold; font-size: 0.9em; }
</style>
""", unsafe_allow_html=True)

st.title(Config.APP_TITLE)
st.caption("Advanced OSINT analytics (public sources only). No operational advice, no predictions.")

# -----------------------------
# Helpers: safe serialization
# -----------------------------
def to_serializable(obj: Any) -> Any:
    """Make objects JSON-serializable (fixes your export TypeError)."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (dt.date, dt.datetime)):
        return obj.isoformat()
    if isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    if isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    if isinstance(obj, (np.ndarray,)):
        return obj.tolist()
    if isinstance(obj, (set, frozenset, tuple, list)):
        return [to_serializable(x) for x in list(obj)]
    if isinstance(obj, dict):
        return {str(k): to_serializable(v) for k, v in obj.items()}
    # pandas timestamp
    if hasattr(obj, "to_pydatetime"):
        try:
            return obj.to_pydatetime().isoformat()
        except Exception:
            pass
    return str(obj)

# -----------------------------
# URL / domain utils
# -----------------------------
def get_domain(url: str) -> str:
    try:
        if not url:
            return ""
        d = urlparse(url).netloc.lower()
        if d.startswith("www."):
            d = d[4:]
        return d
    except Exception:
        return ""

def is_aggregator_domain(d: str) -> bool:
    if not d:
        return False
    d = d.lower().replace("www.", "")
    return any(d == s or d.endswith("." + s) for s in Config.AGGREGATOR_SUFFIXES)

def normalize_url(u: str) -> str:
    """Stronger canonicalization to reduce mismatch between grounded URLs and model output."""
    try:
        if not u:
            return ""
        p = urlparse(u.strip())
        scheme = (p.scheme or "https").lower()
        netloc = p.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]

        path = p.path.rstrip("/")

        # common canonical fixes
        if path.endswith("/amp"):
            path = path[:-4]
        if path.endswith("/index.html"):
            path = path[:-11]

        drop_keys = {
            "fbclid", "gclid", "ref", "ref_src", "ocid",
            "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"
        }
        q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
             if k.lower() not in drop_keys and not k.lower().startswith("utm_")]
        query = urlencode(q, doseq=True)

        return urlunparse((scheme, netloc, path, "", query, ""))
    except Exception:
        return u or ""

def domain_weight(domain: str) -> float:
    d = (domain or "").lower().replace("www.", "")
    if not d:
        return Config.DEFAULT_WEIGHT
    # exact or suffix match
    if d in Config.DOMAIN_WEIGHTS:
        return Config.DOMAIN_WEIGHTS[d]
    for k, w in Config.DOMAIN_WEIGHTS.items():
        if d.endswith("." + k):
            return w
    return Config.DEFAULT_WEIGHT

# -----------------------------
# Rate limiter (token bucket)
# -----------------------------
class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: float):
        self.rate = float(rate_per_sec)
        self.capacity = float(burst)
        self.tokens = float(burst)
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self, tokens: float = 1.0):
        while True:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.updated
                self.updated = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return

                need = tokens - self.tokens
                wait_s = need / self.rate if self.rate > 0 else 1.0

            # sleep outside the lock
            time.sleep(max(0.05, wait_s))

rate_limiter = TokenBucket(Config.RATE_PER_SEC, Config.BURST)

# -----------------------------
# Retry with exponential backoff + jitter
# -----------------------------
def retry_with_backoff(retries: int = Config.MAX_RETRIES, base: float = 0.6):
    def deco(fn):
        def wrapper(*args, **kwargs):
            for attempt in range(retries + 1):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    if attempt >= retries:
                        raise
                    sleep = (base * (2 ** attempt)) + random.uniform(0.0, 0.6)
                    logger.warning(f"Retry {attempt+1}/{retries} after error: {e} (sleep {sleep:.2f}s)")
                    time.sleep(sleep)
        return wrapper
    return deco

# -----------------------------
# SQLite connection pool + DB manager
# -----------------------------
class SQLitePool:
    def __init__(self, db_file: str, pool_size: int = 4):
        self.db_file = db_file
        self.q = queue.Queue(maxsize=pool_size)
        for _ in range(pool_size):
            conn = sqlite3.connect(self.db_file, check_same_thread=False, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA busy_timeout=5000;")
            self.q.put(conn)

    def get(self) -> sqlite3.Connection:
        return self.q.get()

    def put(self, conn: sqlite3.Connection):
        self.q.put(conn)

db_pool = SQLitePool(Config.DB_FILE, pool_size=max(4, Config.MAX_WORKERS + 1))

class DatabaseManager:
    def __init__(self):
        self._init_db()

    def _init_db(self):
        conn = db_pool.get()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS daily_scans (
                    scan_date TEXT,
                    query_hash TEXT,
                    raw_json TEXT,
                    updated_at TEXT,
                    PRIMARY KEY (scan_date, query_hash)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    ts TEXT,
                    ref_anchor TEXT,
                    live_anchor TEXT,
                    window_days INTEGER,
                    validation_mode TEXT,
                    keywords TEXT
                )
            """)
            conn.commit()
        finally:
            db_pool.put(conn)

    def get_data(self, date_str: str, query_hash: str) -> Optional[Dict[str, Any]]:
        conn = db_pool.get()
        try:
            cur = conn.cursor()
            cur.execute("SELECT raw_json FROM daily_scans WHERE scan_date=? AND query_hash=?", (date_str, query_hash))
            row = cur.fetchone()
            if not row:
                return None
            return json.loads(row[0])
        finally:
            db_pool.put(conn)

    def save_data(self, date_str: str, query_hash: str, data: Dict[str, Any]) -> None:
        conn = db_pool.get()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO daily_scans (scan_date, query_hash, raw_json, updated_at)
                VALUES (?, ?, ?, ?)
            """, (date_str, query_hash, json.dumps(to_serializable(data), ensure_ascii=False), dt.datetime.now().isoformat()))
            conn.commit()
        finally:
            db_pool.put(conn)

    def audit(self, ref_anchor: dt.date, live_anchor: dt.date, window_days: int, validation_mode: str, keywords: str):
        conn = db_pool.get()
        try:
            conn.execute("""
                INSERT INTO audit_log (ts, ref_anchor, live_anchor, window_days, validation_mode, keywords)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                dt.datetime.now().isoformat(),
                ref_anchor.isoformat(),
                live_anchor.isoformat(),
                int(window_days),
                str(validation_mode),
                str(keywords)
            ))
            conn.commit()
        finally:
            db_pool.put(conn)

db = DatabaseManager()

# -----------------------------
# Gemini scanner
# -----------------------------
class GeminiScanner:
    def __init__(self, api_key: str):
        self.client = genai.Client(api_key=api_key)

    def _extract_grounding(self, response) -> Tuple[Set[str], Set[str]]:
        urls_norm: Set[str] = set()
        domains: Set[str] = set()
        try:
            if not getattr(response, "candidates", None):
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

                if uri and isinstance(uri, str) and uri.startswith("http"):
                    u = normalize_url(uri)
                    urls_norm.add(u)
                    d = get_domain(uri)
                    if d and not is_aggregator_domain(d):
                        domains.add(d)

                # sometimes domain appears in title
                if title and "." in title and " " not in title:
                    d2 = title.lower().replace("www.", "")
                    if len(d2) > 3 and not is_aggregator_domain(d2):
                        domains.add(d2)
        except Exception:
            pass
        return urls_norm, domains

    @retry_with_backoff()
    def fetch_day(self, date_obj: dt.date, keywords: str, mode: str) -> Tuple[Dict[str, Any], bool]:
        date_str = date_obj.isoformat()
        query_hash = hashlib.md5((date_str + keywords + mode + "v1.5.2").encode("utf-8")).hexdigest()

        cached = db.get_data(date_str, query_hash)
        if cached is not None:
            return cached, True

        after = date_obj
        before = date_obj + dt.timedelta(days=1)
        search_query = f'{keywords} after:{after.isoformat()} before:{before.isoformat()}'

        prompt = f"""
ROLE: OSINT Data Extractor.
TASK: Find specific news items for DATE: {date_str}.
QUERY: "{search_query}"

INSTRUCTIONS:
1. Return the publisher’s CANONICAL URL (direct publisher page).
2. DO NOT return google.com/news.google.com/msn.com redirect links.
3. Output JSON only, strict schema.

SCHEMA:
{{
  "items": [
    {{ "title": "...", "source": "...", "url": "...", "snippet": "..." }}
  ]
}}
"""

        tool = types.Tool(google_search=types.GoogleSearch())

        # rate limit BEFORE API call
        rate_limiter.acquire()

        response = self.client.models.generate_content(
            model=Config.FLASH_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.0,
                response_mime_type="application/json",
                tools=[tool]
            )
        )

        grounded_urls, grounded_domains = self._extract_grounding(response)

        # parse model JSON
        raw_items: List[Dict[str, Any]] = []
        try:
            raw = json.loads(response.text)
            raw_items = raw.get("items", []) or []
        except Exception:
            raw_items = []

        validated: List[Dict[str, Any]] = []
        reasons = {"url_match": 0, "domain_match": 0, "tier1_domain_match": 0, "blacklist": 0, "aggregator": 0}

        # primary validation pass
        for it in raw_items:
            u = (it.get("url") or "").strip()
            if not u:
                continue
            u_norm = normalize_url(u)
            d = get_domain(u_norm)

            if not d or is_aggregator_domain(d):
                reasons["aggregator"] += 1
                continue
            if d in Config.BLACKLIST_DOMAINS:
                reasons["blacklist"] += 1
                continue

            ok = False
            if u_norm in grounded_urls:
                ok = True
                reasons["url_match"] += 1
            else:
                # domain-based validation (hybrid strict)
                if d in grounded_domains:
                    if mode == "Relaxed":
                        ok = True
                        reasons["domain_match"] += 1
                    else:
                        # Strict: allow ONLY if Tier1/high weight
                        if domain_weight(d) >= Config.STRICT_DOMAIN_WEIGHT_THRESHOLD:
                            ok = True
                            reasons["tier1_domain_match"] += 1

            if ok:
                it["url"] = u_norm
                validated.append(it)

        # strict fallback: if we got ZERO but grounding exists, salvage a couple of high-weight domain matches
        if mode == "Strict" and not validated and raw_items and grounded_domains:
            candidates = []
            for it in raw_items:
                u = (it.get("url") or "").strip()
                if not u:
                    continue
                u_norm = normalize_url(u)
                d = get_domain(u_norm)
                if not d or is_aggregator_domain(d) or d in Config.BLACKLIST_DOMAINS:
                    continue
                if d in grounded_domains:
                    candidates.append((domain_weight(d), u_norm, it))
            candidates.sort(reverse=True, key=lambda x: x[0])
            for w, u_norm, it in candidates[:Config.STRICT_FALLBACK_MAX_ITEMS]:
                it["url"] = u_norm
                validated.append(it)

        out = {
            "items": validated,
            "error": None,
            "debug": {
                "date": date_str,
                "raw_items": len(raw_items),
                "validated": len(validated),
                "grounded_urls": len(grounded_urls),
                "grounded_domains": len(grounded_domains),
                "mode": mode,
                "reasons": reasons
            }
        }

        db.save_data(date_str, query_hash, out)
        return out, False

# -----------------------------
# Analyzer (dedupe + clustering + scoring)
# -----------------------------
class DataAnalyzer:
    def _fp(self, title: str, snippet: str) -> str:
        raw = (title.lower().strip() + "||" + snippet.lower().strip()).encode("utf-8")
        return hashlib.sha1(raw).hexdigest()

    def analyze(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not items:
            return self._empty()

        df = pd.DataFrame(items)

        for col in ["title", "snippet", "url", "source"]:
            if col not in df.columns:
                df[col] = ""
            df[col] = df[col].fillna("").astype(str)

        df["url_norm"] = df["url"].apply(normalize_url)
        df["domain"] = df["url_norm"].apply(get_domain)

        # hard filters
        df = df[~df["domain"].isin(Config.BLACKLIST_DOMAINS)]
        df = df[~df["domain"].apply(is_aggregator_domain)]

        if df.empty:
            return self._empty()

        # strong dedupe: URL + content fingerprint
        df["fp"] = df.apply(lambda r: self._fp(r["title"], r["snippet"]), axis=1)
        df = df.drop_duplicates(subset=["url_norm", "fp"])

        if df.empty:
            return self._empty()

        # weights
        df["weight"] = df["domain"].apply(domain_weight)
        df["text"] = (df["title"] + " " + df["snippet"]).str.strip()

        clusters = self._cluster_dbscan(df)

        unique_domains = set(df["domain"].unique()) - {""}
        unique_stories = len(clusters)

        weighted_volume = float(df["weight"].sum())
        avg_cluster_quality = float(np.mean([c["max_weight"] for c in clusters])) if clusters else 0.0
        avg_sources_per_story = float(np.mean([c["unique_domains"] for c in clusters])) if clusters else 0.0

        # score (bounded)
        score = (unique_stories * 3.0) + (weighted_volume * 5.0) + (avg_cluster_quality * 20.0) + (avg_sources_per_story * 4.0)
        score = float(min(score, 100.0))

        # confidence (continuous)
        domain_count = len(unique_domains)
        scarcity = 1.0
        if domain_count < 4:
            scarcity *= (domain_count / 4.0)
        if unique_stories < 2:
            scarcity *= 0.6
        conf = float(max(0.05, min(1.0, avg_cluster_quality * scarcity)))

        # evidence: best row per top clusters
        evidence = []
        seen = set()
        top = sorted(clusters, key=lambda c: (c["max_weight"], c["count"]), reverse=True)[:6]
        for cl in top:
            part = df.iloc[cl["indices"]].copy()
            part = part.sort_values("weight", ascending=False)
            row = part.iloc[0]
            if row["url_norm"] in seen:
                continue
            seen.add(row["url_norm"])
            evidence.append({
                "title": row["title"],
                "url": row["url_norm"],
                "domain": row["domain"],
                "weight": float(row["weight"]),
                "is_tier1": bool(row["weight"] >= 0.80)
            })

        return {
            "volume": int(len(df)),
            "clusters": int(unique_stories),
            "valid_unique_domains": int(len(unique_domains)),
            "escalation_score": score,
            "confidence": round(conf, 2),
            "top_clusters": top[:3],
            "evidence": evidence
        }

    def _cluster_dbscan(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        texts = df["text"].fillna("").astype(str).tolist()
        if len(texts) == 1:
            return [{
                "main_title": df.iloc[0]["title"],
                "count": 1,
                "unique_domains": 1,
                "max_weight": float(df.iloc[0]["weight"]),
                "indices": [0]
            }]

        # Optional: sentence-transformers embeddings
        use_embeddings = False
        embeddings = None
        try:
            from sentence_transformers import SentenceTransformer  # optional dependency
            model = SentenceTransformer("all-MiniLM-L6-v2")
            embeddings = model.encode(texts, normalize_embeddings=True)
            use_embeddings = True
        except Exception:
            use_embeddings = False

        if use_embeddings and embeddings is not None:
            X = np.asarray(embeddings)
            # cosine distance in DBSCAN with metric="cosine"
            cl = DBSCAN(eps=0.30, min_samples=Config.DBSCAN_MIN_SAMPLES, metric="cosine").fit(X)
            labels = cl.labels_
        else:
            # TFIDF -> DBSCAN cosine
            vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
            X = vec.fit_transform(texts)
            cl = DBSCAN(eps=Config.DBSCAN_EPS, min_samples=Config.DBSCAN_MIN_SAMPLES, metric="cosine").fit(X)
            labels = cl.labels_

        clusters: List[Dict[str, Any]] = []
        visited_labels = set(labels.tolist())

        # label -1 = noise -> treat each as singleton
        for lab in visited_labels:
            idxs = np.where(labels == lab)[0].tolist()
            if lab == -1:
                for i in idxs:
                    clusters.append({
                        "main_title": df.iloc[i]["title"],
                        "count": 1,
                        "unique_domains": 1,
                        "max_weight": float(df.iloc[i]["weight"]),
                        "indices": [int(i)]
                    })
            else:
                part = df.iloc[idxs]
                clusters.append({
                    "main_title": part.iloc[0]["title"],
                    "count": int(len(part)),
                    "unique_domains": int(part["domain"].nunique()),
                    "max_weight": float(part["weight"].max()),
                    "indices": [int(i) for i in idxs]
                })
        return clusters

    def _empty(self) -> Dict[str, Any]:
        return {
            "volume": 0, "clusters": 0, "valid_unique_domains": 0,
            "escalation_score": 0.0, "confidence": 0.0,
            "top_clusters": [], "evidence": []
        }

analyzer = DataAnalyzer()

# -----------------------------
# Trend + anomaly
# -----------------------------
def compute_trends(scores: List[float]) -> Dict[str, List[float]]:
    s = pd.Series(scores, dtype=float)
    roll = s.rolling(Config.ROLLING_WIN, min_periods=1).mean()
    mom = s.diff().fillna(0.0)
    mu = float(s.mean()) if len(s) else 0.0
    sd = float(s.std(ddof=0)) if len(s) else 0.0
    z = ((s - mu) / sd) if sd > 1e-9 else pd.Series([0.0] * len(s))
    return {
        "rolling": roll.tolist(),
        "momentum": mom.tolist(),
        "z": z.tolist()
    }

def corr(a: List[float], b: List[float]) -> float:
    if len(a) < 2 or len(b) < 2:
        return 0.0
    if np.std(a) < 1e-9 or np.std(b) < 1e-9:
        return 0.0
    return float(np.corrcoef(a, b)[0, 1])

# -----------------------------
# Secrets only for API key
# -----------------------------
API_KEY = st.secrets.get("GOOGLE_API_KEY", "")
if not API_KEY:
    st.error("חסר GOOGLE_API_KEY ב־st.secrets. אין אפשרות להזין מפתח דרך הממשק.")
    st.stop()

# -----------------------------
# Sidebar
# -----------------------------
with st.sidebar:
    st.header("⚙️ הגדרות סנסור")
    st.divider()

    st.subheader("📡 טווחי זמן")
    reference_anchor = st.date_input("תאריך אירוע עבר (Reference):", dt.date(2025, 6, 15))
    live_anchor = st.date_input("תאריך נוכחי (Live):", dt.date(2025, 12, 28))
    window_days = st.slider("חלון סריקה (ימים):", 7, 45, 15)

    st.caption(f"📊 צפי קריאות API: {(window_days+1)*2} (במקביליות: {Config.MAX_WORKERS})")
    if (window_days + 1) * 2 > 60:
        st.markdown("<span class='metric-warning'>⚠️ Quota גבוה</span>", unsafe_allow_html=True)

    st.divider()
    validation_mode = st.radio("רמת אימות:", ["Strict", "Relaxed"], index=0)

    keywords = st.text_input("מילות חיפוש:", "Iran Israel military conflict missile attack nuclear")
    st.caption("המערכת מסכמת שיח תקשורתי בלבד ואינה מפיקה תחזיות/התרעות אופרטיביות.")

# -----------------------------
# Session state
# -----------------------------
if "result" not in st.session_state:
    st.session_state.result = None

# -----------------------------
# Scan logic (concurrent)
# -----------------------------
def scan() -> Dict[str, Any]:
    scanner = GeminiScanner(API_KEY)

    ref_dates = [reference_anchor - dt.timedelta(days=i) for i in range(window_days, -1, -1)]
    live_dates = [live_anchor - dt.timedelta(days=i) for i in range(window_days, -1, -1)]
    all_dates = [("Reference", d) for d in ref_dates] + [("Live", d) for d in live_dates]

    db.audit(reference_anchor, live_anchor, window_days, validation_mode, keywords)

    status = st.empty()
    prog = st.progress(0)
    done = 0
    total = len(all_dates)

    def process(kind: str, d: dt.date) -> Dict[str, Any]:
        raw, cached = scanner.fetch_day(d, keywords, validation_mode)
        analytics = analyzer.analyze(raw.get("items", []))
        day_offset = -(reference_anchor - d).days if kind == "Reference" else -(live_anchor - d).days
        return {
            "type": kind,
            "day_offset": int(day_offset),
            "date": d.strftime("%d/%m"),
            "date_iso": d.isoformat(),
            "cached": bool(cached),
            "raw": raw,
            "analytics": analytics
        }

    results: List[Dict[str, Any]] = []
    # ThreadPool
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as ex:
        futures = {ex.submit(process, kind, d): (kind, d) for kind, d in all_dates}
        for fut in concurrent.futures.as_completed(futures):
            kind, d = futures[fut]
            try:
                results.append(fut.result())
            except Exception as e:
                logger.error(f"Failed day {kind} {d}: {e}")
                results.append({
                    "type": kind,
                    "day_offset": 0,
                    "date": d.strftime("%d/%m"),
                    "date_iso": d.isoformat(),
                    "cached": False,
                    "raw": {"items": [], "error": str(e), "debug": {"date": d.isoformat()}},
                    "analytics": analyzer._empty()
                })
            done += 1
            prog.progress(done / total)
            status.text(f"Processed {kind} {d.strftime('%d/%m')} ({done}/{total})")

    status.empty()
    prog.empty()

    reference = sorted([r for r in results if r["type"] == "Reference"], key=lambda x: x["day_offset"])
    live = sorted([r for r in results if r["type"] == "Live"], key=lambda x: x["day_offset"])

    ref_scores = [float(x["analytics"]["escalation_score"]) for x in reference]
    live_scores = [float(x["analytics"]["escalation_score"]) for x in live]

    ref_tr = compute_trends(ref_scores)
    live_tr = compute_trends(live_scores)

    live_conf = [float(x["analytics"]["confidence"]) for x in live]
    avg_conf_live = float(np.mean(live_conf)) if live_conf else 0.0
    live_max = float(np.max(live_scores)) if live_scores else 0.0
    live_anoms = [i for i, z in enumerate(live_tr["z"]) if abs(float(z)) >= Config.ANOM_Z]
    c = corr(ref_scores, live_scores)

    meta = {
        "generated_at": dt.datetime.now().isoformat(),
        "keywords": keywords,
        "validation_mode": validation_mode,
        "window_days": int(window_days),
        "reference_anchor": reference_anchor.isoformat(),
        "live_anchor": live_anchor.isoformat(),
        "models": {"flash": Config.FLASH_MODEL, "pro": Config.PRO_MODEL},
        "kpis": {
            "correlation": round(c, 2),
            "avg_confidence_live": round(avg_conf_live, 2),
            "live_max_score": round(live_max, 2),
            "live_anomaly_count": int(len(live_anoms))
        }
    }

    return {
        "meta": meta,
        "reference": reference,
        "live": live,
        "trends": {"reference": ref_tr, "live": live_tr, "live_anomaly_idx": live_anoms}
    }

# -----------------------------
# Run button
# -----------------------------
if st.button("🚀 הפעל ניתוח (Run)", type="primary"):
    st.session_state.result = scan()

# -----------------------------
# Render
# -----------------------------
res = st.session_state.result
if res:
    meta = res["meta"]
    ref = res["reference"]
    live = res["live"]
    tr_ref = res["trends"]["reference"]
    tr_live = res["trends"]["live"]
    live_anoms = set(res["trends"]["live_anomaly_idx"])

    # KPIs
    st.subheader("📌 KPIs")
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Correlation (Ref↔Live)", meta["kpis"]["correlation"])
    k2.metric("Avg Confidence (Live)", meta["kpis"]["avg_confidence_live"])
    k3.metric("Live Max Score", meta["kpis"]["live_max_score"])
    k4.metric(f"Live Anomalies (|z|≥{Config.ANOM_Z})", meta["kpis"]["live_anomaly_count"])

    # Notification (non-operational)
    if meta["kpis"]["live_max_score"] >= 60 and meta["kpis"]["avg_confidence_live"] >= 0.6:
        st.info("נראה עליה משמעותית בשיח ובאיכות המקורות (OSINT בלבד). מומלץ להמשיך מעקב ולהצליב מקורות.")

    # Plot
    st.divider()
    st.subheader("📈 תמונת מודיעין (Score + Confidence + Trend)")

    x_ref = [x["day_offset"] for x in ref]
    y_ref = [x["analytics"]["escalation_score"] for x in ref]
    x_live = [x["day_offset"] for x in live]
    y_live = [x["analytics"]["escalation_score"] for x in live]
    c_live = [x["analytics"]["confidence"] for x in live]

    fig = make_subplots(specs=[[{"secondary_y": True}]])
    fig.add_trace(go.Scatter(x=x_ref, y=y_ref, name="Ref Score", line=dict(width=2, dash="dot")), secondary_y=False)
    fig.add_trace(go.Scatter(x=x_live, y=y_live, name="Live Score", line=dict(width=3)), secondary_y=False)
    fig.add_trace(go.Scatter(x=x_live, y=tr_live["rolling"], name="Live Rolling Avg", line=dict(width=2, dash="dash")), secondary_y=False)
    fig.add_trace(go.Bar(x=x_live, y=c_live, name="Confidence", opacity=0.25), secondary_y=True)

    # anomaly markers
    anom_x = [x_live[i] for i in range(len(x_live)) if i in live_anoms]
    anom_y = [y_live[i] for i in range(len(y_live)) if i in live_anoms]
    if anom_x:
        fig.add_trace(go.Scatter(x=anom_x, y=anom_y, name="Anomaly", mode="markers", marker=dict(size=10, symbol="x")), secondary_y=False)

    fig.update_layout(hovermode="x unified")
    fig.update_yaxes(title_text="Score", secondary_y=False, range=[0, 100])
    fig.update_yaxes(title_text="Confidence", secondary_y=True, range=[0, 1])
    st.plotly_chart(fig, use_container_width=True)

    # Evidence Locker + Filters
    st.divider()
    st.subheader("🔍 חקר ראיות (Evidence Locker)")

    f1, f2, f3 = st.columns([1.2, 1.0, 1.0])
    with f1:
        q = st.text_input("חיפוש בתוך כותרות/דומיינים:", "")
    with f2:
        only_tier1 = st.checkbox("הצג רק Tier1/High-weight", value=False)
    with f3:
        only_anoms = st.checkbox("הצג רק ימים חריגים (Live)", value=False)

    def match_filters(day: Dict[str, Any], is_live: bool, idx_live: int) -> bool:
        ev = day["analytics"].get("evidence", []) or []
        blob = " ".join([(e.get("title","") + " " + e.get("domain","")) for e in ev]).lower()
        if q.strip() and q.lower() not in blob:
            return False
        if only_tier1:
            if not any(float(e.get("weight", 0.0)) >= Config.STRICT_DOMAIN_WEIGHT_THRESHOLD for e in ev):
                return False
        if only_anoms and is_live:
            return idx_live in live_anoms
        if only_anoms and not is_live:
            return False
        return True

    c1, c2 = st.columns(2)

    def render_timeline(tl: List[Dict[str, Any]], title: str, is_live: bool):
        st.markdown(f"### {title}")
        for idx, day in enumerate(tl):
            a = day["analytics"]
            conf = float(a.get("confidence", 0.0))
            score = float(a.get("escalation_score", 0.0))
            icon = "🟢" if conf >= 0.6 else ("🟠" if conf >= 0.3 else "🔴")
            err = (day.get("raw", {}) or {}).get("error")

            if not match_filters(day, is_live=is_live, idx_live=idx):
                continue

            tag = " ⚠️" if err else ""
            anom_tag = " ✳️" if (is_live and idx in live_anoms) else ""
            with st.expander(f"{day['date']} | Score: {score:.0f} | Conf: {conf:.2f} {icon}{anom_tag}{tag}"):
                if err:
                    st.error(err)

                evidence = a.get("evidence", []) or []
                if evidence:
                    for e in evidence:
                        star = "⭐" if e.get("is_tier1") else ""
                        st.markdown(
                            f"<a class='evidence-link' href='{e.get('url','')}' target='_blank'>"
                            f"{star} {e.get('title','')} <span style='color:#777'>({e.get('domain','')})</span>"
                            f"</a>",
                            unsafe_allow_html=True
                        )
                else:
                    st.caption("אין ראיות מאומתות.")

                dbg = (day.get("raw", {}) or {}).get("debug", {}) or {}
                if dbg:
                    st.markdown(
                        "<div class='debug-info'>"
                        f"Raw: {dbg.get('raw_items',0)} | Validated: {dbg.get('validated',0)} | "
                        f"GroundedDomains: {dbg.get('grounded_domains',0)} | Mode: {dbg.get('mode','')}"
                        "</div>",
                        unsafe_allow_html=True
                    )

    with c1:
        render_timeline(ref, "Reference", is_live=False)
    with c2:
        render_timeline(live, "Live", is_live=True)

    # -----------------------------
    # Executive summary (OSINT-only)
    # -----------------------------
    st.divider()
    st.subheader("🧠 הערכת מצב (OSINT בלבד)")

    # keep summary non-operational, no forecasting
    try:
        client = genai.Client(api_key=API_KEY)
        live_tail = live[-7:] if len(live) >= 7 else live
        summary_input = {
            "kpis": meta["kpis"],
            "live_last_days": [
                {
                    "date": d["date_iso"],
                    "score": d["analytics"]["escalation_score"],
                    "confidence": d["analytics"]["confidence"],
                    "domains": d["analytics"]["valid_unique_domains"],
                    "evidence": d["analytics"]["evidence"]
                } for d in live_tail
            ]
        }

        rate_limiter.acquire()
        resp = client.models.generate_content(
            model=Config.PRO_MODEL,
            contents=f"""
אתה אנליסט OSINT בכיר. חשוב: אין לתת תחזיות תקיפה, אין לתת ייעוץ אופרטיבי.
תנתח רק מגמות בשיח תקשורתי ומידת אמינות המקורות.
נתונים:
{json.dumps(to_serializable(summary_input), ensure_ascii=False)}
פלט בעברית, מבנה:
1) מה מאומת
2) מה לא מאומת/רעש
3) מגמות קצרות טווח בשיח
4) המלצות מחקר להמשך (OSINT בלבד)
""",
            config=types.GenerateContentConfig(temperature=0.2)
        )
        st.write(resp.text)
    except Exception as e:
        st.info("לא הצלחתי להפיק תקציר מודל (ייתכן Quota/שגיאת API).")
        st.caption(str(e))

    # -----------------------------
    # Export (JSON/CSV/Excel) - fixed
    # -----------------------------
    st.divider()
    st.subheader("⬇️ יצוא דו״ח")

    export_obj = {
        "meta": meta,
        "reference": ref,
        "live": live,
        "trends": res["trends"]
    }

    export_json = json.dumps(to_serializable(export_obj), ensure_ascii=False, indent=2).encode("utf-8")
    st.download_button(
        "Download JSON",
        data=export_json,
        file_name="osint_report.json",
        mime="application/json"
    )

    # summary table
    def flatten(tl: List[Dict[str, Any]]) -> pd.DataFrame:
        rows = []
        for d in tl:
            a = d["analytics"]
            rows.append({
                "type": d["type"],
                "date": d["date_iso"],
                "day_offset": d["day_offset"],
                "score": float(a.get("escalation_score", 0.0)),
                "confidence": float(a.get("confidence", 0.0)),
                "volume": int(a.get("volume", 0)),
                "clusters": int(a.get("clusters", 0)),
                "unique_domains": int(a.get("valid_unique_domains", 0)),
                "error": (d.get("raw", {}) or {}).get("error")
            })
        return pd.DataFrame(rows)

    df_out = pd.concat([flatten(ref), flatten(live)], ignore_index=True)
    st.download_button(
        "Download CSV",
        data=df_out.to_csv(index=False).encode("utf-8"),
        file_name="osint_report_summary.csv",
        mime="text/csv"
    )

    bio = BytesIO()
    with pd.ExcelWriter(bio, engine="openpyxl") as writer:
        df_out.to_excel(writer, index=False, sheet_name="summary")
    st.download_button(
        "Download Excel",
        data=bio.getvalue(),
        file_name="osint_report_summary.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )