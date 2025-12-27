# app.py
# ============================================================
# 🛡️ OSINT Sentinel: Platinum v1.5.2 (FULL FIXED)
# - Fix: JSON export (non-serializable objects)
# - Fix: Retry actually works (no swallowed exceptions)
# - Fix: Grounding extraction logs + SDK field fallbacks
# - Fix: Avoid caching technical failures (prevents "all zeros forever")
# - Add: Concurrency + rate limiter + cache controls
# - Add: Trends + anomalies (z-score) + KPIs
# ============================================================

from __future__ import annotations

import datetime as dt
import json
import hashlib
import logging
import random
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd
import streamlit as st
from contextlib import contextmanager
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from google import genai
from google.genai import types

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN


# ----------------------------
# Logging
# ----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger("osint_sentinel")


# ----------------------------
# Config
# ----------------------------
@dataclass(frozen=True)
class Config:
    APP_TITLE: str = "🛡️ OSINT Sentinel: Platinum v1.5.2"
    DB_FILE: str = "osint_plat_v1_5_2.db"

    # Gemini models
    FLASH_MODEL: str = "gemini-3-flash-preview"
    PRO_MODEL: str = "gemini-3-pro-preview"

    # Concurrency / rate
    MAX_WORKERS: int = 3              # threads
    MAX_RETRIES: int = 4              # retries per day
    BASE_BACKOFF_SEC: float = 1.0     # exponential backoff base
    RATE_QPS: float = 0.8             # approx queries per second across all threads
    RATE_BURST: int = 2               # burst tokens

    # Filtering
    AGGREGATOR_SUFFIXES: Set[str] = frozenset({
        "news.google.com", "google.com", "msn.com", "yahoo.com", "bing.com",
        "vertexaisearch.cloud.google.com", "webcache.googleusercontent.com"
    })

    BLACKLIST_DOMAINS: Set[str] = frozenset({
        # add your noisy/propaganda sources here
        "mronline.org", "alwaght.net", "presstv.ir", "sputniknews.com",
        # aggregators (redundant safety)
        "news.google.com", "google.com", "msn.com", "yahoo.com", "bing.com",
        "vertexaisearch.cloud.google.com", "webcache.googleusercontent.com",
    })

    # Domain weights (simple reliability heuristic)
    DOMAIN_WEIGHTS: Dict[str, float] = None  # set below
    DEFAULT_WEIGHT: float = 0.35

    # Similarity / clustering
    DBSCAN_EPS: float = 0.55     # cosine distance eps; tune as needed
    DBSCAN_MIN_SAMPLES: int = 1

    # Anomalies
    ANOMALY_Z_THRESHOLD: float = 2.0

    # Export
    EXPORT_MAX_ITEMS_PER_DAY: int = 50


# init weights
Config.DOMAIN_WEIGHTS = {
    "reuters.com": 1.00, "apnews.com": 1.00, "bbc.com": 1.00,
    "cnn.com": 0.90,
    "ynet.co.il": 0.85, "haaretz.co.il": 0.85, "timesofisrael.com": 0.85,
    "jpost.com": 0.80, "maariv.co.il": 0.75, "walla.co.il": 0.75,
    "aljazeera.com": 0.70,
    "tasnimnews.com": 0.60, "isna.ir": 0.60,
    "iranintl.com": 0.65
}


# ----------------------------
# UI setup
# ----------------------------
st.set_page_config(layout="wide", page_title=Config.APP_TITLE)

st.markdown("""
<style>
    .stTextInput > label, .stSelectbox > label, .stDateInput > label,
    .stSlider > label, .stRadio > label, .stCheckbox > label {
        direction: rtl; text-align: right; font-weight: bold;
    }
    .stMarkdown, div[data-testid="stSidebar"], div[data-testid="stText"], .stExpander {
        direction: rtl; text-align: right;
    }
    h1, h2, h3, h4 { text-align: right; }

    .evidence-link {
        font-size: 0.9em; display: block; margin-bottom: 5px;
        text-decoration: none; color: #0066cc;
    }
    .evidence-link:hover { text-decoration: underline; }
    .debug-info {
        font-size: 0.78em; color: #666; margin-top: 8px;
        border-top: 1px dashed #ccc; padding-top: 6px;
    }
</style>
""", unsafe_allow_html=True)

# חובה לפי הדרישה שלך
st.warning("""
⚖️ **הצהרת אחריות**
מערכת זו נועדה למחקר ואנליזה של מידע פומבי בלבד.
אין להשתמש במידע למטרות בלתי חוקיות.
המשתמש אחראי לציות לכל החוקים הרלוונטיים.
""")

st.title(Config.APP_TITLE)
st.caption("Advanced OSINT I&W: Concurrency-safe, Rate-limited, Weighted Evidence + Trends/Anomalies")


# ----------------------------
# Helpers: URL + domains
# ----------------------------
DROP_KEYS = {
    "fbclid", "gclid", "ref", "ref_src", "ocid",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"
}

def normalize_url(u: str) -> str:
    try:
        if not u:
            return ""
        p = urlparse(u.strip())
        scheme = (p.scheme or "https").lower()
        netloc = (p.netloc or "").lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        path = (p.path or "").rstrip("/")

        q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
             if k.lower() not in DROP_KEYS and not k.lower().startswith("utm_")]
        query = urlencode(q, doseq=True)

        return urlunparse((scheme, netloc, path, "", query, ""))
    except Exception:
        return u or ""

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

def domain_weight(domain: str) -> float:
    if not domain:
        return Config.DEFAULT_WEIGHT
    d = domain.lower().replace("www.", "")
    return float(Config.DOMAIN_WEIGHTS.get(d, Config.DEFAULT_WEIGHT))

def is_blacklisted(domain: str) -> bool:
    if not domain:
        return False
    d = domain.lower().replace("www.", "")
    return (d in Config.BLACKLIST_DOMAINS) or is_aggregator_domain(d)


# ----------------------------
# Safe JSON parsing + export serializer
# ----------------------------
def safe_json_loads(text: str) -> Dict[str, Any]:
    """
    Robust-ish JSON parse:
    - try json.loads
    - else extract first {...} block
    """
    try:
        return json.loads(text)
    except Exception:
        pass

    # extract JSON object
    m = re.search(r"(\{.*\})", text, flags=re.DOTALL)
    if not m:
        raise ValueError("Response is not valid JSON (no object found).")
    return json.loads(m.group(1))

def json_default(o: Any) -> Any:
    if isinstance(o, (dt.datetime, dt.date)):
        return o.isoformat()
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, set):
        return list(o)
    return str(o)


# ----------------------------
# Rate limiter (token bucket)
# ----------------------------
class RateLimiter:
    def __init__(self, rate_qps: float, burst: int) -> None:
        self.rate = float(max(0.01, rate_qps))
        self.capacity = int(max(1, burst))
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.updated
                self.updated = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return

            time.sleep(0.05)


rate_limiter = RateLimiter(Config.RATE_QPS, Config.RATE_BURST)


# ----------------------------
# Retry (exponential backoff + jitter)
# ----------------------------
def is_retryable_error(e: Exception) -> bool:
    msg = str(e).lower()
    # best-effort matching for quota / transient errors
    retry_signals = ["429", "rate", "quota", "temporar", "timeout", "unavailable", "503", "500"]
    return any(s in msg for s in retry_signals)

def retry_with_backoff(max_retries: int, base_backoff: float):
    def deco(fn):
        def wrapped(*args, **kwargs):
            attempt = 0
            while True:
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    attempt += 1
                    if attempt > max_retries or (not is_retryable_error(e) and attempt > 1):
                        logger.exception(f"FAILED after retries={attempt-1}: {e}")
                        raise

                    sleep = (base_backoff * (2 ** (attempt - 1))) + random.uniform(0, 0.7)
                    sleep = min(30.0, sleep)
                    logger.warning(f"Retry {attempt}/{max_retries} in {sleep:.1f}s | err={e}")
                    time.sleep(sleep)
        return wrapped
    return deco


# ----------------------------
# SQLite DB manager (thread-local connections)
# ----------------------------
class DatabaseManager:
    def __init__(self, db_file: str) -> None:
        self.db_file = db_file
        self.local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self.local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_file, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA temp_store=MEMORY;")
            conn.execute("PRAGMA busy_timeout=5000;")
            self.local.conn = conn
        return conn

    @contextmanager
    def conn(self):
        c = self._get_conn()
        try:
            yield c
        finally:
            pass  # keep thread-local open for reuse

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_file) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS daily_scans (
                    scan_date TEXT,
                    query_hash TEXT,
                    raw_json TEXT,
                    ok INTEGER,
                    updated_at TEXT,
                    PRIMARY KEY (scan_date, query_hash)
                )
            """)
            conn.commit()

    def get(self, date_str: str, query_hash: str) -> Optional[Dict[str, Any]]:
        with self.conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT raw_json, ok FROM daily_scans WHERE scan_date=? AND query_hash=?",
                (date_str, query_hash),
            )
            row = cur.fetchone()
            if not row:
                return None
            raw_json, ok = row
            data = json.loads(raw_json)
            data["_cache_ok"] = bool(ok)
            return data

    def put(self, date_str: str, query_hash: str, data: Dict[str, Any], ok: bool) -> None:
        with self.conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO daily_scans (scan_date, query_hash, raw_json, ok, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (date_str, query_hash, json.dumps(data, ensure_ascii=False, default=json_default), int(ok), dt.datetime.now().isoformat()),
            )
            conn.commit()

    def clear_all(self) -> None:
        with sqlite3.connect(self.db_file) as conn:
            conn.execute("DELETE FROM daily_scans")
            conn.commit()


db = DatabaseManager(Config.DB_FILE)


# ----------------------------
# Gemini scanner
# ----------------------------
class GeminiScanner:
    def __init__(self, api_key: str) -> None:
        self.client = genai.Client(api_key=api_key)

    def _extract_grounding(self, response: Any) -> Tuple[Set[str], Set[str]]:
        urls_norm: Set[str] = set()
        domains: Set[str] = set()

        try:
            cands = getattr(response, "candidates", None) or []
            if not cands:
                logger.warning("No candidates in response")
                return urls_norm, domains

            cand0 = cands[0]
            gm = getattr(cand0, "grounding_metadata", None) or getattr(cand0, "groundingMetadata", None)
            if not gm:
                logger.warning("No grounding metadata in candidate")
                return urls_norm, domains

            chunks = getattr(gm, "grounding_chunks", None) or getattr(gm, "groundingChunks", None) or []
            for ch in chunks:
                web = getattr(ch, "web", None)
                if not web:
                    continue
                uri = getattr(web, "uri", None)
                title = getattr(web, "title", None)

                if uri and isinstance(uri, str) and uri.startswith("http"):
                    u_norm = normalize_url(uri)
                    urls_norm.add(u_norm)
                    d = get_domain(uri)
                    if d and not is_aggregator_domain(d):
                        domains.add(d)

                # sometimes domain appears as title (rare)
                if title and isinstance(title, str) and "." in title and " " not in title:
                    d2 = title.lower().replace("www.", "")
                    if len(d2) > 3 and not is_aggregator_domain(d2):
                        domains.add(d2)

        except Exception as e:
            logger.exception(f"Grounding extraction failed: {e}")

        return urls_norm, domains

    @retry_with_backoff(Config.MAX_RETRIES, Config.BASE_BACKOFF_SEC)
    def fetch_day(
        self,
        date_obj: dt.date,
        keywords: str,
        mode: str,
        ignore_cache: bool = False
    ) -> Tuple[Dict[str, Any], bool]:
        date_str = date_obj.strftime("%Y-%m-%d")
        query_hash = hashlib.md5((date_str + "|" + keywords + "|" + mode + "|v1.5.2").encode("utf-8")).hexdigest()

        if not ignore_cache:
            cached = db.get(date_str, query_hash)
            if cached is not None and cached.get("_cache_ok", False):
                cached.pop("_cache_ok", None)
                return cached, True

        after = date_obj
        before = date_obj + dt.timedelta(days=1)
        search_query = f'{keywords} after:{after} before:{before}'

        prompt = f"""
ROLE: OSINT Data Extractor.
TASK: Find specific news items for DATE: {date_str}.
QUERY: "{search_query}"

INSTRUCTIONS:
1) Return the publisher’s CANONICAL URL.
2) DO NOT return google.com, news.google.com, msn.com or redirect links.
3) JSON only (no extra text).

JSON Schema:
{{
  "items": [
    {{ "title":"...", "source":"...", "url":"...", "snippet":"..." }}
  ]
}}
""".strip()

        # global rate limiter across threads
        rate_limiter.acquire()

        tool = types.Tool(google_search=types.GoogleSearch())

        response = self.client.models.generate_content(
            model=Config.FLASH_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.0,
                response_mime_type="application/json",
                tools=[tool],
            ),
        )

        grounded_urls, grounded_domains = self._extract_grounding(response)

        # Parse JSON
        raw_items: List[Dict[str, Any]] = []
        parse_error: Optional[str] = None
        try:
            raw_data = safe_json_loads(getattr(response, "text", "") or "")
            raw_items = raw_data.get("items", []) or []
            if not isinstance(raw_items, list):
                raw_items = []
        except Exception as e:
            parse_error = f"JSON_PARSE_ERROR: {e}"
            raw_items = []

        # Validate items vs grounding
        validated: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        for it in raw_items:
            try:
                u = str(it.get("url", "") or "")
                if not u:
                    continue
                u_norm = normalize_url(u)
                dom = get_domain(u_norm)

                if not dom or is_blacklisted(dom):
                    continue

                # grounding checks
                ok = False
                if u_norm in grounded_urls:
                    ok = True
                elif mode == "Relaxed" and dom in grounded_domains:
                    ok = True

                if not ok:
                    continue

                # dedupe by normalized URL
                if u_norm in seen:
                    continue
                seen.add(u_norm)

                it2 = {
                    "title": str(it.get("title", "") or "").strip(),
                    "source": str(it.get("source", "") or "").strip(),
                    "url": u_norm,
                    "snippet": str(it.get("snippet", "") or "").strip(),
                }
                validated.append(it2)
            except Exception:
                continue

        # Decide cacheability:
        # - If we got a response + grounding metadata exists, this is a real run (cache OK),
        #   even if items are empty (could be legit "no results").
        # - If grounding missing + parse error => treat as technical (do NOT cache OK).
        ok_cache = True
        error: Optional[str] = None

        if parse_error:
            # parse errors are usually transient/tooling; avoid caching "ok"
            ok_cache = False
            error = parse_error

        if (not grounded_urls and not grounded_domains):
            # could be SDK/availability issue -> avoid caching ok
            ok_cache = False
            error = error or "NO_GROUNDING_SOURCES"

        out = {
            "items": validated,
            "error": error,
            "debug": {
                "date": date_str,
                "raw_items": len(raw_items),
                "validated": len(validated),
                "grounded_urls": len(grounded_urls),
                "grounded_domains": len(grounded_domains),
                "mode": mode,
            },
        }

        db.put(date_str, query_hash, out, ok=ok_cache)

        return out, False


# ----------------------------
# Analyzer (DBSCAN clustering + scoring + evidence)
# ----------------------------
class DataAnalyzer:
    @staticmethod
    def _fingerprint(title: str, snippet: str) -> str:
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

        df["url"] = df["url"].map(normalize_url)
        df["domain"] = df["url"].map(get_domain)

        # hard filter
        df = df[~df["domain"].map(is_blacklisted)]
        if df.empty:
            return self._empty()

        # content dedup
        df["fp"] = df.apply(lambda r: self._fingerprint(r["title"], r["snippet"]), axis=1)
        df = df.drop_duplicates("fp")

        # weight
        df["weight"] = df["domain"].map(lambda d: domain_weight(d))

        # text for clustering
        df["text"] = (df["title"] + " " + df["snippet"]).str.strip()
        texts = df["text"].tolist()

        # DBSCAN clustering over TF-IDF (cosine distance)
        labels = np.zeros(len(df), dtype=int)
        if len(df) > 1 and df["text"].str.len().sum() > 0:
            vec = TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=5000)
            X = vec.fit_transform(texts)
            # metric='cosine' uses cosine distance
            model = DBSCAN(eps=Config.DBSCAN_EPS, min_samples=Config.DBSCAN_MIN_SAMPLES, metric="cosine")
            labels = model.fit_predict(X)

        df["cluster_id"] = labels

        clusters: List[Dict[str, Any]] = []
        for cid, part in df.groupby("cluster_id", sort=False):
            clusters.append({
                "cluster_id": int(cid),
                "main_title": part.iloc[0]["title"],
                "count": int(len(part)),
                "unique_domains": int(part["domain"].nunique()),
                "max_weight": float(part["weight"].max()),
                "indices": part.index.tolist(),
            })

        unique_domains = set(df["domain"].unique()) - {""}
        unique_stories = len(clusters)
        weighted_volume = float(df["weight"].sum())
        avg_cluster_quality = float(np.mean([c["max_weight"] for c in clusters])) if clusters else 0.0

        # score
        score = (unique_stories * 3.0) + (weighted_volume * 5.0) + (avg_cluster_quality * 20.0)
        score = float(min(100.0, max(0.0, score)))

        # confidence
        domain_count = len(unique_domains)
        scarcity = 1.0
        if domain_count < 4:
            scarcity *= (domain_count / 4.0) if domain_count > 0 else 0.0
        if unique_stories < 2:
            scarcity *= 0.6
        conf = float(np.clip(avg_cluster_quality * scarcity, 0.0, 1.0))

        # evidence: pick best-weight row per top clusters
        evidence: List[Dict[str, Any]] = []
        top_clusters = sorted(clusters, key=lambda c: (c["max_weight"], c["count"]), reverse=True)[:5]
        seen_urls: Set[str] = set()

        for cl in top_clusters:
            part = df.loc[cl["indices"]].sort_values("weight", ascending=False)
            best = part.iloc[0]
            u = normalize_url(best["url"])
            if u in seen_urls:
                continue
            seen_urls.add(u)
            evidence.append({
                "title": str(best["title"]),
                "url": u,
                "domain": str(best["domain"]),
                "weight": float(best["weight"]),
                "is_tier1": float(best["weight"]) >= 0.80,
            })

        return {
            "volume": int(len(df)),
            "clusters": int(unique_stories),
            "valid_unique_domains": int(len(unique_domains)),
            "escalation_score": score,
            "confidence": float(round(conf, 2)),
            "top_clusters": top_clusters[:3],
            "evidence": evidence,
        }

    @staticmethod
    def _empty() -> Dict[str, Any]:
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


# ----------------------------
# Sidebar (NO API KEY INPUT — secrets only)
# ----------------------------
with st.sidebar:
    st.header("⚙️ הגדרות סנסור")

    api_key = st.secrets.get("GOOGLE_API_KEY", "")
    if not api_key:
        st.error("חסר GOOGLE_API_KEY ב-st.secrets. הוסף ב-.streamlit/secrets.toml ואז רענן.")
        st.stop()

    st.divider()
    st.subheader("📡 טווחי זמן")
    attack_date = st.date_input("תאריך אירוע עבר (Reference):", dt.date(2025, 6, 15))
    today_date = st.date_input("תאריך נוכחי (Live):", dt.date(2025, 12, 28))
    window = st.slider("חלון סריקה (ימים):", 7, 45, 20)

    st.divider()
    validation_mode = st.radio("רמת אימות:", ["Strict", "Relaxed"], index=1)
    keywords = st.text_input("מילות חיפוש:", "Iran Israel military conflict missile attack nuclear")

    st.divider()
    ignore_cache = st.checkbox("התעלם מה-Cache (Force Refresh)", value=False)
    if st.button("🧹 נקה Cache (SQLite)"):
        db.clear_all()
        st.success("Cache נוקה.")

    st.caption(f"📊 צפי קריאות API: {(window+1)*2} | מקביליות: {Config.MAX_WORKERS}")


# ----------------------------
# Scan execution
# ----------------------------
def build_dates(anchor: dt.date, window_days: int) -> List[dt.date]:
    return [anchor - dt.timedelta(days=i) for i in range(window_days, -1, -1)]

def compute_correlation(a: List[float], b: List[float]) -> float:
    if len(a) < 2 or len(b) < 2:
        return 0.0
    if np.std(a) == 0 or np.std(b) == 0:
        return 0.0
    return float(np.corrcoef(a, b)[0, 1])

def moving_avg(values: List[float], w: int) -> List[float]:
    if w <= 1:
        return values[:]
    s = pd.Series(values, dtype=float)
    return s.rolling(w, min_periods=1).mean().tolist()

def z_scores(values: List[float]) -> List[float]:
    arr = np.array(values, dtype=float)
    if len(arr) < 2 or float(arr.std()) == 0.0:
        return [0.0 for _ in values]
    z = (arr - arr.mean()) / arr.std()
    return z.tolist()

def clean_day_for_export(day: Dict[str, Any]) -> Dict[str, Any]:
    raw = day.get("raw", {}) or {}
    analytics = day.get("analytics", {}) or {}
    items = raw.get("items", []) or []
    items = items[:Config.EXPORT_MAX_ITEMS_PER_DAY]

    return {
        "type": day.get("type"),
        "day_offset": int(day.get("day_offset", 0)),
        "date": day.get("date"),
        "cached": bool(day.get("cached", False)),
        "raw": {
            "error": raw.get("error"),
            "debug": raw.get("debug", {}),
            "items": items,
        },
        "analytics": analytics,
    }


if "scan" not in st.session_state:
    st.session_state.scan = None


def run_scan() -> None:
    scanner = GeminiScanner(api_key=api_key)

    ref_dates = build_dates(attack_date, window)
    live_dates = build_dates(today_date, window)

    status = st.empty()
    prog = st.progress(0)

    total = len(ref_dates) + len(live_dates)
    done = 0

    results: List[Dict[str, Any]] = []

    def process_day(d: dt.date, typ: str, anchor: dt.date) -> Dict[str, Any]:
        raw, cached = scanner.fetch_day(d, keywords, validation_mode, ignore_cache=ignore_cache)
        analytics = analyzer.analyze(raw.get("items", []) or [])
        delta = (anchor - d).days
        return {
            "type": typ,
            "date": d.strftime("%d/%m"),
            "date_iso": d.isoformat(),
            "day_offset": int(-delta),
            "raw": raw,
            "analytics": analytics,
            "cached": cached,
        }

    # Thread pool (concurrency)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as ex:
        futures = []
        for d in ref_dates:
            futures.append(ex.submit(process_day, d, "Reference", attack_date))
        for d in live_dates:
            futures.append(ex.submit(process_day, d, "Live", today_date))

        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            results.append(res)
            done += 1
            prog.progress(done / total)
            status.text(f"Processed {res['type']} | {res['date']}")

    status.empty()
    prog.empty()

    ref = sorted([r for r in results if r["type"] == "Reference"], key=lambda x: x["day_offset"])
    live = sorted([r for r in results if r["type"] == "Live"], key=lambda x: x["day_offset"])

    # KPIs + trend/anomalies
    ref_scores = [float(x["analytics"]["escalation_score"]) for x in ref]
    live_scores = [float(x["analytics"]["escalation_score"]) for x in live]
    live_conf = [float(x["analytics"]["confidence"]) for x in live]

    corr = compute_correlation(ref_scores, live_scores)
    avg_conf = float(np.mean(live_conf)) if live_conf else 0.0
    live_max = float(max(live_scores)) if live_scores else 0.0

    live_z = z_scores(live_scores)
    anomalies = [i for i, z in enumerate(live_z) if abs(z) >= Config.ANOMALY_Z_THRESHOLD]
    anomaly_count = int(len(anomalies))

    live_ma3 = moving_avg(live_scores, 3)
    live_ma5 = moving_avg(live_scores, 5)

    st.session_state.scan = {
        "ref": ref,
        "live": live,
        "kpis": {
            "correlation": corr,
            "avg_confidence_live": avg_conf,
            "live_max_score": live_max,
            "live_anomaly_count": anomaly_count,
        },
        "trend": {
            "live_ma3": live_ma3,
            "live_ma5": live_ma5,
            "live_z": live_z,
        }
    }


if st.button("🚀 הפעל ניתוח מבצעי (Run)", type="primary"):
    run_scan()


# ----------------------------
# Render
# ----------------------------
scan = st.session_state.scan
if scan:
    ref = scan["ref"]
    live = scan["live"]
    k = scan["kpis"]
    trend = scan["trend"]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Correlation (Ref↔Live)", f"{k['correlation']:.2f}")
    c2.metric("Avg Confidence (Live)", f"{k['avg_confidence_live']:.2f}")
    c3.metric("Live Max Score", f"{k['live_max_score']:.0f}")
    c4.metric("Live Anomalies (|z|≥2)", f"{k['live_anomaly_count']}")

    st.divider()
    st.subheader("📈 תמונת מודיעין (Score + Confidence + Trend)")

    fig = make_subplots(specs=[[{"secondary_y": True}]])
    x_ref = [x["day_offset"] for x in ref]
    y_ref = [x["analytics"]["escalation_score"] for x in ref]
    x_live = [x["day_offset"] for x in live]
    y_live = [x["analytics"]["escalation_score"] for x in live]
    y_conf = [x["analytics"]["confidence"] for x in live]

    fig.add_trace(go.Scatter(x=x_ref, y=y_ref, name="Ref Score", mode="lines"), secondary_y=False)
    fig.add_trace(go.Scatter(x=x_live, y=y_live, name="Live Score", mode="lines"), secondary_y=False)
    fig.add_trace(go.Scatter(x=x_live, y=trend["live_ma3"], name="Live MA(3)", mode="lines"), secondary_y=False)
    fig.add_trace(go.Scatter(x=x_live, y=trend["live_ma5"], name="Live MA(5)", mode="lines"), secondary_y=False)

    fig.add_trace(go.Bar(x=x_live, y=y_conf, name="Confidence", opacity=0.25), secondary_y=True)

    fig.update_layout(hovermode="x unified", title="Escalation vs Reliability (with Trend)")
    fig.update_yaxes(title_text="Score", secondary_y=False, range=[0, 100])
    fig.update_yaxes(title_text="Confidence", secondary_y=True, range=[0, 1])

    st.plotly_chart(fig, use_container_width=True)

    st.divider()
    st.subheader("🔍 חקר ראיות (Evidence Locker)")
    colA, colB = st.columns(2)

    def render_timeline(tl: List[Dict[str, Any]]) -> None:
        for day in tl:
            a = day["analytics"]
            conf = float(a.get("confidence", 0.0))
            score = float(a.get("escalation_score", 0.0))
            conf_icon = "🟢" if conf > 0.6 else "🟠" if conf > 0.3 else "🔴"
            raw = day.get("raw", {}) or {}
            err = raw.get("error")
            err_mark = "⚠️" if err else ""

            with st.expander(f"{day['date']} | Score: {score:.0f} | Conf: {conf:.2f} {conf_icon} {err_mark}"):
                if err:
                    st.error(err)

                evidence = a.get("evidence", []) or []
                if evidence:
                    st.markdown("**🔗 ראיות נבחרות:**")
                    for ev in evidence:
                        star = "⭐" if ev.get("is_tier1") else ""
                        st.markdown(
                            f"<a href='{ev.get('url','')}' target='_blank' class='evidence-link'>"
                            f"{star} {ev.get('title','')} <span style='color:#777'>({ev.get('domain','')})</span>"
                            f"</a>",
                            unsafe_allow_html=True,
                        )
                else:
                    st.caption("אין ראיות מאומתות.")

                dbg = raw.get("debug", {}) or {}
                st.markdown(
                    f"<div class='debug-info'>"
                    f"items={len(raw.get('items',[]))} | "
                    f"raw_items={dbg.get('raw_items',0)} | "
                    f"validated={dbg.get('validated',0)} | "
                    f"grounded_domains={dbg.get('grounded_domains',0)} | "
                    f"grounded_urls={dbg.get('grounded_urls',0)} | "
                    f"cached={day.get('cached',False)}"
                    f"</div>",
                    unsafe_allow_html=True
                )

    with colA:
        st.markdown("### Reference")
        render_timeline(ref)
    with colB:
        st.markdown("### Live")
        render_timeline(live)

    # ----------------------------
    # Summary (optional)
    # ----------------------------
    st.divider()
    st.subheader("🧠 הערכת מצב (OSINT בלבד)")

    if st.button("🧾 הפק סיכום (Gemini Pro)"):
        client = genai.Client(api_key=api_key)

        live_scores = [float(x["analytics"]["escalation_score"]) for x in live]
        live_conf = [float(x["analytics"]["confidence"]) for x in live]

        corr = k["correlation"]
        avg_conf = float(np.mean(live_conf)) if live_conf else 0.0
        live_max = float(max(live_scores)) if live_scores else 0.0
        anomaly_count = k["live_anomaly_count"]

        # חשוב: ללא תחזיות/תאריכים/ייעוץ אופרטיבי
        prompt = f"""
אתה אנליסט OSINT בכיר.
המערכת מציגה סטטיסטיקה של שיח תקשורתי בלבד. אין להפיק תחזיות תקיפה/ייעוץ מבצעי.

נתונים:
- Correlation(Ref↔Live): {corr:.2f}
- Avg Confidence (Live): {avg_conf:.2f}
- Live Max Score: {live_max:.0f}
- Live Anomalies Count: {anomaly_count}

משימה:
1) מה מאומת לפי הראיות (התבסס רק על evidence + metrics).
2) מה לא מאומת / סיכוני False Positive/False Negative.
3) מגמות קצרות טווח (בהתבסס על moving averages + שינויי scores).
4) המלצות OSINT להרחבת איסוף (למשל: מילות מפתח, מקורות, חלון זמן) — ללא הנחיות פעולה.
כתוב בעברית, תמציתי, עם נקודות.
""".strip()

        with st.spinner("Gemini Pro מנתח..."):
            resp = client.models.generate_content(
                model=Config.PRO_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(temperature=0.2),
            )
        st.write(resp.text)

    # ----------------------------
    # Export
    # ----------------------------
    st.divider()
    st.subheader("⬇️ יצוא דו״ח")

    export_obj = {
        "meta": {
            "generated_at": dt.datetime.now().isoformat(),
            "keywords": keywords,
            "validation_mode": validation_mode,
            "window_days": window,
            "reference_anchor": attack_date.isoformat(),
            "live_anchor": today_date.isoformat(),
            "models": {"flash": Config.FLASH_MODEL, "pro": Config.PRO_MODEL},
            "kpis": k,
        },
        "reference": [clean_day_for_export(x) for x in ref],
        "live": [clean_day_for_export(x) for x in live],
    }

    json_bytes = json.dumps(export_obj, ensure_ascii=False, indent=2, default=json_default).encode("utf-8")
    st.download_button(
        "⬇️ Export JSON",
        data=json_bytes,
        file_name="osint_report.json",
        mime="application/json",
    )

    # CSV summary export
    rows = []
    for x in ref + live:
        rows.append({
            "type": x["type"],
            "date": x["date"],
            "day_offset": x["day_offset"],
            "score": float(x["analytics"]["escalation_score"]),
            "confidence": float(x["analytics"]["confidence"]),
            "volume": int(x["analytics"]["volume"]),
            "clusters": int(x["analytics"]["clusters"]),
            "unique_domains": int(x["analytics"]["valid_unique_domains"]),
            "error": (x.get("raw", {}) or {}).get("error"),
            "cached": bool(x.get("cached", False)),
        })
    df_out = pd.DataFrame(rows)
    csv_bytes = df_out.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Export CSV (Summary)",
        data=csv_bytes,
        file_name="osint_report_summary.csv",
        mime="text/csv",
    )
