# -*- coding: utf-8 -*-
"""
🛡️ OSINT Sentinel: Platinum v1.5.1 (Fixed)
- Smart Strict validation (prevents "validated=0" flatline)
- Global rate limiter + client pool (thread-safe)
- Robust JSON export (no "not JSON serializable" TypeError)
- Evidence locker + Trends + Anomalies (z-score)
- SQLite WAL + daily cache + audit log
"""

import re
import os
import io
import json
import time
import hmac
import math
import queue
import hashlib
import random
import logging
import sqlite3
import threading
import datetime
import concurrent.futures
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import numpy as np
import pandas as pd
import streamlit as st
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from google import genai
from google.genai import types

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


# =========================
# Logging
# =========================
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("osint_platinum")


# =========================
# Config
# =========================
@dataclass(frozen=True)
class Config:
    APP_TITLE: str = "🛡️ OSINT Sentinel: Platinum v1.5.1"
    VERSION_TAG: str = "v1.5.1"
    DB_FILE: str = "osint_plat_v1_5.db"

    # Concurrency & retries
    MAX_WORKERS: int = 3
    MAX_RETRIES: int = 3

    # Models (keep as strings; allow override via secrets if needed)
    FLASH_MODEL: str = "gemini-3-flash-preview"
    PRO_MODEL: str = "gemini-3-pro-preview"

    # Rate limiting (global across threads)
    MIN_INTERVAL_SEC: float = 0.55  # min spacing between calls
    JITTER_SEC: float = 0.25

    # Noise / propaganda blocks
    BLACKLIST_DOMAINS: Set[str] = frozenset({
        "news.google.com", "google.com", "msn.com", "yahoo.com", "bing.com",
        "vertexaisearch.cloud.google.com", "webcache.googleusercontent.com",
        "mronline.org", "alwaght.net", "presstv.ir", "sputniknews.com"
    })

    # Aggregator suffixes to filter
    AGGREGATOR_SUFFIXES: Set[str] = frozenset({
        "news.google.com", "google.com", "msn.com", "yahoo.com", "bing.com",
        "vertexaisearch.cloud.google.com"
    })

    # Domain weights (1.0 high, 0.35 default)
    DOMAIN_WEIGHTS: Dict[str, float] = None  # set below
    DEFAULT_WEIGHT: float = 0.35

    # Smart-Strict: allow domain-level validation only if weight >= this threshold
    STRICT_DOMAIN_FALLBACK_MIN_WEIGHT: float = 0.80

    # Similarity clustering threshold (greedy)
    CLUSTER_SIM_THRESHOLD: float = 0.55

    # Anomaly threshold
    ANOMALY_Z_ABS: float = 2.0


DOMAIN_WEIGHTS = {
    "reuters.com": 1.0, "apnews.com": 1.0, "bbc.com": 1.0, "cnn.com": 0.9,

    "ynet.co.il": 0.85, "haaretz.co.il": 0.85, "timesofisrael.com": 0.85,

    "jpost.com": 0.80, "maariv.co.il": 0.75, "walla.co.il": 0.75,

    "aljazeera.com": 0.70, "tasnimnews.com": 0.60, "isna.ir": 0.60,
    "iranintl.com": 0.65
}
Config.DOMAIN_WEIGHTS = DOMAIN_WEIGHTS


# =========================
# Streamlit page setup
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
    .cluster-card {
        border-right: 3px solid #4285f4; padding-right: 10px; margin-bottom: 8px;
        background-color: #f8f9fa; padding: 8px; border-radius: 4px; font-size: 0.92em;
    }
    .evidence-link { font-size: 0.88em; display:block; margin-bottom: 3px; text-decoration:none; color:#0066cc; }
    .evidence-link:hover { text-decoration: underline; }
    .metric-warning { color: #d9534f; font-weight: bold; font-size: 0.85em; }
    .debug-info {
        font-size: 0.78em; color: #666; margin-top: 6px;
        border-top: 1px dashed #ccc; padding-top: 4px;
    }
</style>
""", unsafe_allow_html=True)

st.warning(
    "⚖️ מערכת זו נועדה למחקר ואנליזה של מידע פומבי בלבד (OSINT). "
    "היא מציגה סטטיסטיקה של שיח תקשורתי ואינה מספקת התרעות, תחזיות תקיפה או ייעוץ אופרטיבי."
)

st.title(Config.APP_TITLE)
st.caption("Advanced OSINT I&W: Concurrency-safe, Rate-limited, Weighted Evidence + Trends/Anomalies (No forecasting)")


# =========================
# Helpers: URL + domains
# =========================
def normalize_url(u: str) -> str:
    try:
        if not u:
            return ""
        p = urlparse(u.strip())
        scheme = (p.scheme or "https").lower()
        netloc = p.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        path = p.path.rstrip("/")

        drop_keys = {"fbclid", "gclid", "ref", "ref_src", "utm_source", "utm_medium", "utm_campaign", "ocid"}
        q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
             if k.lower() not in drop_keys and not k.lower().startswith("utm_")]
        query = urlencode(q, doseq=True)

        return urlunparse((scheme, netloc, path, "", query, ""))
    except Exception:
        return u or ""


def normalize_url_key(u: str) -> str:
    """
    Key for matching: scheme ignored, query dropped.
    This is more stable than exact URL matching.
    """
    try:
        u_norm = normalize_url(u)
        p = urlparse(u_norm)
        netloc = p.netloc.lower().replace("www.", "")
        path = (p.path or "").rstrip("/")
        return f"{netloc}{path}"
    except Exception:
        return (u or "").strip()


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


def domain_weight(domain: str) -> float:
    d = (domain or "").lower().replace("www.", "")
    return Config.DOMAIN_WEIGHTS.get(d, Config.DEFAULT_WEIGHT)


# =========================
# Robust JSON serialization
# =========================
def to_jsonable(obj: Any) -> Any:
    """
    Convert common non-JSON types into JSON-safe Python types.
    Fixes: datetime/date, numpy scalars/arrays, sets, tuples, bytes, pandas types.
    """
    if obj is None:
        return None

    # primitives
    if isinstance(obj, (str, int, float, bool)):
        return obj

    # datetime
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()

    # numpy
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, (np.ndarray,)):
        return obj.tolist()

    # pandas
    if isinstance(obj, (pd.Timestamp,)):
        return obj.isoformat()

    # bytes
    if isinstance(obj, (bytes, bytearray)):
        try:
            return obj.decode("utf-8", errors="replace")
        except Exception:
            return str(obj)

    # dict
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}

    # list/tuple/set
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(x) for x in list(obj)]

    # fallback
    return str(obj)


def safe_json_bytes(obj: Any, indent: int = 2) -> bytes:
    return json.dumps(to_jsonable(obj), ensure_ascii=False, indent=indent).encode("utf-8")


def extract_json_object(text: str) -> Dict[str, Any]:
    """
    Gemini sometimes returns JSON with extra whitespace; try strict load first,
    then substring between first '{' and last '}'.
    """
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        pass

    m1 = text.find("{")
    m2 = text.rfind("}")
    if 0 <= m1 < m2:
        chunk = text[m1:m2 + 1]
        try:
            return json.loads(chunk)
        except Exception:
            return {}
    return {}


# =========================
# Retry with backoff
# =========================
def retry_with_backoff(retries: int = Config.MAX_RETRIES, base: float = 1.0):
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_err = None
            for i in range(retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_err = e
                    if i >= retries:
                        break
                    sleep = (base * (2 ** i)) + random.uniform(0, 1.0)
                    time.sleep(sleep)
            raise last_err
        return wrapper
    return decorator


# =========================
# Global Rate Limiter
# =========================
class GlobalRateLimiter:
    def __init__(self, min_interval: float, jitter: float):
        self.min_interval = float(min_interval)
        self.jitter = float(jitter)
        self._lock = threading.Lock()
        self._last_ts = 0.0

    def acquire(self):
        with self._lock:
            now = time.time()
            elapsed = now - self._last_ts
            wait = self.min_interval - elapsed
            if wait > 0:
                time.sleep(wait + random.uniform(0, self.jitter))
            self._last_ts = time.time()


# =========================
# SQLite Manager (WAL + cache + audit)
# =========================
class SQLitePool:
    def __init__(self, db_file: str, pool_size: int = 6):
        self.db_file = db_file
        self.pool = queue.Queue(maxsize=pool_size)
        for _ in range(pool_size):
            conn = sqlite3.connect(self.db_file, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            self.pool.put(conn)

    def get(self) -> sqlite3.Connection:
        return self.pool.get()

    def put(self, conn: sqlite3.Connection):
        self.pool.put(conn)


class DatabaseManager:
    def __init__(self, db_file: str):
        self.pool = SQLitePool(db_file, pool_size=max(4, Config.MAX_WORKERS + 2))
        self.init_db()

    def init_db(self):
        conn = self.pool.get()
        try:
            conn.execute('''CREATE TABLE IF NOT EXISTS daily_scans
                (scan_date TEXT, query_hash TEXT, raw_json TEXT, updated_at TIMESTAMP,
                 PRIMARY KEY (scan_date, query_hash))''')

            conn.execute('''CREATE TABLE IF NOT EXISTS audit_log
                (ts TEXT, action TEXT, query_hash TEXT, keywords TEXT, validation_mode TEXT,
                 window_days INTEGER, reference_anchor TEXT, live_anchor TEXT, meta_json TEXT)''')
            conn.commit()
        finally:
            self.pool.put(conn)

    def get_data(self, date_str: str, query_hash: str) -> Optional[Dict[str, Any]]:
        conn = self.pool.get()
        try:
            cur = conn.cursor()
            cur.execute("SELECT raw_json FROM daily_scans WHERE scan_date=? AND query_hash=?", (date_str, query_hash))
            row = cur.fetchone()
            if not row:
                return None
            return json.loads(row[0])
        finally:
            self.pool.put(conn)

    def save_data(self, date_str: str, query_hash: str, data: Dict[str, Any]):
        conn = self.pool.get()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO daily_scans (scan_date, query_hash, raw_json, updated_at) VALUES (?, ?, ?, ?)",
                (date_str, query_hash, json.dumps(to_jsonable(data), ensure_ascii=False), datetime.datetime.now().isoformat())
            )
            conn.commit()
        finally:
            self.pool.put(conn)

    def audit(self, action: str, query_hash: str, keywords: str, validation_mode: str,
              window_days: int, reference_anchor: str, live_anchor: str, meta: Dict[str, Any]):
        conn = self.pool.get()
        try:
            conn.execute(
                "INSERT INTO audit_log (ts, action, query_hash, keywords, validation_mode, window_days, reference_anchor, live_anchor, meta_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.datetime.now().isoformat(),
                    action,
                    query_hash,
                    keywords,
                    validation_mode,
                    int(window_days),
                    reference_anchor,
                    live_anchor,
                    json.dumps(to_jsonable(meta), ensure_ascii=False),
                )
            )
            conn.commit()
        finally:
            self.pool.put(conn)


@st.cache_resource
def get_db() -> DatabaseManager:
    return DatabaseManager(Config.DB_FILE)


db_manager = get_db()


# =========================
# Gemini Client Pool (thread-safe)
# =========================
class GeminiClientPool:
    def __init__(self, api_key: str, pool_size: int):
        self._q: "queue.Queue[genai.Client]" = queue.Queue(maxsize=pool_size)
        for _ in range(pool_size):
            self._q.put(genai.Client(api_key=api_key))

    def acquire(self) -> genai.Client:
        return self._q.get()

    def release(self, client: genai.Client):
        self._q.put(client)


# =========================
# Gemini Scanner (Extraction)
# =========================
class GeminiScanner:
    def __init__(self, api_key: str, rate_limiter: GlobalRateLimiter, pool_size: int):
        self.rate = rate_limiter
        self.clients = GeminiClientPool(api_key=api_key, pool_size=pool_size)

    def _extract_grounded(self, response) -> Tuple[Set[str], Set[str]]:
        grounded_keys: Set[str] = set()
        grounded_domains: Set[str] = set()

        try:
            if not response or not getattr(response, "candidates", None):
                return grounded_keys, grounded_domains

            cand0 = response.candidates[0]
            gm = getattr(cand0, "grounding_metadata", None)
            if not gm:
                return grounded_keys, grounded_domains

            chunks = getattr(gm, "grounding_chunks", []) or []
            for ch in chunks:
                web = getattr(ch, "web", None)
                if not web:
                    continue
                uri = getattr(web, "uri", None)
                title = getattr(web, "title", None)

                if uri and isinstance(uri, str) and uri.startswith("http"):
                    grounded_keys.add(normalize_url_key(uri))
                    d = get_domain(uri)
                    if d and not is_aggregator_domain(d):
                        grounded_domains.add(d)

                # sometimes "title" is a bare domain-like string
                if title and "." in title and " " not in title:
                    d2 = title.lower().replace("www.", "")
                    if len(d2) > 3 and not is_aggregator_domain(d2):
                        grounded_domains.add(d2)

        except Exception:
            pass

        return grounded_keys, grounded_domains

    def _prompt(self, date_str: str, search_query: str) -> str:
        return f"""
ROLE: OSINT Data Extractor (STRICT JSON).
TASK: Find news items for DATE: {date_str}.
QUERY: "{search_query}"

HARD RULES:
1) Return the publisher’s CANONICAL URL (final destination URL).
2) DO NOT return google.com, news.google.com, msn.com or redirect/aggregator links.
3) Return JSON only (no markdown, no prose).
4) Each item must have: title, source, url, snippet.

JSON SCHEMA:
{{ "items": [ {{ "title": "...", "source": "...", "url": "...", "snippet": "..." }} ] }}
""".strip()

    def _validate_items(
        self,
        raw_items: List[Dict[str, Any]],
        grounded_keys: Set[str],
        grounded_domains: Set[str],
        mode: str,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Fix for flatline:
        - Strict: prefer URL-key match (domain+path, no query)
        - Smart Strict fallback: allow domain-level match ONLY for high-trust domains (weight>=0.80)
        - Relaxed: allow domain-level match
        """
        validated: List[Dict[str, Any]] = []
        dbg = {
            "strict_fallback_hits": 0,
            "dropped_blacklist": 0,
            "dropped_aggregator": 0,
            "dropped_ungrounded": 0,
        }

        for item in raw_items or []:
            title = str(item.get("title", "") or "").strip()
            source = str(item.get("source", "") or "").strip()
            url = str(item.get("url", "") or "").strip()
            snippet = str(item.get("snippet", "") or "").strip()

            if not url or not url.startswith("http"):
                continue

            u_norm = normalize_url(url)
            d = get_domain(u_norm)

            if not d:
                continue

            if d in Config.BLACKLIST_DOMAINS:
                dbg["dropped_blacklist"] += 1
                continue

            if is_aggregator_domain(d):
                dbg["dropped_aggregator"] += 1
                continue

            u_key = normalize_url_key(u_norm)

            ok = False
            if u_key in grounded_keys:
                ok = True
            else:
                # domain-level
                if mode == "Relaxed":
                    if d in grounded_domains:
                        ok = True
                else:  # Strict
                    # Smart-Strict: only allow domain-level validation for Tier1-ish
                    if d in grounded_domains and domain_weight(d) >= Config.STRICT_DOMAIN_FALLBACK_MIN_WEIGHT:
                        ok = True
                        dbg["strict_fallback_hits"] += 1

            if not ok:
                dbg["dropped_ungrounded"] += 1
                continue

            validated.append({
                "title": title,
                "source": source,
                "url": u_norm,
                "snippet": snippet
            })

        return validated, dbg

    @retry_with_backoff(retries=Config.MAX_RETRIES, base=1.0)
    def fetch_day(self, date_obj: datetime.date, keywords: str, mode: str) -> Tuple[Dict[str, Any], bool]:
        date_str = date_obj.strftime("%Y-%m-%d")
        query_hash = hashlib.md5((date_str + keywords + mode + Config.VERSION_TAG).encode("utf-8")).hexdigest()

        cached = db_manager.get_data(date_str, query_hash)
        if cached:
            return cached, True

        after = date_obj
        before = date_obj + datetime.timedelta(days=1)
        search_query = f"{keywords} after:{after} before:{before}"

        prompt = self._prompt(date_str, search_query)
        tool = types.Tool(google_search=types.GoogleSearch())

        self.rate.acquire()
        client = self.clients.acquire()
        try:
            response = client.models.generate_content(
                model=Config.FLASH_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.0,
                    response_mime_type="application/json",
                    tools=[tool],
                ),
            )

            grounded_keys, grounded_domains = self._extract_grounded(response)
            parsed = extract_json_object(getattr(response, "text", "") or "")
            raw_items = parsed.get("items", []) if isinstance(parsed, dict) else []
            if not isinstance(raw_items, list):
                raw_items = []

            validated_items, dbg2 = self._validate_items(raw_items, grounded_keys, grounded_domains, mode)

            # error signals
            err = None
            if (grounded_keys or grounded_domains) and not raw_items:
                err = "EMPTY_ITEMS_WITH_GROUNDING"
            if not grounded_keys 