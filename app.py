# -*- coding: utf-8 -*-
"""
🛡️ OSINT Sentinel: Platinum v1.6.0 (X API + Gemini Flash + (Optional) Grok/x.ai Summary)
- Stage 1: X API (daily collection)
- Stage 2: Gemini Flash (Google Search tool) (daily collection)
- Stage 3 (optional): Grok/x.ai chat completions for daily summarization (NO forecasting)
- Then: math/analytics (clusters, weights, trend, z-score)
"""

import re
import io
import json
import time
import hmac
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

import requests
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
    APP_TITLE: str = "🛡️ OSINT Sentinel: Platinum v1.6.0"
    VERSION_TAG: str = "v1.6.0"
    DB_FILE: str = "osint_plat_v1_6.db"

    # Concurrency & retries
    MAX_WORKERS: int = 3
    MAX_RETRIES: int = 3

    # Models (Gemini API)
    FLASH_MODEL: str = "gemini-3-flash-preview"
    PRO_MODEL: str = "gemini-3-pro-preview"

    # Rate limiting (global across threads)
    MIN_INTERVAL_SEC: float = 0.55
    JITTER_SEC: float = 0.25

    # X API (v2)
    X_API_BASE: str = "https://api.x.com"
    X_RECENT_ENDPOINT: str = "/2/tweets/search/recent"
    X_ALL_ENDPOINT: str = "/2/tweets/search/all"  # needs full-archive access
    X_RECENT_DAYS_LIMIT: int = 7
    X_PAGE_SIZE: int = 100
    X_MAX_PAGES: int = 4
    X_MAX_ITEMS_PER_DAY: int = 250

    # x.ai (Grok) chat completions
    XAI_API_BASE: str = "https://api.x.ai"
    XAI_CHAT_COMPLETIONS_ENDPOINT: str = "/v1/chat/completions"
    XAI_DEFAULT_MODEL: str = "grok-4"
    XAI_TIMEOUT_SEC: int = 35
    XAI_MAX_INPUT_ITEMS: int = 60  # cap items passed to grok
    XAI_MAX_TEXT_CHARS_PER_ITEM: int = 380

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
    "iranintl.com": 0.65,
    "x.com": 0.45,
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
    .grok-box {
        background: #f7f7ff;
        border-right: 3px solid #7c3aed;
        padding: 10px;
        border-radius: 8px;
        font-size: 0.92em;
        margin-top: 8px;
    }
</style>
""", unsafe_allow_html=True)

# חובה: Disclaimer בתחילת האפליקציה
st.warning("""
⚖️ **הצהרת אחריות**
מערכת זו נועדה למחקר ואנליזה של מידע פומבי בלבד.
אין להשתמש במידע למטרות בלתי חוקיות.
המשתמש אחראי לציות לכל החוקים הרלוונטיים.
""")

st.info("המערכת מציגה סטטיסטיקה של שיח תקשורתי (OSINT) ואינה מספקת התרעות, תחזיות תקיפה או ייעוץ אופרטיבי.")
st.title(Config.APP_TITLE)
st.caption("OSINT I&W: X API → Gemini Flash → (Optional) Grok Summary → Weighted Evidence + Trends/Anomalies (No forecasting)")


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
    """Key for matching: scheme ignored, query dropped."""
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
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, (np.ndarray,)):
        return obj.tolist()
    if isinstance(obj, (pd.Timestamp,)):
        return obj.isoformat()
    if isinstance(obj, (bytes, bytearray)):
        try:
            return obj.decode("utf-8", errors="replace")
        except Exception:
            return str(obj)
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(x) for x in list(obj)]
    return str(obj)


def safe_json_bytes(obj: Any, indent: int = 2) -> bytes:
    return json.dumps(to_jsonable(obj), ensure_ascii=False, indent=indent).encode("utf-8")


def extract_json_object(text: str) -> Dict[str, Any]:
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
            conn.execute("PRAGMA busy_timeout=5000;")
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
            try:
                return json.loads(row[0])
            except Exception:
                return None
        finally:
            self.pool.put(conn)

    def save_data(self, date_str: str, query_hash: str, data: Dict[str, Any]):
        conn = self.pool.get()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO daily_scans (scan_date, query_hash, raw_json, updated_at) VALUES (?, ?, ?, ?)",
                (date_str, query_hash, json.dumps(to_jsonable(data), ensure_ascii=False),
                 datetime.datetime.now().isoformat())
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
        Collect: keep items after basic hygiene (no grounding match needed)
        Strict: url-key match, with high-trust domain fallback (weight>=0.80)
        Relaxed: domain-level match
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

            # Collect mode: no grounding requirement
            if mode == "Collect":
                validated.append({"title": title, "source": source, "url": u_norm, "snippet": snippet})
                continue

            u_key = normalize_url_key(u_norm)

            ok = False
            if u_key in grounded_keys:
                ok = True
            else:
                if mode == "Relaxed":
                    if d in grounded_domains:
                        ok = True
                else:  # Strict
                    if d in grounded_domains and domain_weight(d) >= Config.STRICT_DOMAIN_FALLBACK_MIN_WEIGHT:
                        ok = True
                        dbg["strict_fallback_hits"] += 1

            if not ok:
                dbg["dropped_ungrounded"] += 1
                continue

            validated.append({"title": title, "source": source, "url": u_norm, "snippet": snippet})

        return validated, dbg

    @retry_with_backoff(retries=Config.MAX_RETRIES, base=1.0)
    def fetch_day(self, date_obj: datetime.date, keywords: str, mode: str) -> Tuple[Dict[str, Any], bool]:
        date_str = date_obj.strftime("%Y-%m-%d")
        query_hash = hashlib.md5((date_str + keywords + mode + Config.VERSION_TAG).encode("utf-8")).hexdigest()

        cached = db_manager.get_data(date_str, "WEB_" + query_hash)
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

            err = None
            if (grounded_keys or grounded_domains) and not raw_items:
                err = "EMPTY_ITEMS_WITH_GROUNDING"
            if not grounded_keys and not grounded_domains and mode != "Collect":
                err = "NO_GROUNDING_SOURCES"

            out = {
                "error": err,
                "debug": {
                    "date": date_str,
                    "raw_items": int(len(raw_items)),
                    "validated": int(len(validated_items)),
                    "grounded_urls": int(len(grounded_keys)),
                    "grounded_domains": int(len(grounded_domains)),
                    "mode": mode,
                    **dbg2,
                },
                "items": validated_items
            }

            db_manager.save_data(date_str, "WEB_" + query_hash, out)
            return out, False

        except Exception as e:
            logger.exception(f"Fetch failed for {date_str}: {e}")
            out = {"error": str(e), "debug": {"date": date_str, "mode": mode}, "items": []}
            db_manager.save_data(date_str, "WEB_" + query_hash, out)
            return out, False
        finally:
            self.clients.release(client)


# =========================
# X API Scanner (Stage 1)
# =========================
class XScanner:
    def __init__(self, bearer_token: str, rate_limiter: GlobalRateLimiter):
        self.token = bearer_token
        self.rate = rate_limiter

    def _iso_utc(self, d: datetime.datetime) -> str:
        if d.tzinfo is None:
            d = d.replace(tzinfo=datetime.timezone.utc)
        return d.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    def _too_old_for_recent(self, day: datetime.date) -> bool:
        today = datetime.datetime.now(datetime.timezone.utc).date()
        return (today - day).days > Config.X_RECENT_DAYS_LIMIT

    @retry_with_backoff(retries=Config.MAX_RETRIES, base=1.0)
    def fetch_day(self, date_obj: datetime.date, x_query: str, use_full_archive: bool) -> Tuple[Dict[str, Any], bool]:
        date_str = date_obj.strftime("%Y-%m-%d")
        mode_tag = "ALL" if use_full_archive else "RECENT"
        query_hash = hashlib.md5((date_str + x_query + mode_tag + Config.VERSION_TAG).encode("utf-8")).hexdigest()

        cached = db_manager.get_data(date_str, "X_" + query_hash)
        if cached:
            return cached, True

        if (not use_full_archive) and self._too_old_for_recent(date_obj):
            out = {
                "error": f"X_RECENT_LIMIT_{Config.X_RECENT_DAYS_LIMIT}D",
                "debug": {"date": date_str, "mode": mode_tag, "items": 0},
                "items": []
            }
            db_manager.save_data(date_str, "X_" + query_hash, out)
            return out, False

        start_dt = datetime.datetime.combine(date_obj, datetime.time.min).replace(tzinfo=datetime.timezone.utc)
        end_dt = start_dt + datetime.timedelta(days=1)

        endpoint = Config.X_ALL_ENDPOINT if use_full_archive else Config.X_RECENT_ENDPOINT
        url = Config.X_API_BASE + endpoint
        headers = {"Authorization": f"Bearer {self.token}"}

        items: List[Dict[str, Any]] = []
        next_token = None
        pages = 0

        while pages < Config.X_MAX_PAGES and len(items) < Config.X_MAX_ITEMS_PER_DAY:
            params = {
                "query": x_query.strip(),
                "start_time": self._iso_utc(start_dt),
                "end_time": self._iso_utc(end_dt),
                "max_results": Config.X_PAGE_SIZE,
                "tweet.fields": "created_at,lang,public_metrics,author_id",
                "expansions": "author_id",
                "user.fields": "username",
            }
            if next_token:
                params["next_token"] = next_token

            self.rate.acquire()
            r = requests.get(url, headers=headers, params=params, timeout=25)

            if r.status_code == 429:
                raise RuntimeError("X_RATE_LIMIT_429")
            if r.status_code >= 400:
                raise RuntimeError(f"X_HTTP_{r.status_code}: {r.text[:300]}")

            payload = r.json()
            data = payload.get("data") or []
            includes = payload.get("includes") or {}
            users = includes.get("users") or []

            id_to_username = {}
            for u in users:
                uid = str(u.get("id", "") or "")
                uname = str(u.get("username", "") or "")
                if uid and uname:
                    id_to_username[uid] = uname

            for t in data:
                tid = str(t.get("id", "") or "")
                text = str(t.get("text", "") or "").strip()
                author_id = str(t.get("author_id", "") or "")
                uname = id_to_username.get(author_id, "")
                created_at = t.get("created_at")

                if not tid or not text:
                    continue

                if uname:
                    tweet_url = f"https://x.com/{uname}/status/{tid}"
                    title = f"@{uname}: {text[:90]}"
                else:
                    tweet_url = f"https://x.com/i/web/status/{tid}"
                    title = text[:90]

                items.append({
                    "title": title,
                    "source": "X",
                    "url": tweet_url,
                    "snippet": text,
                    "created_at": created_at,
                })

                if len(items) >= Config.X_MAX_ITEMS_PER_DAY:
                    break

            meta = payload.get("meta") or {}
            next_token = meta.get("next_token")
            pages += 1
            if not next_token:
                break

        out = {
            "error": None,
            "debug": {"date": date_str, "mode": mode_tag, "pages": pages, "items": len(items)},
            "items": items
        }

        db_manager.save_data(date_str, "X_" + query_hash, out)
        return out, False


# =========================
# Grok/x.ai Summarizer (Stage 3 - Optional)
# =========================
class GrokSummarizer:
    def __init__(self, api_key: str, rate_limiter: GlobalRateLimiter):
        self.api_key = api_key
        self.rate = rate_limiter

    def _items_fingerprint(self, items: List[Dict[str, Any]]) -> str:
        # stable hash based on normalized urls + titles (capped)
        parts = []
        for it in (items or [])[:200]:
            parts.append(normalize_url(str(it.get("url", "") or "")))
            parts.append(str(it.get("title", "") or "")[:140])
        raw = "||".join(parts).encode("utf-8", errors="ignore")
        return hashlib.sha1(raw).hexdigest()

    def _build_prompt(self, date_str: str, items: List[Dict[str, Any]]) -> str:
        # IMPORTANT: NO forecasting, NO operational guidance. Summary only.
        trimmed = []
        for it in (items or [])[:Config.XAI_MAX_INPUT_ITEMS]:
            t = str(it.get("title", "") or "").strip()
            s = str(it.get("snippet", "") or "").strip()
            u = str(it.get("url", "") or "").strip()
            if not (t or s):
                continue
            line = f"- TITLE: {t[:160]}\n  SNIPPET: {s[:Config.XAI_MAX_TEXT_CHARS_PER_ITEM]}\n  URL: {u[:220]}"
            trimmed.append(line)

        blob = "\n".join(trimmed).strip()
        if not blob:
            blob = "(no items)"

        return f"""
You are an OSINT summarizer.
DATE: {date_str}

TASK:
Summarize the main publicly-visible topics and narratives for this date based ONLY on the collected items.
Do NOT forecast, do NOT provide tactical/operational advice, do NOT suggest harmful actions.
Be concise and factual.

Return STRICT JSON ONLY with this schema:
{{
  "summary": "2-5 sentences",
  "top_topics": [{{"topic":"...", "notes":"..."}}, ...],
  "source_mix": {{"x_items": <int>, "web_items": <int>}},
  "caveats": ["..."]
}}

ITEMS:
{blob}
""".strip()

    @retry_with_backoff(retries=Config.MAX_RETRIES, base=1.0)
    def summarize_day(
        self,
        date_obj: datetime.date,
        items: List[Dict[str, Any]],
        model: str,
        temperature: float
    ) -> Tuple[Dict[str, Any], bool]:
        date_str = date_obj.strftime("%Y-%m-%d")
        fp = self._items_fingerprint(items)
        query_hash = hashlib.md5((date_str + fp + model + str(temperature) + Config.VERSION_TAG).encode("utf-8")).hexdigest()

        cached = db_manager.get_data(date_str, "GROK_" + query_hash)
        if cached:
            return cached, True

        prompt = self._build_prompt(date_str, items)

        url = Config.XAI_API_BASE + Config.XAI_CHAT_COMPLETIONS_ENDPOINT
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        payload = {
            "messages": [{"role": "user", "content": prompt}],
            "model": model,
            "stream": False,
            "temperature": float(temperature),
        }

        self.rate.acquire()
        r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=Config.XAI_TIMEOUT_SEC)

        if r.status_code == 429:
            raise RuntimeError("XAI_RATE_LIMIT_429")
        if r.status_code >= 400:
            raise RuntimeError(f"XAI_HTTP_{r.status_code}: {r.text[:300]}")

        resp = r.json()

        # expected shape similar to OpenAI-style chat completions
        text = ""
        try:
            text = resp["choices"][0]["message"]["content"]
        except Exception:
            text = ""

        parsed = extract_json_object(text)
        if not isinstance(parsed, dict) or not parsed:
            parsed = {
                "summary": (text or "")[:1200],
                "top_topics": [],
                "source_mix": {"x_items": 0, "web_items": 0},
                "caveats": ["non_strict_json_response"],
            }

        out = {
            "error": None,
            "debug": {"date": date_str, "model": model, "temperature": float(temperature)},
            "result": parsed,
        }

        db_manager.save_data(date_str, "GROK_" + query_hash, out)
        return out, False


# =========================
# Data Analyzer
# =========================
class DataAnalyzer:
    @staticmethod
    def _clean_text(s: str) -> str:
        s = (s or "").lower().strip()
        s = re.sub(r"\s+", " ", s)
        s = re.sub(r"[^\w\s\-:/\.]", "", s)
        return s.strip()

    def _fingerprint(self, title: str, snippet: str) -> str:
        raw = (self._clean_text(title) + "||" + self._clean_text(snippet)).encode("utf-8", errors="ignore")
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

        df = df[~df["domain"].isin(Config.BLACKLIST_DOMAINS)]
        df = df[~df["domain"].apply(is_aggregator_domain)]

        if df.empty:
            return self._empty()

        df["fp"] = df.apply(lambda r: self._fingerprint(r["title"], r["snippet"]), axis=1)
        df = df.drop_duplicates("fp")
        df = df.drop_duplicates("url_norm")

        if df.empty:
            return self._empty()

        df["weight"] = df["domain"].apply(domain_weight).astype(float)
        df["text"] = (df["title"] + " " + df["snippet"]).str.strip()

        clusters = []
        if len(df) > 1 and df["text"].str.len().sum() > 0:
            vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
            tfidf = vec.fit_transform(df["text"])
            sim = cosine_similarity(tfidf)

            visited = set()
            for i in range(len(df)):
                if i in visited:
                    continue
                idxs = [i]
                visited.add(i)
                for j in range(i + 1, len(df)):
                    if j in visited:
                        continue
                    if float(sim[i][j]) > Config.CLUSTER_SIM_THRESHOLD:
                        idxs.append(j)
                        visited.add(j)

                part = df.iloc[idxs]
                clusters.append({
                    "cluster_id": int(len(clusters)),
                    "main_title": str(part.iloc[0]["title"]),
                    "count": int(len(part)),
                    "unique_domains": int(part["domain"].nunique()),
                    "max_weight": float(part["weight"].max()),
                    "indices": [int(x) for x in idxs]
                })
        else:
            clusters = [{
                "cluster_id": 0,
                "main_title": str(df.iloc[0]["title"]),
                "count": 1,
                "unique_domains": 1,
                "max_weight": float(df.iloc[0]["weight"]),
                "indices": [0]
            }]

        unique_domains = set([d for d in df["domain"].unique().tolist() if d])
        unique_stories = int(len(clusters))

        weighted_volume = float(df["weight"].sum())
        avg_cluster_quality = float(np.mean([c["max_weight"] for c in clusters])) if clusters else 0.0

        score = (unique_stories * 3.0) + (weighted_volume * 5.0) + (avg_cluster_quality * 20.0)
        score = float(min(score, 100.0))

        conf = avg_cluster_quality
        domain_count = len(unique_domains)
        scarcity_penalty = 1.0
        if domain_count < 4:
            scarcity_penalty *= (domain_count / 4.0)
        if unique_stories < 2:
            scarcity_penalty *= 0.6
        conf = float(max(0.0, min(1.0, conf * scarcity_penalty)))

        evidence = []
        top_clusters = sorted(clusters, key=lambda x: (x["max_weight"], x["count"]), reverse=True)[:5]
        seen = set()
        for cl in top_clusters:
            cdf = df.iloc[cl["indices"]]
            best = cdf.sort_values("weight", ascending=False).iloc[0]
            u = str(best["url_norm"])
            if u in seen:
                continue
            seen.add(u)
            evidence.append({
                "title": str(best["title"]),
                "url": u,
                "domain": str(best["domain"]),
                "weight": float(best["weight"]),
                "is_tier1": bool(float(best["weight"]) >= 0.80),
            })

        return {
            "volume": int(len(df)),
            "clusters": unique_stories,
            "valid_unique_domains": int(len(unique_domains)),
            "escalation_score": score,
            "confidence": round(conf, 2),
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
            "evidence": []
        }


@st.cache_resource
def get_analyzer() -> DataAnalyzer:
    return DataAnalyzer()


analyzer = get_analyzer()


# =========================
# Timeline metrics
# =========================
def pearson_corr(a: List[float], b: List[float]) -> float:
    if not a or not b:
        return 0.0
    n = min(len(a), len(b))
    x = np.array(a[:n], dtype=float)
    y = np.array(b[:n], dtype=float)
    if float(np.std(x)) == 0.0 or float(np.std(y)) == 0.0:
        return 0.0
    return float(np.corrcoef(x, y)[0, 1])


def moving_average(arr: List[float], w: int) -> List[float]:
    if not arr:
        return []
    out = []
    for i in range(len(arr)):
        start = max(0, i - w + 1)
        chunk = arr[start:i + 1]
        out.append(float(np.mean(chunk)))
    return out


def z_scores(arr: List[float]) -> List[float]:
    if not arr:
        return []
    x = np.array(arr, dtype=float)
    mu = float(np.mean(x))
    sd = float(np.std(x))
    if sd == 0.0:
        return [0.0 for _ in arr]
    return [float((v - mu) / sd) for v in x]


def build_assessment(live_rows: List[Dict[str, Any]], kpis: Dict[str, Any]) -> str:
    max_score = float(kpis.get("live_max_score", 0.0) or 0.0)
    avg_conf = float(kpis.get("avg_confidence_live", 0.0) or 0.0)
    anom = int(kpis.get("live_anomaly_count", 0) or 0)

    if not live_rows:
        return "אין נתונים להצגה בטווח שנבחר (OSINT בלבד)."

    if max_score == 0.0 and avg_conf == 0.0:
        return (
            "לא אותר סיגנל תקשורתי בטווח הנבדק. "
            "אם זה לא הגיוני מול המציאות, בדוק: מילות מפתח, מצב איסוף/אימות, ומכסת API."
        )

    lines = []
    lines.append(f"בטווח הנבדק: שיא Score={max_score:.2f}, ממוצע Confidence={avg_conf:.2f}, אנומליות={anom}.")
    if max_score >= 60:
        lines.append("נפח/איכות דיווחים גלויים גבוהה יחסית (עדיין OSINT).")
    elif max_score >= 30:
        lines.append("יש פעילות תקשורתית בינונית-מובהקת (OSINT).")
    else:
        lines.append("יש פעילות תקשורתית חלשה/מפוזרת (OSINT).")

    if anom > 0:
        lines.append("זוהתה חריגה סטטיסטית (z-score). זה מצדיק בדיקה ידנית של הראיות.")
    return "\n".join(lines)


# =========================
# Secrets / Access
# =========================
GOOGLE_API_KEY = st.secrets.get("GOOGLE_API_KEY", "")
if not GOOGLE_API_KEY:
    st.error("חסר GOOGLE_API_KEY ב־Streamlit Secrets. (Settings → Secrets)")
    st.stop()

APP_PASSWORD = st.secrets.get("APP_PASSWORD", "")
if APP_PASSWORD:
    pw = st.sidebar.text_input("סיסמה", type="password")
    if not pw or not hmac.compare_digest(pw, APP_PASSWORD):
        st.sidebar.info("נדרש אימות כדי להמשיך.")
        st.stop()


# =========================
# Sidebar
# =========================
with st.sidebar:
    st.header("⚙️ הגדרות סנסור")

    st.divider()
    st.subheader("📡 טווחי זמן")
    reference_anchor = st.date_input("תאריך אירוע עבר (Reference):", datetime.date(2025, 6, 15))
    live_anchor = st.date_input("תאריך נוכחי (Live):", datetime.date(2025, 12, 28))
    window_days = st.slider("חלון סריקה (ימים):", 7, 45, 20)

    st.divider()
    st.subheader("✅ מצב איסוף/אימות")
    validation_mode = st.radio("מצב:", ["Collect", "Strict", "Relaxed"], index=0)
    keywords = st.text_input("מילות חיפוש (WEB/Gemini):", "Iran Israel military conflict missile attack nuclear")

    st.divider()
    st.subheader("𝕏 שלב 1: X API")
    include_x = st.checkbox("לשלב X API בשלב הראשון", value=True)
    x_query = st.text_input(
        "שאילתת X (query):",
        value="(Iran OR Israel) (missile OR nuclear OR attack OR military) -is:retweet lang:en"
    )
    use_full_archive = st.checkbox("X Full-Archive (/search/all) אם יש הרשאה", value=False)

    st.divider()
    st.subheader("🤖 שלב 3: Grok (x.ai) סיכום יומי")
    include_grok = st.checkbox("להפעיל Grok לסיכום יומי (לא תחזיות)", value=False)
    grok_model = st.text_input("Model", value=Config.XAI_DEFAULT_MODEL)
    grok_temperature = st.slider("Temperature", 0.0, 1.0, 0.7, 0.1)

    st.divider()
    show_debug = st.checkbox("הצג Debug לכל יום", value=False)

    # estimate calls (rough)
    days_total = (window_days + 1) * 2  # ref + live
    est_calls = days_total  # WEB per day
    if include_x:
        est_calls += days_total  # X per day (ignoring pagination)
    if include_grok:
        est_calls += days_total  # Grok per day
    st.caption(f"📊 צפי קריאות API (גס): {est_calls}  | מקביליות: {Config.MAX_WORKERS}")
    if est_calls > 80:
        st.markdown("<span class='metric-warning'>⚠️ שים לב ל-Quota</span>", unsafe_allow_html=True)

# load X + XAI secrets only if enabled
X_BEARER_TOKEN = st.secrets.get("X_BEARER_TOKEN", "")
if include_x and not X_BEARER_TOKEN:
    st.error("חסר X_BEARER_TOKEN ב־Streamlit Secrets. (Settings → Secrets)")
    st.stop()

XAI_API_KEY = st.secrets.get("XAI_API_KEY", "")
if include_grok and not XAI_API_KEY:
    st.error("חסר XAI_API_KEY ב־Streamlit Secrets. (Settings → Secrets)")
    st.stop()


# =========================
# Execution
# =========================
@st.cache_resource
def get_rate_limiter() -> GlobalRateLimiter:
    return GlobalRateLimiter(min_interval=Config.MIN_INTERVAL_SEC, jitter=Config.JITTER_SEC)


rate_limiter = get_rate_limiter()


def process_day(
    scanner: GeminiScanner,
    xscanner: Optional[XScanner],
    grok: Optional[GrokSummarizer],
    d: datetime.date,
    keywords_: str,
    x_query_: str,
    mode_: str,
    include_x_: bool,
    use_full_archive_: bool,
    include_grok_: bool,
    grok_model_: str,
    grok_temp_: float,
) -> Dict[str, Any]:

    # Stage 1: X
    x_raw = {"error": "X_DISABLED", "debug": {"date": d.isoformat()}, "items": []}
    x_cached = False
    if include_x_ and xscanner is not None and x_query_.strip():
        x_raw, x_cached = xscanner.fetch_day(d, x_query_, use_full_archive_)

    # Stage 2: Gemini Flash (Web)
    web_raw, web_cached = scanner.fetch_day(d, keywords_, mode_)

    # Combined daily "data lake" (no mandatory cross-validation)
    combined_items = (x_raw.get("items", []) or []) + (web_raw.get("items", []) or [])

    combined_error = None
    if x_raw.get("error") and x_raw.get("error") not in ("X_DISABLED", None, ""):
        combined_error = f"X:{x_raw.get('error')}"
    if web_raw.get("error"):
        combined_error = (combined_error + " | " if combined_error else "") + f"WEB:{web_raw.get('error')}"

    combined_raw = {
        "error": combined_error,
        "debug": {
            "date": d.isoformat(),
            "mode": mode_,
            "x": x_raw.get("debug", {}),
            "web": web_raw.get("debug", {}),
            "x_items": int(len(x_raw.get("items", []) or [])),
            "web_items": int(len(web_raw.get("items", []) or [])),
        },
        "items": combined_items,
        "sources": {"x": x_raw, "web": web_raw},
    }

    analytics = analyzer.analyze(combined_raw.get("items", []))

    # Stage 3: Grok daily summary (optional)
    grok_out = {"error": "GROK_DISABLED", "debug": {"date": d.isoformat()}, "result": {}}
    grok_cached = False
    if include_grok_ and grok is not None:
        try:
            grok_out, grok_cached = grok.summarize_day(d, combined_items, model=grok_model_, temperature=grok_temp_)
        except Exception as e:
            grok_out = {"error": str(e), "debug": {"date": d.isoformat()}, "result": {}}

    combined_raw["grok"] = grok_out
    combined_raw["debug"]["grok_cached"] = bool(grok_cached)

    # Cached: if X is off -> web only; if grok on -> all should be cached to be "cached"
    cached = web_cached
    if include_x_:
        cached = cached and x_cached
    if include_grok_:
        cached = cached and grok_cached

    return {
        "date_obj": d,
        "date_label": d.strftime("%d/%m"),
        "raw": combined_raw,
        "analytics": analytics,
        "cached": cached,
    }


def run_scan() -> Dict[str, Any]:
    scanner = GeminiScanner(
        api_key=GOOGLE_API_KEY,
        rate_limiter=rate_limiter,
        pool_size=max(2, Config.MAX_WORKERS),
    )

    xscanner = None
    if include_x:
        xscanner = XScanner(bearer_token=X_BEARER_TOKEN, rate_limiter=rate_limiter)

    grok = None
    if include_grok:
        grok = GrokSummarizer(api_key=XAI_API_KEY, rate_limiter=rate_limiter)

    ref_dates = [reference_anchor - datetime.timedelta(days=i) for i in range(window_days, -1, -1)]
    live_dates = [live_anchor - datetime.timedelta(days=i) for i in range(window_days, -1, -1)]

    total_tasks = len(ref_dates) + len(live_dates)
    completed = 0

    status = st.empty()
    prog = st.progress(0.0)

    results_map: Dict[str, Dict[str, Any]] = {}
    all_dates = [("Reference", d) for d in ref_dates] + [("Live", d) for d in live_dates]

    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as ex:
        futures = {
            ex.submit(
                process_day,
                scanner, xscanner, grok,
                d, keywords, x_query, validation_mode,
                include_x, use_full_archive,
                include_grok, grok_model, grok_temperature
            ): (typ, d)
            for typ, d in all_dates
        }

        for fut in concurrent.futures.as_completed(futures):
            typ, d = futures[fut]
            try:
                res = fut.result()
                if typ == "Reference":
                    delta = (reference_anchor - d).days
                    res["day_offset"] = int(-delta)
                else:
                    delta = (live_anchor - d).days
                    res["day_offset"] = int(-delta)
                res["type"] = typ
                results_map[f"{typ}_{d.isoformat()}"] = res
            except Exception as e:
                logger.exception(f"{typ} {d} failed: {e}")
            finally:
                completed += 1
                prog.progress(min(1.0, completed / max(1, total_tasks)))
                status.text(f"Processed: {d.strftime('%d/%m')} ({typ})")

    ref_timeline = sorted([v for v in results_map.values() if v["type"] == "Reference"], key=lambda x: x["day_offset"])
    live_timeline = sorted([v for v in results_map.values() if v["type"] == "Live"], key=lambda x: x["day_offset"])

    ref_scores = [float(x["analytics"]["escalation_score"]) for x in ref_timeline]
    live_scores = [float(x["analytics"]["escalation_score"]) for x in live_timeline]
    corr = pearson_corr(ref_scores, live_scores)

    live_conf = [float(x["analytics"]["confidence"]) for x in live_timeline]
    avg_conf = float(np.mean(live_conf)) if live_conf else 0.0
    live_max = float(np.max(live_scores)) if live_scores else 0.0

    live_z = z_scores(live_scores)
    anomalies = [i for i, z in enumerate(live_z) if abs(float(z)) >= Config.ANOMALY_Z_ABS]
    anom_count = int(len(anomalies))

    kpis = {
        "correlation": float(corr),
        "avg_confidence_live": float(avg_conf),
        "live_max_score": float(live_max),
        "live_anomaly_count": anom_count,
    }

    export_obj = {
        "meta": {
            "generated_at": datetime.datetime.now().isoformat(),
            "keywords_web": keywords,
            "x_query": x_query,
            "validation_mode": validation_mode,
            "window_days": int(window_days),
            "reference_anchor": reference_anchor.isoformat(),
            "live_anchor": live_anchor.isoformat(),
            "models": {"flash": Config.FLASH_MODEL, "pro": Config.PRO_MODEL},
            "x": {"enabled": bool(include_x), "full_archive": bool(use_full_archive)},
            "grok": {"enabled": bool(include_grok), "model": grok_model, "temperature": float(grok_temperature)},
            "kpis": kpis,
        },
        "reference": [
            {
                "type": "Reference",
                "day_offset": x["day_offset"],
                "date": x["date_label"],
                "cached": x["cached"],
                "raw": x["raw"],
                "analytics": x["analytics"],
            } for x in ref_timeline
        ],
        "live": [
            {
                "type": "Live",
                "day_offset": x["day_offset"],
                "date": x["date_label"],
                "cached": x["cached"],
                "raw": x["raw"],
                "analytics": x["analytics"],
            } for x in live_timeline
        ],
    }

    db_manager.audit(
        action="scan_run",
        query_hash=hashlib.md5((keywords + x_query + validation_mode + Config.VERSION_TAG).encode("utf-8")).hexdigest(),
        keywords=keywords,
        validation_mode=validation_mode,
        window_days=window_days,
        reference_anchor=reference_anchor.isoformat(),
        live_anchor=live_anchor.isoformat(),
        meta={"kpis": kpis, "x": {"enabled": include_x, "full_archive": use_full_archive}, "grok": {"enabled": include_grok}},
    )

    return {
        "ref_timeline": ref_timeline,
        "live_timeline": live_timeline,
        "kpis": kpis,
        "live_anomaly_indices": anomalies,
        "export_obj": export_obj
    }


# =========================
# UI Controls
# =========================
if "scan_state" not in st.session_state:
    st.session_state.scan_state = None

colA, colB, colC = st.columns([1, 1, 2])
with colA:
    run_btn = st.button("🚀 הפעל סריקה", use_container_width=True)
with colB:
    clear_btn = st.button("🧹 נקה תוצאות", use_container_width=True)

if clear_btn:
    st.session_state.scan_state = None
    st.rerun()

if run_btn:
    if not keywords.strip():
        st.error("מילות חיפוש ריקות (WEB).")
    else:
        st.session_state.scan_state = run_scan()

state = st.session_state.scan_state
if not state:
    st.info("בחר הגדרות והפעל סריקה.")
    st.stop()

ref_timeline = state["ref_timeline"]
live_timeline = state["live_timeline"]
kpis = state["kpis"]
anom_idxs = state["live_anomaly_indices"]
export_obj = state["export_obj"]


# =========================
# KPI cards
# =========================
k1, k2, k3, k4 = st.columns(4)
k1.metric("Correlation (Ref↔Live)", f"{kpis['correlation']:.2f}")
k2.metric("Avg Confidence (Live)", f"{kpis['avg_confidence_live']:.2f}")
k3.metric("Live Max Score", f"{kpis['live_max_score']:.2f}")
k4.metric(f"Live Anomalies (|z|≥{Config.ANOMALY_Z_ABS:g})", f"{kpis['live_anomaly_count']}")


# =========================
# Trend chart
# =========================
st.subheader("📈 תמונת מודיעין (Score + Confidence + Trend)")

live_scores = [float(x["analytics"]["escalation_score"]) for x in live_timeline]
live_conf = [float(x["analytics"]["confidence"]) for x in live_timeline]
labels = [x["date_label"] for x in live_timeline]

ma3 = moving_average(live_scores, 3)
ma7 = moving_average(live_scores, 7)
zs = z_scores(live_scores)

fig = make_subplots(specs=[[{"secondary_y": True}]])
fig.add_trace(go.Scatter(x=labels, y=live_scores, mode="lines+markers", name="Score"), secondary_y=False)
fig.add_trace(go.Scatter(x=labels, y=ma3, mode="lines", name="MA(3)"), secondary_y=False)
fig.add_trace(go.Scatter(x=labels, y=ma7, mode="lines", name="MA(7)"), secondary_y=False)
fig.add_trace(go.Scatter(x=labels, y=live_conf, mode="lines+markers", name="Confidence"), secondary_y=True)

if anom_idxs:
    fig.add_trace(
        go.Scatter(
            x=[labels[i] for i in anom_idxs],
            y=[live_scores[i] for i in anom_idxs],
            mode="markers",
            name="Anomaly",
            marker=dict(size=12, symbol="x")
        ),
        secondary_y=False
    )

fig.update_layout(height=420, margin=dict(l=10, r=10, t=30, b=10))
fig.update_yaxes(title_text="Score", secondary_y=False)
fig.update_yaxes(title_text="Confidence", secondary_y=True)
st.plotly_chart(fig, use_container_width=True)

if anom_idxs:
    st.subheader("🧨 חריגות (Anomalies)")
    adf = pd.DataFrame({
        "date": [labels[i] for i in anom_idxs],
        "score": [live_scores[i] for i in anom_idxs],
        "z": [zs[i] for i in anom_idxs],
        "confidence": [live_conf[i] for i in anom_idxs],
    })
    st.dataframe(adf, use_container_width=True, hide_index=True)


# =========================
# Evidence Locker
# =========================
st.subheader("🔍 חקר ראיות (Evidence Locker)")
tab1, tab2 = st.tabs(["Reference", "Live"])


def render_timeline(timeline: List[Dict[str, Any]]):
    for day in timeline:
        score = float(day["analytics"]["escalation_score"])
        conf = float(day["analytics"]["confidence"])
        vol = int(day["analytics"]["volume"])
        err = day["raw"].get("error")
        debug = day["raw"].get("debug", {}) or {}

        badge = "🟢" if conf >= 0.55 else ("🟡" if conf >= 0.30 else "🔴")
        title = f"{day['date_label']} | Score: {score:.2f} | Conf: {conf:.2f} {badge} | Vol: {vol}"
        if err:
            title += f" | ⚠️ {err}"

        with st.expander(title, expanded=False):
            # show grok (optional)
            grok_obj = (day["raw"].get("grok") or {})
            grok_err = grok_obj.get("error")
            grok_res = grok_obj.get("result") or {}
            if include_grok and (grok_err is None or grok_err == "") and grok_res:
                st.markdown(
                    f"<div class='grok-box'><b>Grok סיכום יומי:</b><br>{str(grok_res.get('summary','')).strip()}</div>",
                    unsafe_allow_html=True
                )

            for cl in day["analytics"].get("top_clusters", [])[:3]:
                st.markdown(
                    f"<div class='cluster-card'><b>{cl['main_title']}</b><br>"
                    f"Count: {cl['count']} | Unique domains: {cl['unique_domains']} | Max weight: {cl['max_weight']}</div>",
                    unsafe_allow_html=True
                )

            ev = day["analytics"].get("evidence", [])
            if not ev:
                st.caption("אין ראיות מסוננות ליום הזה.")
            else:
                for e in ev:
                    tier = "Tier1" if e.get("is_tier1") else "Other"
                    st.markdown(
                        f"<a class='evidence-link' href='{e['url']}' target='_blank'>🔗 {e['domain']} ({tier}) — {e['title']}</a>",
                        unsafe_allow_html=True
                    )

            if show_debug:
                st.markdown("<div class='debug-info'>", unsafe_allow_html=True)
                st.write("debug:", debug)
                if include_grok:
                    st.write("grok_debug:", grok_obj.get("debug", {}))
                    if grok_err and grok_err not in ("GROK_DISABLED", None, ""):
                        st.write("grok_error:", grok_err)
                st.markdown("</div>", unsafe_allow_html=True)


with tab1:
    render_timeline(ref_timeline)

with tab2:
    render_timeline(live_timeline)


# =========================
# Assessment (deterministic, no forecasting)
# =========================
st.subheader("🧠 הערכת מצב (OSINT בלבד)")
st.write(build_assessment(live_timeline, kpis))


# =========================
# Export
# =========================
st.subheader("⬇️ יצוא דו״ח")

json_bytes = safe_json_bytes(export_obj, indent=2)
st.download_button(
    "הורד JSON",
    data=json_bytes,
    file_name="osint_report.json",
    mime="application/json",
    use_container_width=True,
)

rows = []
for day in (ref_timeline + live_timeline):
    dbg = (day["raw"].get("debug") or {})
    web_dbg = (dbg.get("web") or {})
    x_dbg = (dbg.get("x") or {})
    grok_dbg = (day["raw"].get("grok") or {}).get("debug", {}) or {}

    rows.append({
        "type": day["type"],
        "date": day["date_obj"].isoformat(),
        "date_label": day["date_label"],
        "day_offset": day["day_offset"],
        "score": float(day["analytics"]["escalation_score"]),
        "confidence": float(day["analytics"]["confidence"]),
        "volume": int(day["analytics"]["volume"]),
        "clusters": int(day["analytics"]["clusters"]),
        "unique_domains": int(day["analytics"]["valid_unique_domains"]),
        "cached": bool(day["cached"]),
        "error": str(day["raw"].get("error") or ""),
        "x_items": int(dbg.get("x_items", 0) or 0),
        "web_items": int(dbg.get("web_items", 0) or 0),
        "web_raw_items": int(web_dbg.get("raw_items", 0) or 0),
        "web_validated": int(web_dbg.get("validated", 0) or 0),
        "x_pages": int(x_dbg.get("pages", 0) or 0),
        "grok_model": str(grok_dbg.get("model", "") or ""),
        "grok_temp": float(grok_dbg.get("temperature", 0.0) or 0.0),
    })

summary_df = pd.DataFrame(rows).sort_values(["type", "day_offset"])
csv_bytes = summary_df.to_csv(index=False).encode("utf-8")
st.download_button(
    "הורד CSV (סיכום)",
    data=csv_bytes,
    file_name="osint_report_summary.csv",
    mime="text/csv",
    use_container_width=True,
)

xlsx_buf = io.BytesIO()
with pd.ExcelWriter(xlsx_buf, engine="openpyxl") as writer:
    summary_df.to_excel(writer, index=False, sheet_name="summary")
    pd.DataFrame([to_jsonable(export_obj["meta"])]).to_excel(writer, index=False, sheet_name="meta")
xlsx_buf.seek(0)

st.download_button(
    "הורד XLSX",
    data=xlsx_buf.getvalue(),
    file_name="osint_report.xlsx",
    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    use_container_width=True,
)
