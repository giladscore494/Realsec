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
            if not grounded_keys and not grounded_domains:
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

            db_manager.save_data(date_str, query_hash, out)
            return out, False

        except Exception as e:
            logger.exception(f"Fetch failed for {date_str}: {e}")
            out = {"error": str(e), "debug": {"date": date_str, "mode": mode}, "items": []}
            db_manager.save_data(date_str, query_hash, out)
            return out, False
        finally:
            self.clients.release(client)


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

        # hard filters
        df = df[~df["domain"].isin(Config.BLACKLIST_DOMAINS)]
        df = df[~df["domain"].apply(is_aggregator_domain)]

        if df.empty:
            return self._empty()

        # dedup: fingerprint + url_norm
        df["fp"] = df.apply(lambda r: self._fingerprint(r["title"], r["snippet"]), axis=1)
        df = df.drop_duplicates("fp")
        df = df.drop_duplicates("url_norm")

        if df.empty:
            return self._empty()

        # weights
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

        # confidence: calibrated
        conf = avg_cluster_quality
        domain_count = len(unique_domains)
        scarcity_penalty = 1.0
        if domain_count < 4:
            scarcity_penalty *= (domain_count / 4.0)
        if unique_stories < 2:
            scarcity_penalty *= 0.6
        conf = float(max(0.0, min(1.0, conf * scarcity_penalty)))

        # evidence: pick best from top clusters
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
# Timeline metrics (trend/anomaly/correlation)
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
    # deterministic, no forecasting
    max_score = float(kpis.get("live_max_score", 0.0) or 0.0)
    avg_conf = float(kpis.get("avg_confidence_live", 0.0) or 0.0)
    anom = int(kpis.get("live_anomaly_count", 0) or 0)

    if not live_rows:
        return "אין נתונים להצגה בטווח שנבחר (OSINT בלבד)."

    if max_score == 0.0 and avg_conf == 0.0:
        return (
            "לא אותר סיגנל תקשורתי מאומת בטווח הנבדק. "
            "אם זה לא הגיוני מול המציאות, בדוק: מילות מפתח, מצב אימות (Strict/Relaxed), ומקורות."
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
        lines.append("זוהתה חריגה סטטיסטית לפחות פעם אחת (z-score). זה מצדיק בדיקה ידנית של הראיות.")
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

    est_calls = (window_days + 1) * 2
    st.caption(f"📊 צפי קריאות API: {est_calls} (במקביליות: {Config.MAX_WORKERS})")
    if est_calls > 60:
        st.markdown("<span class='metric-warning'>⚠️ שים לב ל-Quota</span>", unsafe_allow_html=True)

    st.divider()
    validation_mode = st.radio("רמת אימות:", ["Strict", "Relaxed"], index=1)
    keywords = st.text_input("מילות חיפוש:", "Iran Israel military conflict missile attack nuclear")

    st.divider()
    show_debug = st.checkbox("הצג Debug לכל יום", value=False)


# =========================
# Execution
# =========================
rate_limiter = GlobalRateLimiter(min_interval=Config.MIN_INTERVAL_SEC, jitter=Config.JITTER_SEC)


def process_day(scanner: GeminiScanner, d: datetime.date, keywords: str, mode: str) -> Dict[str, Any]:
    raw_data, cached = scanner.fetch_day(d, keywords, mode)
    analytics = analyzer.analyze(raw_data.get("items", []))
    return {
        "date_obj": d,
        "date_label": d.strftime("%d/%m"),
        "raw": raw_data,
        "analytics": analytics,
        "cached": cached,
    }


def run_scan() -> Dict[str, Any]:
    scanner = GeminiScanner(
        api_key=GOOGLE_API_KEY,
        rate_limiter=rate_limiter,
        pool_size=max(2, Config.MAX_WORKERS),
    )

    ref_dates = [reference_anchor - datetime.timedelta(days=i) for i in range(window_days, -1, -1)]
    live_dates = [live_anchor - datetime.timedelta(days=i) for i in range(window_days, -1, -1)]

    total_tasks = len(ref_dates) + len(live_dates)
    completed = 0

    status = st.empty()
    prog = st.progress(0.0)

    results_map: Dict[str, Dict[str, Any]] = {}

    all_dates = [("Reference", d) for d in ref_dates] + [("Live", d) for d in live_dates]

    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as ex:
        futures = {}
        for typ, d in all_dates:
            futures[ex.submit(process_day, scanner, d, keywords, validation_mode)] = (typ, d)

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

    # KPI
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
            "keywords": keywords,
            "validation_mode": validation_mode,
            "window_days": int(window_days),
            "reference_anchor": reference_anchor.isoformat(),
            "live_anchor": live_anchor.isoformat(),
            "models": {"flash": Config.FLASH_MODEL, "pro": Config.PRO_MODEL},
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
        query_hash=hashlib.md5((keywords + validation_mode + Config.VERSION_TAG).encode("utf-8")).hexdigest(),
        keywords=keywords,
        validation_mode=validation_mode,
        window_days=window_days,
        reference_anchor=reference_anchor.isoformat(),
        live_anchor=live_anchor.isoformat(),
        meta={"kpis": kpis},
    )

    return {
        "ref_timeline": ref_timeline,
        "live_timeline": live_timeline,
        "kpis": kpis,
        "live_anomaly_indices": anomalies,
        "export_obj": export_obj
    }


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
        st.error("מילות חיפוש ריקות.")
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

# anomaly markers
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

# Anomalies table
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
            # clusters preview
            for cl in day["analytics"].get("top_clusters", [])[:3]:
                st.markdown(
                    f"<div class='cluster-card'><b>{cl['main_title']}</b><br>"
                    f"Count: {cl['count']} | Unique domains: {cl['unique_domains']} | Max weight: {cl['max_weight']}</div>",
                    unsafe_allow_html=True
                )

            # evidence
            ev = day["analytics"].get("evidence", [])
            if not ev:
                st.caption("אין ראיות מאומתות ליום הזה.")
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

# JSON
json_bytes = safe_json_bytes(export_obj, indent=2)
st.download_button(
    "הורד JSON",
    data=json_bytes,
    file_name="osint_report.json",
    mime="application/json",
    use_container_width=True,
)

# CSV summary (per-day)
rows = []
for day in (ref_timeline + live_timeline):
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
        "raw_items": int((day["raw"].get("debug") or {}).get("raw_items", 0) or 0),
        "validated": int((day["raw"].get("debug") or {}).get("validated", 0) or 0),
        "strict_fallback_hits": int((day["raw"].get("debug") or {}).get("strict_fallback_hits", 0) or 0),
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

# XLSX
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