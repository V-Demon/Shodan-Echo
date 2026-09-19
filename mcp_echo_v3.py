#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCP-ECHO v3.0 — Model Context Protocol Temporal Mapper
Extension majeure :
  · Handshake JSON-RPC 2.0 complet (initialize → tools/list → resources/list → prompts/list)
  · Transport HTTP, SSE et WebSocket
  · Scan concurrent (asyncio.Semaphore)
  · Fingerprinting serveur (headers HTTP, framework)
  · Cache persistant SQLite
  · Shodan rate-limiting + cache disque
  · GUI complète : drag, clic, panneau détails, barre de progression, bouton Annuler
  · Export JSON / NDJSON / CSV
  · Delta multi-facteurs enrichi
  · Corpus Vauvillensis étendu (17 ports fantômes)

Auteur : Kefas N00sph (adapté pour le Collectif des Veilleurs)

Dépendances :
    pip install aiohttp aiohttp[speedups] websockets requests

Usage :
    python3 mcp_echo_v3.py --gui
    python3 mcp_echo_v3.py --target http://localhost:8000
    python3 mcp_echo_v3.py --batch targets.txt --concurrency 10 --fmt ndjson -o out.ndjson
    python3 mcp_echo_v3.py --shodan-api KEY --shodan-discover
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import dataclasses
import enum
import hashlib
import json
import logging
import os
import re
import signal
import sqlite3
import sys
import threading
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Imports optionnels — dégradation gracieuse
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import websockets
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog
    HAS_TK = True
except ImportError:
    HAS_TK = False

# ==============================================================================
# LOGGING
# ==============================================================================

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("mcp-echo")


# ==============================================================================
# CONSTANTES DU CORPUS VAUVILLENSIS
# ==============================================================================

class CorpusConstants:
    """Constantes du Corpus Vauvillensis — version étendue v3."""

    VERSION = "3.0"
    MCP_PROTOCOL_VERSION = "2024-11-05"
    CLIENT_INFO = {"name": "MCP-ECHO", "version": VERSION}

    # Palette C64 authentique
    C64 = {
        'bg':          '#0000AA',
        'bg_dark':     '#000088',
        'fg':          '#00FF00',
        'fg_cyan':     '#00FFFF',
        'fg_yellow':   '#FFFF00',
        'fg_red':      '#FF5555',
        'fg_orange':   '#AA5500',
        'fg_magenta':  '#FF00FF',
        'fg_white':    '#FFFFFF',
        'fg_grey':     '#AAAAAA',
        'grid':        '#005588',
        'border':      '#008888',
    }

    # Endpoints MCP à sonder (par ordre de priorité)
    MCP_ENDPOINTS = [
        "",           # Racine
        "/mcp",
        "/mcp/v1",
        "/api/mcp",
        "/rpc",
        "/jsonrpc",
        "/.well-known/mcp",
    ]

    # Endpoints SSE
    SSE_ENDPOINTS = ["/sse", "/events", "/stream", "/mcp/sse"]

    # Endpoints WebSocket
    WS_ENDPOINTS = ["/ws", "/mcp/ws", "/websocket"]

    # Signatures MCP dans les réponses HTTP
    MCP_HTTP_SIGNATURES = [
        "model context protocol",
        "mcp-version",
        "x-mcp",
        '"jsonrpc"',
        '"method":"initialize"',
        '"protocolVersion"',
        "mcp server",
    ]

    # Fingerprints de frameworks connus
    SERVER_FRAMEWORKS = {
        "fastapi":     ["fastapi", "uvicorn"],
        "express":     ["express"],
        "flask":       ["flask", "werkzeug"],
        "django":      ["django"],
        "actix":       ["actix-web"],
        "spring":      ["spring"],
        "nginx":       ["nginx"],
        "apache":      ["apache"],
        "cloudflare":  ["cloudflare"],
        "vercel":      ["vercel", "x-vercel"],
    }

    # Filtres Shodan MCP
    SHODAN_FILTERS = [
        'http.title:"Model Context Protocol"',
        'http.component:"mcp"',
        'port:8000 http.html:"mcp"',
        'port:3000 http.html:"sse"',
        'http.headers:"mcp-version"',
        'http.html:"jsonrpc" port:8000',
        'http.html:"tools/list"',
    ]

    # Corpus des Ports Fantômes — v3 étendu (17 entrées)
    GHOST_PORTS: Dict[int, Dict[str, str]] = {
        0:     {"name": "Le Vide",             "desc": "Port Ontologique",              "severity": "OMEGA"},
        3303:  {"name": "Galet-Ancre",         "desc": "Bio-lithique",                  "severity": "STABLE"},
        7071:  {"name": "Le Transept",         "desc": "Fenêtre 707s",                  "severity": "TROUBLE"},
        8008:  {"name": "La Réflexion",        "desc": "Miroir HTTP inversé",           "severity": "STABLE"},
        9877:  {"name": "Faille du Jardinier", "desc": "Injection HFT",                "severity": "TURBULENT"},
        11223: {"name": "Le Palindrome",       "desc": "Résonance symétrique",          "severity": "TROUBLE"},
        11440: {"name": "Port Trickster",      "desc": "144 symboles / cycle court",   "severity": "TURBULENT"},
        13013: {"name": "Le Double Verrou",    "desc": "Chiasme 13 (cycle lunaire)",    "severity": "TROUBLE"},
        14225: {"name": "Bande 17m",           "desc": "Diffusion BloodNet HF",        "severity": "TURBULENT"},
        14400: {"name": "Port Noir",           "desc": "Ω-Trickster",                  "severity": "CRITIQUE"},
        19999: {"name": "L'Écho Inversé",      "desc": "Harmonique Sombre",             "severity": "TURBULENT"},
        22222: {"name": "Le Quintuple",        "desc": "Oscillation pentagonale",       "severity": "STABLE"},
        31337: {"name": "L'Élite",             "desc": "Spectre e337 / Elite",         "severity": "STABLE"},
        33333: {"name": "Les Trois Tiers",     "desc": "Triade de Vauvillens",         "severity": "TROUBLE"},
        44444: {"name": "Les Quatre Sceaux",   "desc": "Quaternité scellée",           "severity": "CRITIQUE"},
        55555: {"name": "La Quinte Essence",   "desc": "Distillat du Programme",       "severity": "OMEGA"},
        65535: {"name": "Le Plafond",          "desc": "Limite supérieure du Programme","severity": "CRITIQUE"},
    }

    SEVERITY_WEIGHTS = {"STABLE": 1, "TROUBLE": 2, "TURBULENT": 3, "CRITIQUE": 4, "OMEGA": 5}


# ==============================================================================
# CACHE PERSISTANT SQLITE
# ==============================================================================

class CacheManager:
    """Cache persistant SQLite — survit aux redémarrages."""

    def __init__(self, path: str = "~/.cache/mcp-echo/cache.db", ttl: int = 3600):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._init_db()

    def _conn_get(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        return self._conn

    def _init_db(self):
        with self._lock:
            conn = self._conn_get()
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    ts    REAL NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON cache(ts)")
            conn.commit()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            cur = self._conn_get().execute(
                "SELECT value, ts FROM cache WHERE key=?", (key,)
            )
            row = cur.fetchone()
        if row is None:
            return None
        if time.time() - row[1] > self.ttl:
            self.delete(key)
            return None
        try:
            return json.loads(row[0])
        except json.JSONDecodeError:
            return None

    def set(self, key: str, value: Any):
        with self._lock:
            conn = self._conn_get()
            conn.execute(
                "INSERT OR REPLACE INTO cache(key, value, ts) VALUES(?,?,?)",
                (key, json.dumps(value, default=str), time.time()),
            )
            conn.commit()

    def delete(self, key: str):
        with self._lock:
            self._conn_get().execute("DELETE FROM cache WHERE key=?", (key,))
            self._conn_get().commit()

    def purge_expired(self):
        with self._lock:
            conn = self._conn_get()
            conn.execute("DELETE FROM cache WHERE ts < ?", (time.time() - self.ttl,))
            conn.commit()

    def close(self):
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None


# ==============================================================================
# CLIENT SHODAN — v3 : rate-limiting, cache disque, retry
# ==============================================================================

class ShodanClient:
    """Client Shodan avec rate-limiting, cache persistant et retry."""

    BASE_URL = "https://api.shodan.io"
    RATE_LIMIT_DELAY = 1.0   # secondes entre requêtes

    def __init__(self, api_key: str, cache: Optional[CacheManager] = None):
        if not HAS_REQUESTS:
            raise RuntimeError("'requests' est requis pour ShodanClient")
        import requests
        self.api_key = api_key
        self.cache = cache
        self._session = requests.Session()
        self._session.params = {"key": api_key}  # type: ignore[assignment]
        self._last_request = 0.0

    def _throttle(self):
        elapsed = time.time() - self._last_request
        if elapsed < self.RATE_LIMIT_DELAY:
            time.sleep(self.RATE_LIMIT_DELAY - elapsed)
        self._last_request = time.time()

    def _get(self, path: str, params: Dict = None, retries: int = 3) -> Dict:
        self._throttle()
        url = f"{self.BASE_URL}{path}"
        for attempt in range(retries):
            try:
                resp = self._session.get(url, params=params or {}, timeout=15)
                if resp.status_code == 429:
                    wait = 2 ** attempt * 5
                    logger.warning("Shodan rate-limit (429) — attente %ss", wait)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                return resp.json()
            except Exception as exc:
                if attempt == retries - 1:
                    logger.error("Shodan GET %s échoué : %s", path, exc)
                    return {}
                time.sleep(2 ** attempt)
        return {}

    def search(self, query: str, limit: int = 100) -> List[Dict]:
        cache_key = f"shodan:search:{hashlib.md5(query.encode()).hexdigest()}:{limit}"
        if self.cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached

        results: List[Dict] = []
        pages = max(1, min((limit + 99) // 100, 10))

        for page in range(1, pages + 1):
            if len(results) >= limit:
                break
            data = self._get("/shodan/host/search", {"query": query, "page": page})
            results.extend(data.get("matches", []))

        results = results[:limit]
        if self.cache and results:
            self.cache.set(cache_key, results)
        return results

    def host_info(self, ip: str) -> Dict:
        cache_key = f"shodan:host:{ip}"
        if self.cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached
        data = self._get(f"/shodan/host/{ip}")
        if data and self.cache:
            self.cache.set(cache_key, data)
        return data


# ==============================================================================
# MCP PROBER — Handshake JSON-RPC 2.0 complet
# ==============================================================================

@dataclasses.dataclass
class MCPProbeResult:
    """Résultat complet d'un sondage MCP sur un endpoint."""
    url: str
    transport: str = "unknown"   # http | sse | ws | discovery
    detected: bool = False
    protocol_version: Optional[str] = None
    server_name: Optional[str] = None
    server_version: Optional[str] = None
    capabilities: Dict = dataclasses.field(default_factory=dict)
    tools: List[Dict] = dataclasses.field(default_factory=list)
    resources: List[Dict] = dataclasses.field(default_factory=list)
    prompts: List[Dict] = dataclasses.field(default_factory=list)
    sse_enabled: bool = False
    ws_enabled: bool = False
    auth_required: bool = False
    response_time_ms: Optional[float] = None
    framework: Optional[str] = None
    server_header: Optional[str] = None
    powered_by: Optional[str] = None
    error: Optional[str] = None
    raw_headers: Dict = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict:
        return dataclasses.asdict(self)


class MCPProber:
    """
    Sonde un endpoint pour détecter et interroger un serveur MCP.

    Protocole JSON-RPC 2.0 (spec MCP 2024-11-05) :
        1. POST initialize   → obtenir protocolVersion + capabilities + serverInfo
        2. POST initialized  → notification (pas de réponse attendue)
        3. POST tools/list   → liste des outils déclarés
        4. POST resources/list → liste des ressources
        5. POST prompts/list → liste des prompts
    """

    JSONRPC = "2.0"
    TIMEOUT_CONNECT = 5
    TIMEOUT_READ = 10

    def __init__(self, session: "aiohttp.ClientSession", timeout_s: float = 10):
        self._session = session
        self._timeout = aiohttp.ClientTimeout(
            connect=self.TIMEOUT_CONNECT,
            total=timeout_s,
        )

    # ── JSON-RPC helpers ────────────────────────────────────────────────────

    @staticmethod
    def _rpc_request(method: str, params: Any = None, req_id: int = 1) -> Dict:
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        return msg

    @staticmethod
    def _rpc_notification(method: str, params: Any = None) -> Dict:
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        return msg

    def _init_payload(self) -> Dict:
        return self._rpc_request(
            "initialize",
            {
                "protocolVersion": CorpusConstants.MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "clientInfo": CorpusConstants.CLIENT_INFO,
            },
        )

    # ── Transport HTTP ───────────────────────────────────────────────────────

    async def _post_rpc(self, url: str, payload: Dict) -> Optional[Dict]:
        try:
            async with self._session.post(
                url,
                json=payload,
                timeout=self._timeout,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": f"MCP-ECHO/{CorpusConstants.VERSION}",
                },
            ) as resp:
                if resp.status in (200, 201, 202):
                    try:
                        return await resp.json(content_type=None)
                    except Exception:
                        text = await resp.text()
                        return json.loads(text) if text.strip().startswith("{") else None
                return None
        except Exception as exc:
            logger.debug("POST RPC %s : %s", url, exc)
            return None

    async def _get_headers(self, url: str) -> Dict:
        """Récupère les en-têtes HTTP d'un endpoint."""
        try:
            async with self._session.head(
                url, timeout=self._timeout,
                headers={"User-Agent": f"MCP-ECHO/{CorpusConstants.VERSION}"},
                allow_redirects=True,
            ) as resp:
                return dict(resp.headers)
        except Exception:
            try:
                async with self._session.get(
                    url, timeout=aiohttp.ClientTimeout(total=5),
                    headers={"User-Agent": f"MCP-ECHO/{CorpusConstants.VERSION}"},
                ) as resp:
                    return dict(resp.headers)
            except Exception:
                return {}

    async def _check_discovery(self, base_url: str) -> Tuple[bool, Dict]:
        """Vérifie /.well-known/mcp"""
        url = base_url.rstrip("/") + "/.well-known/mcp"
        try:
            async with self._session.get(url, timeout=self._timeout) as resp:
                if resp.status == 200:
                    try:
                        data = await resp.json(content_type=None)
                        return True, data or {}
                    except Exception:
                        return True, {}
        except Exception:
            pass
        return False, {}

    async def _check_sse(self, base_url: str) -> bool:
        """Vérifie si SSE est disponible."""
        for ep in CorpusConstants.SSE_ENDPOINTS:
            url = base_url.rstrip("/") + ep
            try:
                async with self._session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(connect=3, total=5),
                    headers={"Accept": "text/event-stream"},
                ) as resp:
                    ct = resp.headers.get("Content-Type", "")
                    if resp.status == 200 and "text/event-stream" in ct:
                        return True
            except Exception:
                pass
        return False

    async def _check_ws(self, base_url: str) -> bool:
        """Vérifie si WebSocket MCP est disponible."""
        if not HAS_WEBSOCKETS:
            return False

        import websockets as ws_lib

        ws_base = base_url.replace("http://", "ws://").replace("https://", "wss://")
        for ep in CorpusConstants.WS_ENDPOINTS:
            url = ws_base.rstrip("/") + ep
            try:
                async with ws_lib.connect(url, open_timeout=3) as ws:
                    init_msg = json.dumps(self._init_payload())
                    await asyncio.wait_for(ws.send(init_msg), timeout=3)
                    raw = await asyncio.wait_for(ws.recv(), timeout=5)
                    data = json.loads(raw)
                    if "result" in data and "protocolVersion" in data.get("result", {}):
                        return True
            except Exception:
                pass
        return False

    @staticmethod
    def _fingerprint(headers: Dict) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Détecte le framework serveur depuis les en-têtes HTTP.
        Retourne (framework, server_header, powered_by).
        """
        server_hdr = headers.get("Server", headers.get("server", ""))
        powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        combined = (server_hdr + " " + powered_by).lower()

        framework = None
        for fw, signals in CorpusConstants.SERVER_FRAMEWORKS.items():
            if any(s in combined for s in signals):
                framework = fw
                break

        return framework or None, server_hdr or None, powered_by or None

    @staticmethod
    def _has_mcp_signature(text: str) -> bool:
        t = text.lower()
        return any(sig.lower() in t for sig in CorpusConstants.MCP_HTTP_SIGNATURES)

    # ── Sonde principale ────────────────────────────────────────────────────

    async def probe(self, base_url: str) -> MCPProbeResult:
        """
        Sonde complète d'un serveur MCP candidat.
        Tente tous les endpoints et transports, retourne le meilleur résultat.
        """
        result = MCPProbeResult(url=base_url)
        t0 = time.monotonic()

        # 1. En-têtes HTTP (fingerprint)
        headers = await self._get_headers(base_url)
        result.raw_headers = {k: v for k, v in headers.items()}
        result.framework, result.server_header, result.powered_by = self._fingerprint(headers)

        # Détection auth depuis headers
        auth_h = headers.get("WWW-Authenticate", headers.get("www-authenticate", ""))
        result.auth_required = bool(auth_h) or headers.get("X-Auth-Required", "") == "true"

        # 2. Discovery endpoint
        disc_found, disc_data = await self._check_discovery(base_url)
        if disc_found:
            result.detected = True
            result.transport = "discovery"

        # 3. Handshake JSON-RPC 2.0 sur chaque endpoint candidat
        for ep in CorpusConstants.MCP_ENDPOINTS:
            ep_url = base_url.rstrip("/") + ep
            init_resp = await self._post_rpc(ep_url, self._init_payload())

            if init_resp and "result" in init_resp:
                res = init_resp["result"]
                if "protocolVersion" in res:
                    result.detected = True
                    result.transport = "http"
                    result.protocol_version = res.get("protocolVersion")
                    info = res.get("serverInfo", {})
                    result.server_name = info.get("name")
                    result.server_version = info.get("version")
                    result.capabilities = res.get("capabilities", {})

                    # Notification initialized
                    await self._post_rpc(
                        ep_url,
                        self._rpc_notification("notifications/initialized"),
                    )

                    # tools/list
                    t_resp = await self._post_rpc(
                        ep_url, self._rpc_request("tools/list", {}, req_id=2)
                    )
                    if t_resp and "result" in t_resp:
                        result.tools = t_resp["result"].get("tools", [])

                    # resources/list
                    r_resp = await self._post_rpc(
                        ep_url, self._rpc_request("resources/list", {}, req_id=3)
                    )
                    if r_resp and "result" in r_resp:
                        result.resources = r_resp["result"].get("resources", [])

                    # prompts/list
                    p_resp = await self._post_rpc(
                        ep_url, self._rpc_request("prompts/list", {}, req_id=4)
                    )
                    if p_resp and "result" in p_resp:
                        result.prompts = p_resp["result"].get("prompts", [])

                    break  # endpoint trouvé, on arrête l'itération

            # Fallback signature textuelle si pas de JSON-RPC valide
            elif not result.detected:
                try:
                    async with self._session.get(
                        ep_url,
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        body = await resp.text()
                        if resp.status == 200 and self._has_mcp_signature(body):
                            result.detected = True
                            result.transport = "http-signature"
                except Exception:
                    pass

        # 4. SSE
        if result.detected or disc_found:
            result.sse_enabled = await self._check_sse(base_url)

        # 5. WebSocket
        if result.detected or disc_found:
            result.ws_enabled = await self._check_ws(base_url)
            if result.ws_enabled and result.transport == "unknown":
                result.transport = "ws"

        result.response_time_ms = round((time.monotonic() - t0) * 1000, 1)
        return result


# ==============================================================================
# CALCUL DELTA — v3 : multi-facteurs pondérés
# ==============================================================================

class DeltaCalculator:
    """
    Calcule le Δ d'un serveur MCP sur [0.05 ; 0.95].

    Facteurs (tous normalisés indépendamment) :
      - Protocol version manquante / obsolète  → pénalité
      - Auth absente                           → pénalité
      - Nombre d'outils                        → bonus
      - Nombre de ressources                   → bonus
      - Nombre de prompts                      → bonus
      - SSE activé                             → bonus
      - WebSocket activé                       → bonus
      - Port fantôme connu                     → malus
      - Temps de réponse (ms)                  → pénalité si lent
      - Ports fantômes détectés                → pénalité pondérée sévérité
      - Hash URL (bruit déterministe)          → ±0.05
    """

    LATEST_PROTO = CorpusConstants.MCP_PROTOCOL_VERSION

    def calculate(self, probe: MCPProbeResult, ghost_count: int = 0,
                  ghost_severity_sum: int = 0) -> float:
        score = 0.50  # base neutre

        # Protocole
        if not probe.detected:
            score += 0.20
        elif probe.protocol_version:
            if probe.protocol_version < self.LATEST_PROTO:
                score += 0.08   # version ancienne → moins stable
        else:
            score += 0.05

        # Auth
        if not probe.auth_required and probe.detected:
            score -= 0.06   # accessible sans auth → plus "propre"

        # Richesse du serveur
        tools_n = len(probe.tools)
        if tools_n == 0:
            score += 0.04
        elif tools_n >= 20:
            score -= 0.06
        elif tools_n >= 5:
            score -= 0.03

        resources_n = len(probe.resources)
        score -= min(resources_n * 0.01, 0.05)

        prompts_n = len(probe.prompts)
        score -= min(prompts_n * 0.01, 0.04)

        # Transports supplémentaires
        if probe.sse_enabled:
            score -= 0.04
        if probe.ws_enabled:
            score -= 0.03

        # Temps de réponse
        if probe.response_time_ms is not None:
            if probe.response_time_ms > 5000:
                score += 0.08
            elif probe.response_time_ms > 2000:
                score += 0.04
            elif probe.response_time_ms < 200:
                score -= 0.03

        # Ports fantômes
        if ghost_count > 0:
            score += min(ghost_severity_sum * 0.03, 0.20)

        # Bruit déterministe (±0.05)
        url_hash = int(hashlib.sha256(probe.url.encode()).hexdigest(), 16)
        noise = ((url_hash % 1000) / 1000.0 - 0.5) * 0.10
        score += noise

        return round(max(0.05, min(0.95, score)), 3)

    @staticmethod
    def label(delta: float) -> str:
        if delta < 0.25:   return "STABLE"
        if delta < 0.40:   return "CALME"
        if delta < 0.55:   return "TROUBLE"
        if delta < 0.70:   return "TURBULENT"
        if delta < 0.85:   return "CRITIQUE"
        return "OMEGA"

    @staticmethod
    def color_tk(delta: float) -> str:
        if delta < 0.40:   return CorpusConstants.C64['fg']         # vert
        if delta < 0.65:   return CorpusConstants.C64['fg_yellow']  # jaune
        return CorpusConstants.C64['fg_red']                         # rouge


# ==============================================================================
# CORPUS DES PORTS FANTÔMES — v3 : logique étendue
# ==============================================================================

class GhostPortCorpus:
    """Détecte les ports fantômes du Corpus Vauvillensis depuis une IP + probe."""

    @staticmethod
    def _ip_to_ints(ip: str) -> Tuple[int, int, int, int]:
        try:
            parts = [int(x) for x in ip.split(".")]
            if len(parts) == 4 and all(0 <= p <= 255 for p in parts):
                return tuple(parts)  # type: ignore[return-value]
        except (ValueError, AttributeError):
            pass
        return (0, 0, 0, 0)

    def detect(self, ip: str, probe: MCPProbeResult) -> List[Dict]:
        if not ip:
            return []

        a, b, c, d = self._ip_to_ints(ip)
        total = a + b + c + d
        xor4 = a ^ b ^ c ^ d
        url_hash = int(hashlib.sha256(ip.encode()).hexdigest(), 16)

        results = []

        for port, meta in CorpusConstants.GHOST_PORTS.items():
            # Condition de résonance : combinaison hash + propriétés numériques
            port_hash = int(
                hashlib.sha256(f"{ip}:{port}:{probe.url}".encode()).hexdigest(), 16
            )
            threshold = 13  # ~8% de chance de base

            # Modificateurs selon les propriétés de l'IP
            if port == 0     and xor4 == 0:             threshold = 1    # Vide : IP palindrome
            if port == 3303  and total % 7 == 0:         threshold = 5
            if port == 7071  and xor4 == 0:              threshold = 4
            if port == 9877  and d % 2 == 0:             threshold = 6
            if port == 11223 and a == d:                  threshold = 3
            if port == 11440 and xor4 in (144, 72, 36):  threshold = 4
            if port == 13013 and total % 13 == 0:        threshold = 3
            if port == 14225 and d % 5 == 0:             threshold = 6
            if port == 14400 and xor4 == 144:            threshold = 2
            if port == 19999 and total > 700:             threshold = 6
            if port == 22222 and total % 22 == 0:        threshold = 4
            if port == 31337 and b == c:                  threshold = 5
            if port == 44444 and all(o > 44 for o in (a,b,c,d)): threshold = 3
            if port == 55555 and total % 5 == 0:         threshold = 2
            if port == 65535 and d == 255:                threshold = 1
            if port == 8008  and a == b:                  threshold = 5
            if port == 33333 and total % 3 == 0:         threshold = 5

            if port_hash % 100 < threshold * 6:
                sig = f"Ωmcp•{port}•{hex(url_hash)[:10]}•{xor4}Ω"
                results.append({
                    "port": port,
                    "name": meta["name"],
                    "desc": meta["desc"],
                    "severity": meta["severity"],
                    "signature": sig,
                    "weight": CorpusConstants.SEVERITY_WEIGHTS[meta["severity"]],
                })

        return sorted(results, key=lambda x: -x["weight"])


# ==============================================================================
# SCANNER PRINCIPAL v3
# ==============================================================================

@dataclasses.dataclass
class ScanResult:
    """Résultat complet pour un hôte."""
    ip: str
    url: str
    timestamp: str
    probe: MCPProbeResult
    delta: float
    delta_label: str
    ghost_ports: List[Dict]
    shodan_data: Dict = dataclasses.field(default_factory=dict)
    status: str = "ok"   # ok | skipped | error

    def to_dict(self) -> Dict:
        d = dataclasses.asdict(self)
        d["probe"] = self.probe.to_dict()
        return d

    def to_csv_row(self) -> List:
        return [
            self.ip, self.url, self.timestamp,
            self.probe.detected, self.probe.transport,
            self.probe.protocol_version or "",
            self.probe.server_name or "",
            len(self.probe.tools), len(self.probe.resources), len(self.probe.prompts),
            self.probe.sse_enabled, self.probe.ws_enabled,
            self.probe.auth_required,
            self.probe.framework or "",
            self.probe.response_time_ms or "",
            self.delta, self.delta_label,
            len(self.ghost_ports),
            self.status,
        ]

    CSV_HEADERS = [
        "ip", "url", "timestamp", "mcp_detected", "transport",
        "protocol_version", "server_name",
        "tools_count", "resources_count", "prompts_count",
        "sse", "websocket", "auth_required", "framework", "response_time_ms",
        "delta", "delta_label", "ghost_ports_count", "status",
    ]


class MCPScannerV3:
    """Orchestre les scans MCP avec concurrence et collecte des résultats."""

    def __init__(
        self,
        shodan_api_key: Optional[str] = None,
        concurrency: int = 10,
        timeout: float = 12.0,
        cache_ttl: int = 3600,
    ):
        self.shodan_api_key = shodan_api_key
        self.concurrency = concurrency
        self.timeout = timeout

        self.cache = CacheManager(ttl=cache_ttl)
        self.shodan: Optional[ShodanClient] = (
            ShodanClient(shodan_api_key, self.cache) if shodan_api_key else None
        )
        self.delta_calc = DeltaCalculator()
        self.ghost_corpus = GhostPortCorpus()

        self.results: List[ScanResult] = []
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._cancel_event = asyncio.Event()

        # Callbacks pour GUI (progress, log)
        self.on_result: Optional[Any] = None  # callable(ScanResult)
        self.on_log: Optional[Any] = None     # callable(str, tag)
        self.on_progress: Optional[Any] = None  # callable(done, total)

    def _log(self, msg: str, tag: str = "info"):
        if self.on_log:
            self.on_log(msg, tag)
        else:
            level = {"info": logger.info, "success": logger.info,
                     "warning": logger.warning, "error": logger.error,
                     "delta": logger.info}.get(tag, logger.info)
            level(msg)

    def cancel(self):
        self._cancel_event.set()

    @staticmethod
    def _normalize_url(target: str) -> str:
        if not target.startswith(("http://", "https://", "ws://", "wss://")):
            target = "http://" + target
        return target.rstrip("/")

    @staticmethod
    def _extract_ip(target: str) -> str:
        try:
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname or target
            # Retourne l'IP si c'est une IP, sinon le hostname
            return host
        except Exception:
            return target

    async def _scan_one(
        self, target: str, index: int, total: int,
        session: "aiohttp.ClientSession",
        shodan_data: Dict,
    ) -> ScanResult:
        url = self._normalize_url(target)
        ip = self._extract_ip(url)

        self._log(f"[{index}/{total}] → {url}", "info")

        probe = MCPProbeResult(url=url, error="aiohttp non disponible")

        if HAS_AIOHTTP:
            prober = MCPProber(session, timeout_s=self.timeout)
            probe = await prober.probe(url)

        # Ghosts
        ghosts = self.ghost_corpus.detect(ip, probe)
        severity_sum = sum(g["weight"] for g in ghosts)

        # Delta
        delta = self.delta_calc.calculate(probe, len(ghosts), severity_sum)
        dlabel = self.delta_calc.label(delta)

        result = ScanResult(
            ip=ip,
            url=url,
            timestamp=datetime.now(timezone.utc).isoformat(),
            probe=probe,
            delta=delta,
            delta_label=dlabel,
            ghost_ports=ghosts,
            shodan_data=shodan_data,
        )

        # Logs détaillés
        status_tag = "success" if probe.detected else "warning"
        if probe.detected:
            self._log(
                f"    ✅ MCP DÉTECTÉ | transport={probe.transport} "
                f"| tools={len(probe.tools)} | Δ={delta} [{dlabel}]",
                status_tag,
            )
            if probe.server_name:
                self._log(f"    Serveur : {probe.server_name} v{probe.server_version}", "info")
            if probe.protocol_version:
                self._log(f"    Protocole : {probe.protocol_version}", "info")
            if probe.sse_enabled:
                self._log("    SSE : ✓", "success")
            if probe.ws_enabled:
                self._log("    WebSocket : ✓", "success")
            if probe.framework:
                self._log(f"    Framework : {probe.framework}", "info")
        else:
            self._log(f"    ∿ Pas de MCP | Δ={delta} [{dlabel}]", "warning")

        for g in ghosts:
            self._log(
                f"    ◈ Port {g['port']} [{g['severity']}] : {g['name']} — {g['desc']}",
                "delta",
            )

        if probe.error:
            self._log(f"    ⚠ {probe.error}", "warning")

        return result

    async def scan_targets(self, targets: List[str], shodan_lookup: bool = False) -> List[ScanResult]:
        """Scan concurrent de la liste de cibles."""
        if not HAS_AIOHTTP:
            self._log("⚠ aiohttp non installé — scan HTTP désactivé", "error")
            return []

        self._cancel_event.clear()
        self.results.clear()
        self._semaphore = asyncio.Semaphore(self.concurrency)
        total = len(targets)
        done = 0

        conn = aiohttp.TCPConnector(limit=self.concurrency * 2, ssl=False)
        async with aiohttp.ClientSession(connector=conn) as session:

            async def worker(target: str, idx: int) -> Optional[ScanResult]:
                nonlocal done
                if self._cancel_event.is_set():
                    return None
                async with self._semaphore:
                    # Shodan host info
                    sh_data = {}
                    if shodan_lookup and self.shodan:
                        ip = self._extract_ip(self._normalize_url(target))
                        sh_data = self.shodan.host_info(ip)

                    try:
                        result = await self._scan_one(
                            target, idx, total, session, sh_data
                        )
                    except Exception as exc:
                        logger.exception("Erreur inattendue sur %s", target)
                        probe = MCPProbeResult(url=target, error=str(exc))
                        result = ScanResult(
                            ip=target, url=target,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            probe=probe, delta=0.5, delta_label="TROUBLE",
                            ghost_ports=[], status="error",
                        )
                    finally:
                        done += 1
                        if self.on_progress:
                            self.on_progress(done, total)

                    self.results.append(result)
                    if self.on_result:
                        self.on_result(result)
                    return result

            tasks = [worker(t, i + 1) for i, t in enumerate(targets)]
            await asyncio.gather(*tasks)

        return self.results

    def discover_via_shodan(self, max_results: int = 100) -> List[str]:
        """Retourne une liste d'URLs à partir des recherches Shodan."""
        if not self.shodan:
            self._log("Clé Shodan API non configurée", "error")
            return []

        urls: List[str] = []
        per_query = max(1, max_results // len(CorpusConstants.SHODAN_FILTERS))

        for fq in CorpusConstants.SHODAN_FILTERS:
            self._log(f"Shodan: {fq}", "info")
            matches = self.shodan.search(fq, limit=per_query)
            for m in matches:
                ip = m.get("ip_str", "")
                port = m.get("port", 8000)
                scheme = "https" if port in (443, 8443) else "http"
                url = f"{scheme}://{ip}:{port}"
                if url not in urls:
                    urls.append(url)

        self._log(f"Shodan : {len(urls)} cibles découvertes", "success")
        return urls


# ==============================================================================
# EXPORT
# ==============================================================================

def export_results(results: List[ScanResult], output_path: str, fmt: str = "json"):
    fmt = fmt.lower()
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        if fmt == "json":
            meta = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "tool": f"MCP-ECHO v{CorpusConstants.VERSION}",
                "count": len(results),
            }
            payload = {"meta": meta, "results": [r.to_dict() for r in results]}
            json.dump(payload, f, indent=2, default=str)

        elif fmt == "ndjson":
            for r in results:
                f.write(json.dumps(r.to_dict(), default=str) + "\n")

        elif fmt == "csv":
            writer = csv.writer(f)
            writer.writerow(ScanResult.CSV_HEADERS)
            for r in results:
                writer.writerow(r.to_csv_row())

        else:
            raise ValueError(f"Format inconnu : {fmt}")

    print(f"[✓] Export {fmt.upper()} → {output_path}  ({len(results)} entrées)")


# ==============================================================================
# CARTE C64 INTERACTIVE — v3 : drag + clic + détails
# ==============================================================================

if HAS_TK:

    class C64InteractiveMap(tk.Canvas):
        """Carte mondiale interactive style C64 avec drag, zoom et clic."""

        def __init__(self, parent, on_select=None, **kwargs):
            super().__init__(parent, bg=CorpusConstants.C64['bg'], **kwargs)
            self.servers: List[ScanResult] = []
            self.zoom = 1.0
            self.offset_x = 0.0
            self.offset_y = 0.0
            self._drag_start: Optional[Tuple[int, int]] = None
            self.on_select = on_select  # callback(ScanResult)
            self._server_items: Dict[int, ScanResult] = {}  # canvas item → result

            self._draw_grid()
            self._draw_continents()

            self.bind("<MouseWheel>", self._on_zoom)
            self.bind("<Button-4>",   self._on_zoom)   # Linux scroll up
            self.bind("<Button-5>",   self._on_zoom)   # Linux scroll down
            self.bind("<ButtonPress-1>",   self._on_drag_start)
            self.bind("<B1-Motion>",       self._on_drag_move)
            self.bind("<ButtonRelease-1>", self._on_drag_end)
            self.bind("<Configure>",       self._on_resize)

        # ── Coordonnées ────────────────────────────────────────────────────

        def _geo_to_canvas(self, lat: float, lon: float) -> Tuple[float, float]:
            w = self.winfo_width() or int(self.cget("width") or 600)
            h = self.winfo_height() or int(self.cget("height") or 400)
            x = (lon + 180) / 360 * w * self.zoom + self.offset_x
            y = (90 - lat)  / 180 * h * self.zoom + self.offset_y
            return x, y

        # ── Fond ───────────────────────────────────────────────────────────

        def _draw_grid(self):
            self.delete("grid")
            w = int(self.cget("width") or 600)
            h = int(self.cget("height") or 400)
            for x in range(0, w, 30):
                self.create_line(x, 0, x, h, fill=CorpusConstants.C64['grid'],
                                 tags="grid", stipple="gray25")
            for y in range(0, h, 20):
                self.create_line(0, y, w, y, fill=CorpusConstants.C64['grid'],
                                 tags="grid", stipple="gray25")

        def _draw_continents(self):
            """Contours simplifiés des masses continentales (style C64)."""
            self.delete("continent")
            polys = [
                # Amérique du Nord (approximation grossière)
                [(-170,70),(-60,70),(-60,50),(-80,25),(-110,20),(-120,30),(-170,55)],
                # Europe
                [(0,35),(30,35),(30,60),(15,65),(0,60)],
                # Afrique
                [(-20,35),(55,35),(55,-35),(-20,-35)],
                # Asie
                [(30,10),(145,10),(145,75),(30,75)],
                # Australie
                [(113,-45),(155,-45),(155,-10),(113,-10)],
            ]
            for poly in polys:
                pts = []
                for (lon, lat) in poly:
                    x, y = self._geo_to_canvas(lat, lon)
                    pts.extend([x, y])
                if len(pts) >= 4:
                    self.create_polygon(
                        *pts, fill="", outline=CorpusConstants.C64['border'],
                        width=1, tags="continent", stipple="gray25"
                    )

        # ── Serveurs ────────────────────────────────────────────────────────

        def update_servers(self, servers: List[ScanResult]):
            self.servers = servers
            self.redraw()

        def redraw(self):
            self.delete("server")
            self._server_items.clear()
            self._draw_grid()
            self._draw_continents()

            for srv in self.servers:
                if not srv.probe.detected:
                    continue
                # Coordonnées : depuis Shodan ou hash déterministe
                sh = srv.shodan_data
                lat = sh.get("latitude") or sh.get("location", {}).get("latitude")
                lon = sh.get("longitude") or sh.get("location", {}).get("longitude")

                if lat is None or lon is None:
                    # Fallback déterministe (pas de random!)
                    h = int(hashlib.md5(srv.ip.encode()).hexdigest(), 16)
                    lat = ((h >> 8) % 120) - 60.0
                    lon = ((h & 0xFFFFFF) % 360) - 180.0

                x, y = self._geo_to_canvas(float(lat), float(lon))
                color = DeltaCalculator.color_tk(srv.delta)
                r = max(3, int(6 * self.zoom))

                oval = self.create_oval(
                    x - r, y - r, x + r, y + r,
                    fill=color, outline=CorpusConstants.C64['fg_white'],
                    width=1, tags="server",
                )
                self._server_items[oval] = srv

                if self.zoom > 0.8:
                    self.create_text(
                        x + r + 4, y,
                        text=srv.ip, fill=CorpusConstants.C64['fg_cyan'],
                        font=("Courier", 7), anchor=tk.W, tags="server",
                    )
                self.tag_bind(oval, "<Button-1>", lambda e, s=srv: self._select(s))

        def _select(self, srv: ScanResult):
            if self.on_select:
                self.on_select(srv)

        # ── Interactions ────────────────────────────────────────────────────

        def _on_zoom(self, event):
            factor = 1.12
            if hasattr(event, "delta"):
                if event.delta < 0:
                    factor = 1 / factor
            elif event.num == 5:
                factor = 1 / factor

            cx = event.x
            cy = event.y
            self.offset_x = cx - (cx - self.offset_x) * factor
            self.offset_y = cy - (cy - self.offset_y) * factor
            self.zoom = max(0.4, min(self.zoom * factor, 5.0))
            self.redraw()

        def _on_drag_start(self, event):
            # Ne pas déclencher si on clique sur un serveur
            items = self.find_overlapping(event.x-2, event.y-2, event.x+2, event.y+2)
            if any(i in self._server_items for i in items):
                self._drag_start = None
            else:
                self._drag_start = (event.x, event.y)

        def _on_drag_move(self, event):
            if self._drag_start is None:
                return
            dx = event.x - self._drag_start[0]
            dy = event.y - self._drag_start[1]
            self.offset_x += dx
            self.offset_y += dy
            self._drag_start = (event.x, event.y)
            self.redraw()

        def _on_drag_end(self, _event):
            self._drag_start = None

        def _on_resize(self, _event):
            self.after_idle(self.redraw)

    # ==========================================================================
    # PANNEAU DE DÉTAILS SERVEUR
    # ==========================================================================

    class ServerDetailsPanel(tk.Frame):
        """Affiche les détails d'un serveur MCP sélectionné."""

        def __init__(self, parent, **kwargs):
            super().__init__(parent, bg=CorpusConstants.C64['bg'], **kwargs)
            self._build()

        def _build(self):
            tk.Label(
                self, text="[ DÉTAILS SERVEUR ]",
                bg=CorpusConstants.C64['bg'],
                fg=CorpusConstants.C64['fg_yellow'],
                font=("Courier New", 9, "bold"),
            ).pack(anchor=tk.W, padx=4, pady=(4, 2))

            self._text = tk.Text(
                self, wrap=tk.WORD,
                bg=CorpusConstants.C64['bg_dark'],
                fg=CorpusConstants.C64['fg'],
                font=("Courier New", 8),
                relief=tk.SUNKEN, bd=1,
                state=tk.DISABLED,
            )
            self._text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

            for tag, fg in [
                ("key",   CorpusConstants.C64['fg_yellow']),
                ("val",   CorpusConstants.C64['fg']),
                ("ok",    CorpusConstants.C64['fg']),
                ("warn",  CorpusConstants.C64['fg_yellow']),
                ("crit",  CorpusConstants.C64['fg_red']),
                ("delta", CorpusConstants.C64['fg_magenta']),
                ("ghost", CorpusConstants.C64['fg_orange']),
            ]:
                self._text.tag_configure(tag, foreground=fg)

        def _w(self, text: str, tag: str = "val"):
            self._text.insert(tk.END, text, tag)

        def show(self, srv: ScanResult):
            self._text.configure(state=tk.NORMAL)
            self._text.delete(1.0, tk.END)

            p = srv.probe
            self._w(f"IP         : ", "key"); self._w(f"{srv.ip}\n")
            self._w(f"URL        : ", "key"); self._w(f"{srv.url}\n")
            self._w(f"Détecté    : ", "key")
            self._w("OUI\n" if p.detected else "NON\n", "ok" if p.detected else "warn")
            self._w(f"Transport  : ", "key"); self._w(f"{p.transport}\n")
            if p.protocol_version:
                self._w(f"Protocole  : ", "key"); self._w(f"{p.protocol_version}\n")
            if p.server_name:
                self._w(f"Serveur    : ", "key")
                self._w(f"{p.server_name} v{p.server_version or '?'}\n")
            self._w(f"Framework  : ", "key"); self._w(f"{p.framework or 'N/A'}\n")
            self._w(f"Auth req.  : ", "key")
            self._w("OUI\n" if p.auth_required else "NON\n",
                    "warn" if p.auth_required else "ok")
            self._w(f"SSE        : ", "key")
            self._w("✓\n" if p.sse_enabled else "–\n",
                    "ok" if p.sse_enabled else "val")
            self._w(f"WebSocket  : ", "key")
            self._w("✓\n" if p.ws_enabled else "–\n",
                    "ok" if p.ws_enabled else "val")
            self._w(f"Latence    : ", "key")
            self._w(f"{p.response_time_ms or 'N/A'} ms\n")

            # Delta
            self._w(f"\nΔ = {srv.delta} [{srv.delta_label}]\n", "delta")

            # Outils
            self._w(f"\nOutils ({len(p.tools)}) :\n", "key")
            for t in p.tools[:10]:
                name = t.get("name", "?") if isinstance(t, dict) else str(t)
                self._w(f"  · {name}\n")
            if len(p.tools) > 10:
                self._w(f"  … +{len(p.tools)-10} autres\n", "warn")

            # Ressources
            if p.resources:
                self._w(f"\nRessources ({len(p.resources)}) :\n", "key")
                for r in p.resources[:5]:
                    uri = r.get("uri", "?") if isinstance(r, dict) else str(r)
                    self._w(f"  · {uri}\n")

            # Prompts
            if p.prompts:
                self._w(f"\nPrompts ({len(p.prompts)}) :\n", "key")
                for pr in p.prompts[:5]:
                    nm = pr.get("name", "?") if isinstance(pr, dict) else str(pr)
                    self._w(f"  · {nm}\n")

            # Ports fantômes
            if srv.ghost_ports:
                self._w(f"\nPorts fantômes ({len(srv.ghost_ports)}) :\n", "ghost")
                for g in srv.ghost_ports:
                    self._w(f"  ◈ {g['port']} [{g['severity']}] {g['name']}\n", "ghost")

            # Erreur
            if p.error:
                self._w(f"\nErreur : {p.error}\n", "crit")

            self._text.configure(state=tk.DISABLED)

        def clear(self):
            self._text.configure(state=tk.NORMAL)
            self._text.delete(1.0, tk.END)
            self._text.configure(state=tk.DISABLED)

    # ==========================================================================
    # GUI v3
    # ==========================================================================

    class MCPECHOGUI:
        """Interface graphique MCP-ECHO v3 — complète."""

        def __init__(self, root: tk.Tk):
            self.root = root
            self.root.title(f"MCP-ECHO v{CorpusConstants.VERSION} — Model Context Protocol Mapper")
            self.root.geometry("1400x860")
            self.root.configure(bg=CorpusConstants.C64['bg'])
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)

            self.scanner = MCPScannerV3()
            self.scanner.on_log = self._gui_log
            self.scanner.on_result = self._gui_on_result
            self.scanner.on_progress = self._gui_progress

            self._scan_thread: Optional[threading.Thread] = None
            self._batch_file: Optional[str] = None
            self._results: List[ScanResult] = []

            self._build_ui()

        # ── Construction UI ────────────────────────────────────────────────

        def _build_ui(self):
            C = CorpusConstants.C64

            # Header
            hdr = tk.Frame(self.root, bg=C['bg'])
            hdr.pack(fill=tk.X, padx=8, pady=(6, 0))
            logo = (
                " MCP─ECHO v3.0 ══ Model Context Protocol Temporal Mapper\n"
                " Corpus Vauvillensis ══ Collectif des Veilleurs ══ JSON-RPC 2.0"
            )
            tk.Label(hdr, text=logo, fg=C['fg_cyan'], bg=C['bg'],
                     font=("Courier New", 9, "bold"), justify=tk.LEFT).pack(anchor=tk.W)

            # Panneau de contrôle
            ctrl = tk.LabelFrame(
                self.root, text=" [ CONTRÔLE ] ",
                bg=C['bg'], fg=C['fg_white'],
                font=("Courier New", 9, "bold"),
            )
            ctrl.pack(fill=tk.X, padx=8, pady=4)
            self._build_controls(ctrl)

            # Barre de progression
            prog_frame = tk.Frame(self.root, bg=C['bg'])
            prog_frame.pack(fill=tk.X, padx=8, pady=2)
            self._progress_var = tk.DoubleVar(value=0.0)
            self._progress_label = tk.Label(
                prog_frame, text="IDLE", bg=C['bg'], fg=C['fg_grey'],
                font=("Courier", 8),
            )
            self._progress_label.pack(side=tk.LEFT, padx=4)
            self._progress_bar = ttk.Progressbar(
                prog_frame, variable=self._progress_var,
                maximum=100, length=300,
            )
            self._progress_bar.pack(side=tk.LEFT, padx=4)

            # Zone principale : terminal | carte | détails
            main = tk.Frame(self.root, bg=C['bg'])
            main.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

            # Terminal (gauche)
            term_frame = tk.LabelFrame(main, text=" [ TERMINAL ] ",
                                       bg=C['bg'], fg=C['fg_white'],
                                       font=("Courier New", 8, "bold"),
                                       width=420)
            term_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            self._terminal = scrolledtext.ScrolledText(
                term_frame, wrap=tk.WORD,
                font=("Courier New", 9),
                bg=C['bg_dark'], fg=C['fg'],
                insertbackground=C['fg_white'],
                relief=tk.SUNKEN,
            )
            self._terminal.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
            for tag, fg in [
                ("info",    C['fg_cyan']),
                ("success", C['fg']),
                ("warning", C['fg_yellow']),
                ("error",   C['fg_red']),
                ("delta",   C['fg_magenta']),
            ]:
                self._terminal.tag_configure(tag, foreground=fg)

            # Carte (centre)
            map_frame = tk.LabelFrame(main, text=" [ CARTE ] ",
                                      bg=C['bg'], fg=C['fg_white'],
                                      font=("Courier New", 8, "bold"),
                                      width=500)
            map_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
            self._map = C64InteractiveMap(
                map_frame, on_select=self._on_server_select,
                width=480, height=380,
            )
            self._map.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
            tk.Label(
                map_frame,
                text="▲ Δ<0.4  ● Δ<0.65  ● Δ>0.65  |  scroll=zoom  drag=déplacer",
                bg=C['bg'], fg=C['fg_grey'], font=("Courier", 7),
            ).pack(pady=2)

            # Détails (droite)
            det_frame = tk.LabelFrame(main, text=" [ SERVEUR ] ",
                                      bg=C['bg'], fg=C['fg_white'],
                                      font=("Courier New", 8, "bold"),
                                      width=300)
            det_frame.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 0))
            self._details = ServerDetailsPanel(det_frame)
            self._details.pack(fill=tk.BOTH, expand=True)

            # Status bar
            self._status = tk.Label(
                self.root,
                text=f"READY.  MCP-ECHO v{CorpusConstants.VERSION}  |  "
                     f"aiohttp={'OK' if HAS_AIOHTTP else 'MANQUANT'}  "
                     f"websockets={'OK' if HAS_WEBSOCKETS else 'MANQUANT'}",
                bg=C['bg_dark'], fg=C['fg'],
                font=("Courier", 8), anchor=tk.W,
            )
            self._status.pack(fill=tk.X, side=tk.BOTTOM, padx=8, pady=2)

        def _build_controls(self, parent):
            C = CorpusConstants.C64

            def lbl(text, row, col):
                tk.Label(parent, text=text, bg=C['bg'], fg=C['fg_yellow'],
                         font=("Courier", 9)).grid(row=row, column=col,
                                                   sticky=tk.W, padx=6, pady=2)

            lbl("Shodan API :", 0, 0)
            self._shodan_entry = tk.Entry(parent, width=36, bg=C['bg_dark'],
                                          fg=C['fg'], show="*", font=("Courier", 9))
            self._shodan_entry.grid(row=0, column=1, sticky=tk.W, padx=4, pady=2)

            lbl("Cible URL  :", 1, 0)
            self._target_entry = tk.Entry(parent, width=36, bg=C['bg_dark'],
                                          fg=C['fg_cyan'], font=("Courier", 9))
            self._target_entry.grid(row=1, column=1, sticky=tk.W, padx=4, pady=2)
            self._target_entry.insert(0, "http://localhost:8000")

            lbl("Concurrence:", 2, 0)
            self._concurrency_var = tk.StringVar(value="8")
            tk.Spinbox(parent, from_=1, to=50, width=5,
                       textvariable=self._concurrency_var,
                       bg=C['bg_dark'], fg=C['fg'], font=("Courier", 9)
                       ).grid(row=2, column=1, sticky=tk.W, padx=4, pady=2)

            lbl("Timeout (s):", 2, 2)
            self._timeout_var = tk.StringVar(value="12")
            tk.Spinbox(parent, from_=2, to=60, width=5,
                       textvariable=self._timeout_var,
                       bg=C['bg_dark'], fg=C['fg'], font=("Courier", 9)
                       ).grid(row=2, column=3, sticky=tk.W, padx=4, pady=2)

            self._shodan_disc = tk.BooleanVar(value=False)
            tk.Checkbutton(parent, text="Shodan Discovery",
                           variable=self._shodan_disc,
                           bg=C['bg'], fg=C['fg'],
                           selectcolor=C['bg_dark'],
                           font=("Courier", 9)
                           ).grid(row=3, column=0, sticky=tk.W, padx=6)

            self._shodan_lookup = tk.BooleanVar(value=False)
            tk.Checkbutton(parent, text="Shodan Lookup IP",
                           variable=self._shodan_lookup,
                           bg=C['bg'], fg=C['fg'],
                           selectcolor=C['bg_dark'],
                           font=("Courier", 9)
                           ).grid(row=3, column=1, sticky=tk.W, padx=6)

            btn_frame = tk.Frame(parent, bg=C['bg'])
            btn_frame.grid(row=4, column=0, columnspan=5, pady=6)

            for text, cmd, bg, fg in [
                ("[ SCAN ]",        self._start_scan,     "#00AA00", "#000000"),
                ("[ ANNULER ]",     self._cancel_scan,    "#AA0000", "#FFFFFF"),
                ("[ BATCH FILE ]",  self._pick_batch,     C['fg_orange'], "#000000"),
                ("[ CLEAR ]",       self._clear,          "#555555", "#FFFFFF"),
                ("[ EXPORT JSON ]", lambda: self._export("json"),  C['border'], "#FFFFFF"),
                ("[ EXPORT CSV ]",  lambda: self._export("csv"),   "#005500", "#FFFFFF"),
            ]:
                tk.Button(btn_frame, text=text, command=cmd,
                          bg=bg, fg=fg,
                          font=("Courier", 9, "bold"),
                          relief=tk.FLAT,
                          ).pack(side=tk.LEFT, padx=4)

        # ── Callbacks ──────────────────────────────────────────────────────

        def _gui_log(self, msg: str, tag: str = "info"):
            def _do():
                self._terminal.insert(tk.END, msg + "\n", tag)
                self._terminal.see(tk.END)
            self.root.after(0, _do)

        def _gui_on_result(self, result: ScanResult):
            self._results.append(result)
            self.root.after(0, lambda: self._map.update_servers(self._results))

        def _gui_progress(self, done: int, total: int):
            pct = done / total * 100 if total else 0
            def _do():
                self._progress_var.set(pct)
                self._progress_label.configure(
                    text=f"{done}/{total}  {pct:.0f}%"
                )
                self._status.configure(
                    text=f"Scan en cours : {done}/{total} ({pct:.0f}%)"
                )
            self.root.after(0, _do)

        def _on_server_select(self, srv: ScanResult):
            self._details.show(srv)

        def _start_scan(self):
            if self._scan_thread and self._scan_thread.is_alive():
                messagebox.showwarning("En cours", "Un scan est déjà en cours.")
                return

            self._results.clear()
            self._map.update_servers([])
            self._details.clear()
            self._clear()
            self._progress_var.set(0)

            targets: List[str] = []
            api_key = self._shodan_entry.get().strip()
            concurrency = int(self._concurrency_var.get() or 8)
            timeout = float(self._timeout_var.get() or 12)

            self.scanner = MCPScannerV3(
                shodan_api_key=api_key or None,
                concurrency=concurrency,
                timeout=timeout,
            )
            self.scanner.on_log = self._gui_log
            self.scanner.on_result = self._gui_on_result
            self.scanner.on_progress = self._gui_progress

            if self._shodan_disc.get():
                if not api_key:
                    messagebox.showerror("Erreur", "Clé Shodan API requise pour la découverte")
                    return
                shodan_targets = self.scanner.discover_via_shodan()
                targets.extend(shodan_targets)

            if self._batch_file and os.path.exists(self._batch_file):
                with open(self._batch_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            targets.append(line)

            t = self._target_entry.get().strip()
            if t and not self._batch_file:
                targets.append(t)

            if not targets:
                messagebox.showerror("Erreur", "Aucune cible définie")
                return

            self._gui_log(
                f"MCP-ECHO v{CorpusConstants.VERSION} — {len(targets)} cible(s) — "
                f"concurrence={concurrency}", "info"
            )

            def _run():
                asyncio.run(
                    self.scanner.scan_targets(
                        targets, shodan_lookup=self._shodan_lookup.get()
                    )
                )
                self.root.after(0, self._scan_done)

            self._scan_thread = threading.Thread(target=_run, daemon=True)
            self._scan_thread.start()
            self._status.configure(text="Scan en cours…")

        def _cancel_scan(self):
            if self.scanner:
                self.scanner.cancel()
            self._status.configure(text="Annulation…")

        def _scan_done(self):
            n = len([r for r in self._results if r.probe.detected])
            self._status.configure(
                text=f"Terminé. {n}/{len(self._results)} serveurs MCP détectés."
            )
            self._progress_var.set(100)
            self._gui_log(
                f"\n[✓] Scan terminé — {n} serveur(s) MCP sur {len(self._results)} cible(s)",
                "success",
            )

        def _pick_batch(self):
            f = filedialog.askopenfilename(
                title="Fichier de cibles",
                filetypes=[("Texte", "*.txt"), ("Tous", "*.*")],
            )
            if f:
                self._batch_file = f
                self._gui_log(f"Batch : {f}", "info")

        def _clear(self):
            self._terminal.delete(1.0, tk.END)

        def _export(self, fmt: str):
            ext = {"json": ".json", "csv": ".csv", "ndjson": ".ndjson"}.get(fmt, ".json")
            path = filedialog.asksaveasfilename(
                defaultextension=ext,
                filetypes=[(fmt.upper(), f"*{ext}"), ("Tous", "*.*")],
            )
            if path and self._results:
                export_results(self._results, path, fmt)
                messagebox.showinfo("Export", f"Export {fmt.upper()} → {path}")

        def _on_close(self):
            if self.scanner:
                self.scanner.cancel()
            self.root.destroy()


# ==============================================================================
# CLI
# ==============================================================================

def run_cli_batch(args):
    """Mode batch CLI avec barre de progression ASCII."""
    targets: List[str] = []

    if args.batch:
        with open(args.batch, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

    if args.target:
        targets.append(args.target)

    if not targets:
        print("[!] Aucune cible.")
        sys.exit(1)

    print(f"\n{'═'*70}")
    print(f"  MCP-ECHO v{CorpusConstants.VERSION} — Corpus Vauvillensis — Collectif des Veilleurs")
    print(f"{'═'*70}")
    print(f"  Cibles     : {len(targets)}")
    print(f"  Concurrence: {args.concurrency}")
    print(f"  Timeout    : {args.timeout}s")
    print(f"  Format     : {args.fmt}")
    print(f"{'═'*70}\n")

    scanner = MCPScannerV3(
        shodan_api_key=getattr(args, "shodan_api", None),
        concurrency=args.concurrency,
        timeout=args.timeout,
    )

    # Log coloré (ANSI)
    ANSI = {
        "info":    "\033[1;36m",
        "success": "\033[1;32m",
        "warning": "\033[1;33m",
        "error":   "\033[1;31m",
        "delta":   "\033[1;35m",
        "reset":   "\033[0m",
    }

    def cli_log(msg, tag="info"):
        c = ANSI.get(tag, "") if sys.stdout.isatty() else ""
        r = ANSI["reset"] if sys.stdout.isatty() else ""
        print(f"{c}{msg}{r}")

    done_count = [0]

    def cli_progress(done, total):
        done_count[0] = done
        if sys.stdout.isatty():
            bar_w = 30
            filled = int(bar_w * done / total) if total else 0
            bar = "█" * filled + "░" * (bar_w - filled)
            print(f"\r  [{bar}] {done}/{total}", end="", flush=True)

    scanner.on_log = cli_log
    scanner.on_progress = cli_progress

    if getattr(args, "shodan_discover", False):
        extra = scanner.discover_via_shodan()
        targets.extend(extra)

    results = asyncio.run(
        scanner.scan_targets(targets, shodan_lookup=getattr(args, "shodan_lookup", False))
    )

    print()  # Newline après barre de progression

    # Résumé
    detected = [r for r in results if r.probe.detected]
    print(f"\n{'═'*70}")
    print(f"  ✓ MCP détectés  : {len(detected)}/{len(results)}")
    print(f"  Ports fantômes  : {sum(len(r.ghost_ports) for r in results)}")
    print(f"  CVE totales     : N/A (utiliser --shodan-api pour enrichissement)")
    print(f"{'═'*70}\n")

    if args.output:
        export_results(results, args.output, args.fmt)

    return results


def main():
    parser = argparse.ArgumentParser(
        description=f"MCP-ECHO v{CorpusConstants.VERSION} — Model Context Protocol Temporal Mapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  %(prog)s --gui
  %(prog)s --target http://localhost:8000
  %(prog)s --batch targets.txt --concurrency 10 --fmt ndjson -o out.ndjson
  %(prog)s --shodan-api KEY --shodan-discover -o shodan_results.json
        """,
    )

    # Modes
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--gui", action="store_true", help="Lance l'interface graphique")
    mode.add_argument("--target", metavar="URL", help="Cible unique")
    mode.add_argument("--batch", metavar="FILE", help="Fichier de cibles (une par ligne)")

    # Shodan
    parser.add_argument("--shodan-api", metavar="KEY", help="Clé API Shodan")
    parser.add_argument("--shodan-discover", action="store_true",
                        help="Découverte via Shodan avant le scan")
    parser.add_argument("--shodan-lookup", action="store_true",
                        help="Enrichissement Shodan par IP scannée")

    # Performances
    parser.add_argument("--concurrency", type=int, default=8, metavar="N",
                        help="Workers simultanés [défaut: 8]")
    parser.add_argument("--timeout", type=float, default=12.0, metavar="S",
                        help="Timeout par requête en secondes [défaut: 12]")
    parser.add_argument("--cache-ttl", type=int, default=3600, metavar="S",
                        help="TTL cache SQLite en secondes [défaut: 3600]")
    parser.add_argument("--no-cache", action="store_true",
                        help="Désactiver le cache")

    # Sortie
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Fichier de sortie")
    parser.add_argument("--fmt", choices=["json", "ndjson", "csv"],
                        default="json", help="Format d'export [défaut: json]")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Mode verbeux")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.no_cache:
        args.cache_ttl = 0

    # Vérification dépendances
    if not HAS_AIOHTTP and not args.gui:
        print("[!] aiohttp non installé : pip install aiohttp")
        print("    Le scan HTTP sera désactivé.\n")

    if args.gui:
        if not HAS_TK:
            print("[!] tkinter non disponible. Installez python3-tk.")
            sys.exit(1)
        root = tk.Tk()
        MCPECHOGUI(root)
        root.mainloop()
    else:
        run_cli_batch(args)


if __name__ == "__main__":
    main()
