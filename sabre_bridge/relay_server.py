from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

import yaml
from flask import Flask, Response, request, jsonify
try:
    import httpx
except Exception:
    httpx = None  # we’ll log if missing

# --- Paths / files ---------------------------------------------------------
PKG_DIR = Path(__file__).resolve().parent          # C:\SabreBridge\sabre_bridge
BRIDGE_DIR = PKG_DIR.parent                        # C:\SabreBridge
CFG_PATH = BRIDGE_DIR / "config.yaml"
LOG_DIR = BRIDGE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "sabre_bridge.log"

# --- Logging ---------------------------------------------------------------
logger = logging.getLogger("relay")
handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

app = Flask(__name__)

# --- Helpers ---------------------------------------------------------------
def _load_cfg() -> dict:
    try:
        if CFG_PATH.exists():
            return yaml.safe_load(CFG_PATH.read_text(encoding="utf-8")) or {}
    except Exception as ex:
        logger.error("Failed to read config.yaml: %s", ex)
    return {}

def _save_cfg(cfg: dict) -> None:
    try:
        CFG_PATH.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    except Exception as ex:
        logger.error("Failed to write config.yaml: %s", ex)

def _ensure_iclock(url: str) -> str:
    # make sure base ends with /iclock
    u = url.rstrip("/")
    return u if u.lower().endswith("/iclock") else (u + "/iclock")

def _forward(method: str, wdms_base: str, path: str, query: dict, body: bytes | None, content_type: str | None) -> Response:
    if httpx is None:
        return Response("httpx not installed on bridge", status=500)
    url = _ensure_iclock(wdms_base).rstrip("/") + path
    try:
        params = query or {}
        headers = {}
        if content_type:
            headers["Content-Type"] = content_type
        timeout = httpx.Timeout(20.0, connect=5.0)
        with httpx.Client(timeout=timeout) as c:
            if method == "GET":
                r = c.get(url, params=params, headers=headers)
            else:
                r = c.post(url, params=params, content=body or b"", headers=headers)
        # Pipe back exactly what WDMS returned
        resp = Response(r.content, status=r.status_code)
        for k, v in r.headers.items():
            if k.lower() in {"content-type", "content-length"}:
                resp.headers[k] = v
        return resp
    except Exception as ex:
        logger.error("zkpush proxy error %s %s?%s -> %s", method, path, urlencode(query or {}), ex)
        return Response(f"Proxy error: {ex}", status=502)

SN_RE = re.compile(r"(?:^|[?&])SN=([^&]+)")
def _extract_sn_from_query() -> Optional[str]:
    qs = request.query_string.decode(errors="ignore")
    m = SN_RE.search(qs)
    if m:
        return m.group(1)
    return request.args.get("SN")

def _extract_sn_from_body(body: bytes) -> Optional[str]:
    try:
        s = body.decode("utf-8", errors="ignore")
    except Exception:
        return None
    # Common formats from various firmwares:
    #   "SN=XXXX..." somewhere
    #   JSON with "serial": "XXXX"
    m = re.search(r'(?:SN=|\"serial\"\s*:\s*\")([A-Za-z0-9\-_]+)', s)
    return m.group(1) if m else None

def _auto_add_or_update(sn: str, client_ip: str, relay_port: int) -> None:
    """
    Ensure relay device with SN exists in config.yaml and record/update its IP.
    """
    cfg = _load_cfg()
    relay = cfg.setdefault("relay", {})
    devices = relay.setdefault("devices", [])
    # Look for an existing device with matching SN (or legacy "serial" key)
    found = None
    for d in devices:
        d_sn = str(d.get("sn") or d.get("serial") or "").strip()
        if d_sn.lower() == sn.lower():
            found = d
            break
    if found:
        changed = False
        if (found.get("ip") or "") != client_ip:
            found["ip"] = client_ip
            changed = True
        if "enabled" not in found:
            found["enabled"] = True
            changed = True
        if "port" not in found:
            found["port"] = relay.get("port", relay_port)
            changed = True
        if "type" not in found:
            # Default to ZKCloud unless SN suggests brand
            kind = "ZKCloud"
            usn = sn.upper()
            if usn.startswith("HIK"):
                kind = "Hikvision"
            elif usn.startswith("DAHUA"):
                kind = "Dahua"
            found["type"] = kind
            changed = True
        if changed:
            _save_cfg(cfg)
            logger.info("Relay updated device in config.yaml: %s ip=%s", sn, client_ip)
    else:
        # Create a new one
        kind = "ZKCloud"
        usn = sn.upper()
        if usn.startswith("HIK"):
            kind = "Hikvision"
        elif usn.startswith("DAHUA"):
            kind = "Dahua"
        devices.append({
            "sn": sn,
            "ip": client_ip,
            "port": relay.get("port", relay_port),
            "enabled": True,
            "type": kind,
        })
        _save_cfg(cfg)
        logger.info("Relay wrote new device to config.yaml: %s ip=%s", sn, client_ip)

# --- Flask routes -----------------------------------------------------------
WDMS_BASE = None  # filled in at startup
RELAY_PORT = 9090

@app.route("/relay/health")
def relay_health():
    return jsonify({"ok": True, "wdms": WDMS_BASE})

@app.before_request
def _before():
    # Log each request briefly (method, path, content length)
    logger.info('zkpush proxy method=%s path="%s" length=%s',
                request.method, request.path, request.content_length)

def _handle_auto_add_from_request():
    sn = _extract_sn_from_query()
    if not sn and request.data:
        sn = _extract_sn_from_body(request.data)
    if sn:
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        if client_ip:
            _auto_add_or_update(sn, client_ip, RELAY_PORT)

@app.route("/iclock/getrequest", methods=["GET"])
def iclock_getrequest():
    _handle_auto_add_from_request()
    return _forward("GET", WDMS_BASE, "/getrequest", request.args.to_dict(flat=True), None, None)

@app.route("/iclock/cdata", methods=["GET", "POST"])
def iclock_cdata():
    _handle_auto_add_from_request()
    body = request.get_data() if request.method == "POST" else None
    return _forward(request.method, WDMS_BASE, "/cdata", request.args.to_dict(flat=True), body, request.headers.get("Content-Type"))

@app.route("/iclock/registry", methods=["POST"])
def iclock_registry():
    _handle_auto_add_from_request()
    body = request.get_data()
    return _forward("POST", WDMS_BASE, "/registry", request.args.to_dict(flat=True), body, request.headers.get("Content-Type"))

# --- Main -------------------------------------------------------------------
def main(argv=None):
    global WDMS_BASE, RELAY_PORT
    p = argparse.ArgumentParser(description="Sabre Bridge Relay (ZKCloud/Hik/Dahua proxy)")
    p.add_argument("--port", type=int, default=9090)
    p.add_argument("--wdms", type=str, default="http://cloud.sabreproducts.com:81/iclock")
    p.add_argument("--debug", action="store_true")
    args = p.parse_args(argv)

    WDMS_BASE = args.wdms
    RELAY_PORT = args.port

    if args.debug:
        logger.setLevel(logging.DEBUG)

    logger.info("Relay server starting on 0.0.0.0:%s (wdms=%s)", args.port, WDMS_BASE)
    app.run(host="0.0.0.0", port=args.port, debug=False)

if __name__ == "__main__":
    main()
