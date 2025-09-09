from __future__ import annotations
import threading, time, subprocess, re
from dataclasses import dataclass, asdict
from pathlib import Path
import logging, yaml

from .logging_setup import setup_rotating_logger

# ---------- Layout ----------
PKG_DIR    = Path(__file__).resolve().parent
BRIDGE_DIR = PKG_DIR.parent
LOG_DIR    = BRIDGE_DIR / "logs"
CFG_PATH   = BRIDGE_DIR / "config.yaml"
PULLER_PY  = PKG_DIR / "zkteco_legacy_pull.py"

SCHED_LOG  = LOG_DIR / "zk_scheduler.log"
log: logging.Logger = setup_rotating_logger(SCHED_LOG, logging.INFO, name="zk_scheduler")

try:
    import httpx
except Exception:
    httpx = None  # Heartbeats will be disabled if httpx isn't available in this Python

@dataclass
class ZKDevice:
    name: str
    ip: str
    port: int = 4370
    enabled: bool = True
    interval_min: int = 5
    clear_after_push: bool = True
    wdms_url: str | None = None
    note: str = ""
    last_run: float = 0.0  # epoch seconds

class _Scheduler:
    def __init__(self):
        self.running = False
        self.th: threading.Thread | None = None
        self.hb_th: threading.Thread | None = None
        self.devices: list[ZKDevice] = []
        self.py32: str = r"C:\Users\peter\AppData\Local\Programs\Python\Python313-32\python.exe"
        self.wdms_default: str = "http://cloud.sabreproducts.com:81/iclock"
        self.auto_register: bool = True

        # Heartbeat settings
        self.hb_enabled: bool = False
        self.hb_interval_min: int = 5

        # runtime: discovered SNs per device index, and last heartbeat time
        self._sn_by_idx: dict[int, str] = {}
        self._last_hb: dict[int, float] = {}

    # ---------- config ----------
    def load_from_config(self):
        try:
            cfg = yaml.safe_load(CFG_PATH.read_text(encoding="utf-8")) or {}
        except Exception:
            cfg = {}
        leg = cfg.get("legacy_pull") or {}
        self.py32 = leg.get("python32") or self.py32
        self.wdms_default = leg.get("wdms_url") or self.wdms_default
        self.auto_register = bool(leg.get("auto_register", True))

        hb = leg.get("heartbeat") or {}
        self.hb_enabled = bool(hb.get("enabled", False))
        self.hb_interval_min = int(hb.get("interval_min", 5) or 5)

        self.devices = []
        for d in (leg.get("devices") or []):
            self.devices.append(ZKDevice(
                name=d.get("name","ZK"),
                ip=d.get("ip","192.168.1.100"),
                port=int(d.get("port",4370)),
                enabled=bool(d.get("enabled",True)),
                interval_min=int(d.get("interval_min",5)),
                clear_after_push=bool(d.get("clear_after_push",True)),
                wdms_url=d.get("wdms_url") or None,
                note=d.get("note",""),
                last_run=float(d.get("last_run",0.0)),
            ))

    def save_to_config(self):
        try:
            cfg = yaml.safe_load(CFG_PATH.read_text(encoding="utf-8")) or {}
        except Exception:
            cfg = {}
        leg = cfg.setdefault("legacy_pull", {})
        leg["python32"] = self.py32
        leg["wdms_url"] = self.wdms_default
        leg["auto_register"] = self.auto_register
        leg["devices"] = [asdict(x) for x in self.devices]
        leg["heartbeat"] = {
            "enabled": self.hb_enabled,
            "interval_min": int(self.hb_interval_min),
        }
        CFG_PATH.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")

    # ---------- lifecycle ----------
    def start(self):
        if self.running: return
        self.running = True
        self.th = threading.Thread(target=self._loop, daemon=True)
        self.th.start()
        log.info("ZK scheduler started (py32=%s wdms=%s)", self.py32, self.wdms_default)

        # Start heartbeat thread if configured and httpx is available
        if self.hb_enabled and httpx:
            if not self.hb_th or not self.hb_th.is_alive():
                self.hb_th = threading.Thread(target=self._heartbeat_loop, daemon=True)
                self.hb_th.start()
                log.info("Heartbeat loop started (interval=%s min)", self.hb_interval_min)
        elif self.hb_enabled and not httpx:
            log.warning("Heartbeat requested but httpx is not available in this Python. Install httpx.")

    def stop(self):
        self.running = False
        if self.th and self.th.is_alive():
            self.th.join(timeout=2.0)
        if self.hb_th and self.hb_th.is_alive():
            # allow it to exit naturally on next tick
            self.hb_th.join(timeout=2.0)
        log.info("ZK scheduler stopped")

    def _loop(self):
        while self.running:
            now = time.time()
            for i, d in enumerate(self.devices):
                if not d.enabled: continue
                due = (now - d.last_run) >= max(60, d.interval_min * 60)
                if not due: continue
                try:
                    self._run_one(i, d)
                except Exception as ex:
                    log.error("run device error name=%s ip=%s: %s", d.name, d.ip, ex)
                finally:
                    d.last_run = time.time()
                    self.save_to_config()
            for _ in range(5):
                if not self.running: break
                time.sleep(1)

    # ---------- one run + SN discovery ----------
    _SN_RE = re.compile(r"Device SN:\s*([A-Za-z0-9\-_]+)")
    _SN2_RE = re.compile(r"\bSN=([A-Za-z0-9\-_]+)")

    def _run_one(self, idx: int, d: ZKDevice):
        wdms = d.wdms_url or self.wdms_default
        puller = str(PULLER_PY)
        args = [self.py32, puller, "--ip", d.ip, "--port", str(d.port), "--wdms", wdms]
        if d.clear_after_push:
            args.append("--clear-after-push")

        log.info("zkpull start idx=%s name=%s ip=%s port=%s wdms=%s (puller=%s)",
                 idx, d.name, d.ip, d.port, wdms, puller)

        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for raw in proc.stdout:
            line = raw.rstrip("\r\n")

            # Try to learn/store the device SN from puller output
            m = self._SN_RE.search(line) or self._SN2_RE.search(line)
            if m:
                sn = m.group(1)
                self._sn_by_idx[idx] = sn
                log.info("discovered SN for idx=%s -> %s", idx, sn)

            # Log child lines (ASCII-safe fallback)
            try:
                log.info("zkpull[%s] %s", idx, line)
            except Exception:
                log.info("zkpull[%s] %s", idx, line.encode("ascii","replace").decode("ascii"))

        rc = proc.wait()
        log.info("zkpull done idx=%s rc=%s", idx, rc)

        # Send a one-off heartbeat after each run if enabled and we know the SN
        if self.hb_enabled and httpx and idx in self._sn_by_idx:
            self._post_heartbeat(idx, (d.wdms_url or self.wdms_default), self._sn_by_idx[idx])

    # ---------- heartbeat ----------
    def _hb_due(self, idx: int) -> bool:
        last = self._last_hb.get(idx, 0.0)
        return (time.time() - last) >= max(60, self.hb_interval_min * 60)

    def _hb_url(self, wdms: str, sn: str) -> str:
        base = wdms.rstrip("/")
        # wdms includes /iclock in our config; if it doesn't, add it.
        if not base.lower().endswith("/iclock"):
            base = base + "/iclock"
        return f"{base}/getrequest?SN={sn}"

    def _post_heartbeat(self, idx: int, wdms: str, sn: str):
        url = self._hb_url(wdms, sn)
        try:
            with httpx.Client(timeout=6.0) as c:
                r = c.get(url)
            ok = 200 <= r.status_code < 300
            self._last_hb[idx] = time.time()
            log.info("heartbeat idx=%s sn=%s -> %s %s", idx, sn, r.status_code, r.reason_phrase)
            return ok
        except Exception as ex:
            log.warning("heartbeat idx=%s sn=%s failed: %s", idx, sn, ex)
            return False

    def _heartbeat_loop(self):
        while self.running and self.hb_enabled and httpx:
            for idx, d in enumerate(self.devices):
                if not self.hb_enabled or not self.running:
                    break
                if not d.enabled:  # don't HB disabled devices
                    continue
                sn = self._sn_by_idx.get(idx)
                if not sn:
                    # we don't know SN yet (hasn't run); skip for now
                    continue
                if not self._hb_due(idx):
                    continue
                self._post_heartbeat(idx, (d.wdms_url or self.wdms_default), sn)
            for _ in range(5):
                if not (self.running and self.hb_enabled):
                    break
                time.sleep(1)

_sch = _Scheduler()

def get_scheduler() -> _Scheduler:
    return _sch
