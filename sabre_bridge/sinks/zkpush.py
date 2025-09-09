import logging
import httpx
from urllib.parse import urlencode

log = logging.getLogger("sabre_bridge.sinks.zkpush")

DEFAULT_VERIFY_MAP = {
    "face": "200",
    "card": "1",
    "finger": "11",
    "fingerprint": "11",
    "password": "0",
    "palm": "201",
    "qr": "5"
}

class ZKPushSink:
    """
    Push events to ZKTeco/WDMS (/iclock) like a terminal would.
    """
    def __init__(self, base_url: str, default_sn: str, device_sn_map: dict | None = None,
                 verify_map: dict | None = None, on_push_result=None):
        self.base = base_url.rstrip("/")
        self.default_sn = default_sn
        self.sn_map = device_sn_map or {}
        self.verify_map = {**DEFAULT_VERIFY_MAP, **(verify_map or {})}
        self.on_push_result = on_push_result  # (device_sn, pin, ts, url, status_code, reason)

    def _sn_for(self, device_name: str) -> str:
        return self.sn_map.get(device_name) or self.default_sn

    def _verify_code(self, mode: str) -> str:
        return self.verify_map.get((mode or "").lower(), "0")

    async def send_event(self, evt):
        sn = self._sn_for(evt.device_sn)
        ts = evt.ts.astimezone().strftime("%Y-%m-%d %H:%M:%S")
        verify = self._verify_code(evt.verify_mode)
        pin = (evt.pin or "").strip()

        q = {"SN": sn, "table": "ATTLOG", "Stamp": "1"}
        url = f"{self.base}/cdata?{urlencode(q)}"
        body = f"ATTLOG={pin}\t{ts}\t\t\t\t{verify}"

        try:
            async with httpx.AsyncClient(timeout=15) as cli:
                r = await cli.post(url, content=body.encode("utf-8"))
                log.info("POST %s  body=%r  → %s %s", url, body, r.status_code, r.reason_phrase)
                if callable(self.on_push_result):
                    self.on_push_result(evt.device_sn, pin, evt.ts, url, r.status_code, r.reason_phrase)
        except Exception as ex:
            log.error("Push failed: %s %s  body=%r", url, ex, body)
            if callable(self.on_push_result):
                self.on_push_result(evt.device_sn, pin, evt.ts, url, 0, str(ex))
            raise
