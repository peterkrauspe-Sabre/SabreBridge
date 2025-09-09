import asyncio, httpx, logging, re, json
from datetime import datetime, timezone
from typing import AsyncGenerator, Dict, Any, Optional

log = logging.getLogger("sabre_bridge.collectors.hik")

def _base(ip: str, port: Optional[int]) -> str:
    return f"http://{ip}:{port}" if port else f"http://{ip}"

async def _get_hik_serial(ip: str, username: str, password: str, port: Optional[int]) -> str:
    url = _base(ip, port) + "/ISAPI/System/deviceInfo"
    try:
        async with httpx.AsyncClient(auth=httpx.DigestAuth(username, password), timeout=10) as cli:
            r = await cli.get(url)
            r.raise_for_status()
            txt = r.text
            try:
                obj = json.loads(txt)
                return obj.get("deviceSerialNumber") or obj.get("serialNumber") or ""
            except Exception:
                pass
            m = re.search(r"<serialNumber>([^<]+)</serialNumber>", txt) or re.search(r"<deviceSerialNumber>([^<]+)</deviceSerialNumber>", txt)
            return m.group(1).strip() if m else ""
    except Exception as ex:
        log.warning("Could not fetch Hik serial: %s", ex)
        return ""

def _parse(text: str) -> Dict[str, Any]:
    try:
        if "{" in text and "}" in text:
            s = text.find("{"); e = text.rfind("}")
            obj = json.loads(text[s:e+1])
            acs = obj.get("AccessControllerEvent") or obj.get("AcsEvent") or obj
            employee = acs.get("employeeNoString") or acs.get("employeeNo")
            card = acs.get("cardNo") or acs.get("cardValue")
            tm = acs.get("dateTime") or acs.get("time")
            if tm:
                try: ts = datetime.fromisoformat(tm.replace("Z","+00:00"))
                except Exception: ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)
            verify = (acs.get("currentVerifyMode") or "face").lower()
            return {"person_id": (str(employee) if employee else None),
                    "card_no": (str(card) if card else None),
                    "ts": ts, "verify_mode": verify, "event_type":"pass", "in_out": None}
    except Exception:
        pass
    m_time = re.search(r"<time>([^<]+)</time>|<dateTime>([^<]+)</dateTime>", text)
    tm = m_time.group(1) if m_time and m_time.group(1) else (m_time.group(2) if m_time else "")
    try: ts = datetime.fromisoformat(tm.replace("Z","+00:00"))
    except Exception: ts = datetime.now(timezone.utc)
    m_emp  = re.search(r"<employeeNoString>([^<]+)</employeeNoString>|<employeeNo>([^<]+)</employeeNo>", text)
    emp = m_emp.group(1) if m_emp and m_emp.group(1) else (m_emp.group(2) if m_emp else None)
    m_card = re.search(r"<cardNo>([^<]+)</cardNo>|<cardValue>([^<]+)</cardValue>", text)
    card = m_card.group(1) if m_card and m_card.group(1) else (m_card.group(2) if m_card else None)
    m_mode = re.search(r"<currentVerifyMode>([^<]+)</currentVerifyMode>", text)
    verify = (m_mode.group(1).lower() if m_mode else "face")
    return {"person_id": emp, "card_no": card, "ts": ts, "verify_mode": verify, "event_type":"pass", "in_out": None}

def make_hik_collector(ip: str, username: str, password: str,
                       device_sn: str, use_device_serial: bool = True,
                       port: Optional[int] = None):
    url = _base(ip, port) + "/ISAPI/Event/notification/alertStream"

    async def run() -> AsyncGenerator[dict, None]:
        hw_serial = ""
        if use_device_serial:
            hw_serial = await _get_hik_serial(ip, username, password, port)
        while True:
            try:
                async with httpx.AsyncClient(auth=httpx.DigestAuth(username, password), timeout=None) as cli:
                    async with cli.stream("GET", url) as r:
                        async for chunk in r.aiter_bytes():
                            if not chunk:
                                await asyncio.sleep(0); continue
                            text = chunk.decode(errors="ignore")
                            if ("AccessControllerEvent" in text) or ("<AcsEvent>" in text) or ("<EventNotificationAlert>" in text):
                                parsed = _parse(text)
                                parsed.update({"vendor":"hik","device_sn":device_sn,"hw_serial":hw_serial or None})
                                yield parsed
            except Exception as ex:
                log.exception("Hik alertStream error [%s]: %s", device_sn, ex)
                await asyncio.sleep(3.0)
    return run
