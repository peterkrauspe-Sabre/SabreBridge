import asyncio, httpx, logging, re
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

log = logging.getLogger("sabre_bridge.collectors.dahua")

def _base(ip: str, port: Optional[int]) -> str:
    return f"http://{ip}:{port}" if port else f"http://{ip}"

async def _get_dahua_serial(ip: str, username: str, password: str, port: Optional[int]) -> str:
    url = _base(ip, port) + "/cgi-bin/magicBox.cgi?action=getSystemInfo"
    try:
        async with httpx.AsyncClient(auth=(username, password), timeout=10) as cli:
            r = await cli.get(url)
            r.raise_for_status()
            txt = r.text
            m = re.search(r"serialNumber=([\w-]+)", txt, flags=re.IGNORECASE)
            return m.group(1).strip() if m else ""
    except Exception as ex:
        log.warning("Could not fetch Dahua serial: %s", ex)
        return ""

def _parse_line(line: str):
    code = None
    m_code = re.search(r'Code=([A-Za-z]+)', line)
    if m_code: code = m_code.group(1)
    m_card = re.search(r'CardNo=([0-9A-Fx]+)', line, flags=re.IGNORECASE)
    card = m_card.group(1) if m_card else None
    m_user = re.search(r'UserID=([A-Za-z0-9_-]+)', line)
    user = m_user.group(1) if m_user else None
    ts = datetime.now(timezone.utc)
    verify = "face" if (code or "").lower().startswith("face") else ("card" if card else "face")
    return {"vendor":"dahua","person_id":user,"card_no":card,"ts":ts,"verify_mode":verify,"event_type":"pass","in_out":None}

def make_dahua_collector(ip: str, username: str, password: str,
                         device_sn: str, use_device_serial: bool = True,
                         port: Optional[int] = None):
    url = _base(ip, port) + "/cgi-bin/eventManager.cgi?action=attach&codes=[All]"
    auth = (username, password)
    async def run() -> AsyncGenerator[dict, None]:
        hw_serial = ""
        if use_device_serial:
            hw_serial = await _get_dahua_serial(ip, username, password, port)
        while True:
            try:
                async with httpx.AsyncClient(auth=auth, timeout=None) as cli:
                    async with cli.stream("GET", url) as r:
                        async for line in r.iter_text():
                            if not line:
                                await asyncio.sleep(0); continue
                            if "Code=" in line:
                                parsed = _parse_line(line)
                                parsed["device_sn"] = device_sn
                                parsed["hw_serial"] = hw_serial or None
                                yield parsed
            except Exception as ex:
                log.exception("Dahua eventManager error [%s]: %s", device_sn, ex)
                await asyncio.sleep(3.0)
    return run
