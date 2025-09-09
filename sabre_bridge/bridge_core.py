import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Callable, List
import datetime as dt

@dataclass
class Event:
    vendor: str
    device_sn: str
    pin: Optional[str]
    ts: dt.datetime
    verify_mode: str = "face"
    event_type: str = "pass"
    in_out: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

class PersonMapper:
    """
    Simple CSV mapper: vendor,device_sn,vendor_person_id,card_no,pin
    One of vendor_person_id OR card_no should match.
    """
    def __init__(self, csv_path):
        self.csv_path = csv_path
        self.rows: List[Dict[str, str]] = []
        self.reload()

    def reload(self):
        import csv, os
        self.rows.clear()
        if not os.path.exists(self.csv_path):
            return
        with open(self.csv_path, "r", encoding="utf-8", newline="") as f:
            rdr = csv.DictReader(f)
            for r in rdr:
                row = { (k or "").strip(): ( (v or "").strip() ) for k, v in r.items() }
                self.rows.append(row)

    def resolve(self, vendor: str, device_sn: str, vendor_person_id: Optional[str], card_no: Optional[str]) -> Optional[str]:
        v = (vendor or "").lower()
        d = device_sn or ""
        vpid = (vendor_person_id or "")
        cno = (card_no or "")
        for r in self.rows:
            if (r.get("vendor","").lower()==v) and (r.get("device_sn","")==d):
                if vpid and r.get("vendor_person_id","")==vpid and r.get("pin"):
                    return r["pin"]
        if cno:
            for r in self.rows:
                if (r.get("vendor","").lower()==v) and (r.get("device_sn","")==d):
                    if r.get("card_no","")==cno and r.get("pin"):
                        return r["pin"]
        return None

class BridgeEngine:
    def __init__(self, sink, mapper: PersonMapper, loop: Optional[asyncio.AbstractEventLoop]=None):
        self.sink = sink
        self.mapper = mapper
        self.loop = loop or asyncio.get_event_loop()
        self._tasks: List[asyncio.Task] = []
        self._running = False
        self._device_state: Dict[str, Dict[str, Any]] = {}
        self.on_device_status: Optional[Callable[[str, Dict[str, Any]], None]] = None
        self.on_event: Optional[Callable[[Event], None]] = None
        self.on_error: Optional[Callable[[str, str], None]] = None
        self.log = logging.getLogger("sabre_bridge.engine")

    def _ensure_device(self, device_sn: str):
        if device_sn not in self._device_state:
            self._device_state[device_sn] = {"connected": False, "events": 0, "last_event": None, "last_error": None}

    def device_snapshot(self) -> Dict[str, Dict[str, Any]]:
        return {k: dict(v) for k, v in self._device_state.items()}

    async def _pump(self, device_sn: str, collector):
        self._ensure_device(device_sn)
        st = self._device_state[device_sn]
        while self._running:
            try:
                st["connected"] = True
                if self.on_device_status: self.on_device_status(device_sn, dict(st))
                async for e in collector():
                    pin = self.mapper.resolve(e.get("vendor"), device_sn, e.get("person_id"), e.get("card_no"))
                    evt = Event(
                        vendor=e.get("vendor",""),
                        device_sn=device_sn,
                        pin=pin,
                        ts=e.get("ts", dt.datetime.now(dt.timezone.utc)),
                        verify_mode=e.get("verify_mode","face"),
                        event_type=e.get("event_type","pass"),
                        in_out=e.get("in_out"),
                        raw=e
                    )
                    await self.sink.send_event(evt)
                    st["events"] += 1
                    st["last_event"] = evt.ts
                    if self.on_event: self.on_event(evt)
                    if self.on_device_status: self.on_device_status(device_sn, dict(st))
            except asyncio.CancelledError:
                break
            except Exception as ex:
                st["connected"] = False
                st["last_error"] = str(ex)
                self.log.exception("Collector error [%s]: %s", device_sn, ex)
                if self.on_error: self.on_error(device_sn, str(ex))
                if self.on_device_status: self.on_device_status(device_sn, dict(st))
                await asyncio.sleep(5.0)
        st["connected"] = False
        if self.on_device_status: self.on_device_status(device_sn, dict(st))

    def start(self, devices):
        if self._running: return
        self._running = True
        for d in devices:
            name = d["name"]
            self._ensure_device(name)
            vendor = d["vendor"].lower()
            port = d.get("port")
            if d.get("ip") == "relay":
                # Relay devices don't create a network collector; relay injects events directly.
                self._device_state[name]["connected"] = True
                continue
            if vendor == "hik":
                from .collectors.hik import make_hik_collector
                coll = make_hik_collector(
                    ip=d["ip"], username=d["username"], password=d["password"],
                    device_sn=name, use_device_serial=bool(d.get("use_device_serial", True)),
                    port=port
                )
            elif vendor == "dahua":
                from .collectors.dahua import make_dahua_collector
                coll = make_dahua_collector(
                    ip=d["ip"], username=d["username"], password=d["password"],
                    device_sn=name, use_device_serial=bool(d.get("use_device_serial", True)),
                    port=port
                )
            else:
                raise ValueError(f"Unsupported vendor: {vendor}")
            self._tasks.append(self.loop.create_task(self._pump(name, coll)))

    def add_device_stub(self, device_cfg: Dict[str, Any]):
        """
        Add a logical device that receives events via relay (no collector).
        """
        name = device_cfg["name"]
        self._ensure_device(name)
        self._device_state[name]["connected"] = True

    async def stop(self):
        if not self._running: return
        self._running = False
        for t in self._tasks: t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
