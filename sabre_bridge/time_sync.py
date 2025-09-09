import asyncio, logging, re
from datetime import datetime, time, timedelta, timezone
from typing import Optional, Dict, Any
import httpx

log = logging.getLogger("sabre_bridge.time_sync")

SA_TZ = timezone(timedelta(hours=2))  # Africa/Johannesburg (no DST)

class TimeSyncManager:
    """
    - Schedules a once-per-day device time sync at local 'daily_at'
    - On first connect (optional), sets time/NTP/timezone per vendor
    - For ZKTeco/ADMS: can inject 'C:TIME yyyy-mm-dd HH:MM:SS' on /iclock/getrequest
    """
    def __init__(self, loop: asyncio.AbstractEventLoop, cfg: Dict[str, Any]):
        self.loop = loop
        self.enabled = bool((cfg or {}).get("enabled", True))
        self.tz_label = (cfg or {}).get("timezone", "UTC+02:00")
        self.ntp = (cfg or {}).get("ntp_server", "time.google.com")
        self.daily_at = (cfg or {}).get("daily_at", "02:30")
        self.on_first = bool((cfg or {}).get("on_first_connect", True))
        self.zk_inject = bool((cfg or {}).get("zk_inject_on_getrequest", True))

        self._first_done: set[str] = set()       # device name → done first sync
        self._zk_next_due: Dict[str, datetime] = {}  # SN → next allowed injection time (rate-limit)

        self._daily_task: Optional[asyncio.Task] = None

    # ---------- public API ----------

    def start_daily(self, device_index: Dict[str, Dict[str, Any]]):
        if not self.enabled: 
            return
        if self._daily_task is None:
            self._daily_task = self.loop.create_task(self._daily_runner(device_index))
            log.info("TimeSync daily scheduler started at %s", self.daily_at)

    def on_device_connected(self, name: str, device_cfg: Dict[str, Any]):
        """Call this when a collector reports 'connected'."""
        if not self.enabled or not self.on_first:
            return
        if name in self._first_done:
            return
        self._first_done.add(name)
        self.loop.create_task(self._sync_vendor_time(device_cfg))

    # For /iclock/getrequest handling:
    def zk_should_inject(self, sn: Optional[str]) -> Optional[str]:
        """
        Return time command text if we should inject now, else None.
        """
        if not (self.enabled and self.zk_inject and sn):
            return None
        now = datetime.now(SA_TZ)
        nxt = self._zk_next_due.get(sn)
        if nxt and now < nxt:
            return None
        # Allow next injection after 23h to avoid spamming
        self._zk_next_due[sn] = now + timedelta(hours=23)
        # 'C:TIME yyyy-mm-dd HH:MM:SS'
        cmd_ts = now.strftime("%Y-%m-%d %H:%M:%S")
        return f"OK\nC:TIME {cmd_ts}\n"

    # ---------- internals ----------

    async def _daily_runner(self, index: Dict[str, Dict[str, Any]]):
        while True:
            try:
                hh, mm = [int(x) for x in self.daily_at.split(":", 1)]
            except Exception:
                hh, mm = 2, 30
            now = datetime.now(SA_TZ)
            tomorrow = now.date()
            run_at = datetime.combine(tomorrow, time(hh, mm, 0, tzinfo=SA_TZ))
            if run_at <= now:
                run_at = run_at + timedelta(days=1)
            wait_s = (run_at - now).total_seconds()
            await asyncio.sleep(wait_s)
            log.info("TimeSync daily job starting for %d devices", len(index))
            # run serially to be polite
            for name, cfg in index.items():
                try:
                    await self._sync_vendor_time(cfg)
                except Exception as ex:
                    log.warning("TimeSync failed for %s: %s", name, ex)

    async def _sync_vendor_time(self, device_cfg: Dict[str, Any]):
        vendor = (device_cfg.get("vendor") or "").lower()
        ip = device_cfg.get("ip")
        if not ip or ip == "relay":
            # We cannot address 'relay' pseudo devices directly; ZK handled via injection.
            return
        port = device_cfg.get("port")
        user = device_cfg.get("username") or ""
        pwd  = device_cfg.get("password") or ""
        if vendor == "hik":
            await self._hik_set_time(ip, port, user, pwd)
        elif vendor == "dahua":
            await self._dahua_set_time(ip, port, user, pwd)

    # ---------- vendor specifics ----------

    def _base(self, ip: str, port: Optional[int]) -> str:
        return f"http://{ip}:{port}" if port else f"http://{ip}"

    async def _hik_set_time(self, ip: str, port: Optional[int], user: str, pwd: str):
        base = self._base(ip, port)
        # Enable NTP
        ntp_xml = f"""
<NTPServerList><NTPServer>
  <id>1</id><addressingFormatType>hostname</addressingFormatType>
  <hostName>{self.ntp}</hostName><portNo>123</portNo>
  <synchronizeInterval>3600</synchronizeInterval><enabled>true</enabled>
</NTPServer></NTPServerList>""".strip()
        # Timezone (Hik expects Olson string or offset depending on FW; try timeZone/timeZoneName)
        tz_xml = f"<timeZone>SA</timeZone>"  # 'SA' works on many firmwares; if not, fallback below
        time_xml = f"<time><timeMode>NTP</timeMode></time>"

        auth = httpx.DigestAuth(user, pwd)
        async with httpx.AsyncClient(timeout=8, auth=auth) as cli:
            try:
                r1 = await cli.put(f"{base}/ISAPI/System/time/ntpServers", content=ntp_xml.encode(), headers={"Content-Type":"application/xml"})
                log.info("HIK NTP set %s → %s", ip, r1.status_code)
            except Exception as ex:
                log.warning("HIK NTP error %s: %s", ip, ex)
            try:
                r2 = await cli.put(f"{base}/ISAPI/System/time/timeZone", content=tz_xml.encode(), headers={"Content-Type":"application/xml"})
                log.info("HIK TZ set %s → %s", ip, r2.status_code)
            except Exception as ex:
                log.warning("HIK TZ error %s: %s", ip, ex)
            try:
                r3 = await cli.put(f"{base}/ISAPI/System/time/time", content=time_xml.encode(), headers={"Content-Type":"application/xml"})
                log.info("HIK Time mode %s → %s", ip, r3.status_code)
            except Exception as ex:
                log.warning("HIK time-mode error %s: %s", ip, ex)

    async def _dahua_set_time(self, ip: str, port: Optional[int], user: str, pwd: str):
        base = self._base(ip, port)
        auth = (user, pwd)
        async with httpx.AsyncClient(timeout=8, auth=auth) as cli:
            # Enable NTP + server + interval
            try:
                url = f"{base}/cgi-bin/configManager.cgi?action=setConfig&NTP.Enable=true&NTP.Address={self.ntp}&NTP.Port=123&NTP.UpdatePeriod=3600"
                r1 = await cli.get(url)
                log.info("Dahua NTP set %s → %s", ip, r1.status_code)
            except Exception as ex:
                log.warning("Dahua NTP error %s: %s", ip, ex)
            # Timezone
            try:
                # Many firmwares accept 'Time.TimeZone' like 'UTC+02:00'
                url = f"{base}/cgi-bin/configManager.cgi?action=setConfig&Time.TimeZone={self.tz_label}"
                r2 = await cli.get(url)
                log.info("Dahua TZ set %s → %s", ip, r2.status_code)
            except Exception as ex:
                log.warning("Dahua TZ error %s: %s", ip, ex)
