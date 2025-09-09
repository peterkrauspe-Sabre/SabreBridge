
import pyodbc, logging
from datetime import datetime

log = logging.getLogger("sabre_bridge.sinks.directdb")

class DirectDBSink:
    def __init__(self, odbc_conn_str: str, verify_face_code: int = 200, device_sn_as_sn: bool = True, checktype_default: str = "I"):
        self.conn_str = odbc_conn_str
        self.verify_face_code = verify_face_code
        self.device_sn_as_sn = device_sn_as_sn
        self.checktype_default = checktype_default
        self._conn = None
        self._ensure_conn()

    def _ensure_conn(self):
        if self._conn is None:
            self._conn = pyodbc.connect(self.conn_str, autocommit=True)

    def _resolve_userid(self, pin: str):
        cur = self._conn.cursor()
        cur.execute("SELECT USERID FROM UserInfo WHERE Badgenumber = ?", (pin,))
        row = cur.fetchone()
        return int(row[0]) if row else None

    async def send_event(self, evt):
        if not evt.pin:
            return
        self._ensure_conn()
        userid = self._resolve_userid(evt.pin)
        if userid is None:
            log.warning("PIN not found in UserInfo: %s", evt.pin)
            return
        checktype = (evt.in_out or self.checktype_default)[:1] if evt.in_out else self.checktype_default
        verify = self.verify_face_code if (evt.verify_mode or "").lower() == "face" else 15
        sn = evt.device_sn if self.device_sn_as_sn else None
        ts = evt.ts if isinstance(evt.ts, datetime) else datetime.fromisoformat(str(evt.ts))
        cur = self._conn.cursor()
        try:
            cur.execute("INSERT INTO CheckInOut (USERID, CheckTime, CheckType, VerifyCode, SN) VALUES (?, ?, ?, ?, ?)", (userid, ts, checktype, verify, sn))
        except Exception as ex:
            log.exception("DB insert failed: %s", ex)
            raise
