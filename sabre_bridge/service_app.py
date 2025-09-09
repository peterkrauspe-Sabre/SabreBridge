
# Windows service entry point (requires pywin32). Install on Windows:
#   pip install pywin32
#   python -m sabre_bridge.service_app install
#   python -m sabre_bridge.service_app start
import win32serviceutil, win32service, win32event, servicemanager, socket
import logging, asyncio, yaml
from pathlib import Path
from .bridge_core import BridgeEngine, PersonMapper
from .sinks.zkpush import ZKPushSink
from .sinks.directdb import DirectDBSink

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

class SabreBridgeService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SabreBridgeService"
    _svc_display_name_ = "Sabre Bridge (Hik/Dahua to UTime/WDMS)"
    _svc_description_ = "Listens to Hikvision and Dahua devices and forwards normalized events to UTime/WDMS."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self.loop = asyncio.new_event_loop()
        self.engine = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        if self.engine:
            self.loop.run_until_complete(self.engine.stop())
        self.loop.stop()

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""))
        self.main()

    def main(self):
        cfg_path = Path("config.yaml")
        if not cfg_path.exists():
            servicemanager.LogInfoMsg("config.yaml not found — service idle.")
            return
        cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
        mapper = PersonMapper(str(Path(cfg.get("person_map", {}).get("path","person_map.csv"))))
        mode = cfg.get("utime_sink",{}).get("mode","push").lower()
        if mode=="push":
            base = cfg["utime_sink"]["push"]["wdms_url"].rstrip("/")
            sn = cfg["utime_sink"]["push"]["device_sn"]
            sink = ZKPushSink(base_url=base, device_sn=sn)
        else:
            odbc = cfg["utime_sink"]["db"]["odbc_conn_str"]
            verify_face = int(cfg["utime_sink"]["db"].get("verify_face_code",200))
            sink = DirectDBSink(odbc_conn_str=odbc, verify_face_code=verify_face)
        devices = cfg.get("devices", [])
        self.engine = BridgeEngine(sink, mapper, loop=self.loop)
        def run_loop():
            self.engine.start(devices)
            self.loop.run_forever()
        try:
            run_loop()
        except Exception as ex:
            servicemanager.LogErrorMsg(f"Service exception: {ex}")

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(SabreBridgeService)
