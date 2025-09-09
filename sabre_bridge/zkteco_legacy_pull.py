from __future__ import annotations
import sys, argparse
from pathlib import Path
from datetime import datetime

THIS_FILE   = Path(__file__).resolve()
PKG_DIR     = THIS_FILE.parent
BRIDGE_DIR  = PKG_DIR.parent
LOG_DIR     = BRIDGE_DIR / "logs"
PULL_DIR    = BRIDGE_DIR / "pulls"
LEDGER_DB   = PULL_DIR / "ledger.txt"
DIAG        = PULL_DIR / "diagnostics.txt"

WDMS_BASE   = "http://cloud.sabreproducts.com:81/iclock"

try:
    import win32com.client
    import pythoncom
except Exception:
    print("ERROR: pywin32 is required in 32-bit Python. Install: python -m pip install pywin32")
    sys.exit(1)
try:
    import httpx
except Exception:
    print("ERROR: httpx is required. Install: python -m pip install httpx")
    sys.exit(1)

def ensure_dirs():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    PULL_DIR.mkdir(parents=True, exist_ok=True)
    LEDGER_DB.touch(exist_ok=True)
    if not DIAG.exists():
        DIAG.write_text("", encoding="utf-8")

def dlog(msg: str):
    with DIAG.open("a", encoding="utf-8") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} | {msg}\n")

def ledger_has(key: str) -> bool:
    try:
        with LEDGER_DB.open("r", encoding="utf-8") as f:
            for line in f:
                if line.rstrip() == key:
                    return True
    except Exception:
        pass
    return False

def ledger_add(key: str):
    with LEDGER_DB.open("a", encoding="utf-8") as f:
        f.write(key + "\n")

def hash_key(sn: str, pin: str, dtstr: str) -> str:
    import hashlib as _h
    return _h.sha1(f"{sn}|{pin}|{dtstr}".encode("utf-8")).hexdigest()

def _call_with_overloads(zk, name, *args):
    m = getattr(zk, name)
    try:
        return m(*args)
    except Exception:
        if len(args) >= 2 and isinstance(args[0], int) and isinstance(args[1], str):
            new_args = (args[0], 0) + args[1:]
            return getattr(zk, name)(*new_args)
        raise

def connect_zk(ip: str, port: int = 4370):
    from win32com.client import gencache, Dispatch
    last_err = None
    for progid in ("zkemkeeper.ZKEM.1", "zkemkeeper.ZKEM"):
        try:
            try:
                zk = gencache.EnsureDispatch(progid)
            except Exception:
                zk = Dispatch(progid)
            if not zk.Connect_Net(ip, port):
                raise RuntimeError(f"Connect_Net failed to {ip}:{port}")
            try: zk.SetCommPassword(0)
            except Exception: pass
            try: zk.MachineNumber = 1
            except Exception: pass
            try:
                serial = zk.GetSerialNumber()
            except Exception:
                try:
                    serial = zk.GetStrInfo(1)
                except Exception:
                    serial = ""
            if not serial:
                serial = f"ZK_{ip.replace('.', '-')}"
            return zk, serial
        except Exception as ex:
            last_err = ex
    raise RuntimeError("Could not create ZKEMKeeper COM object (ensure 32-bit py & DLL). Last error: %s" % last_err)

def _parse_kv_line(s: str) -> dict:
    out = {}
    s = s.replace("\r", "").strip()
    for token in s.replace(",", " ").split():
        if "=" in token:
            k, _, v = token.partition("=")
            out[k.strip().lower()] = v.strip()
    return out

def _kv_to_attlog(d: dict):
    pin = d.get("pin") or d.get("userid") or d.get("enrollnumber")
    ts  = d.get("time") or d.get("checktime") or d.get("datetime")
    ver = d.get("verifycode") or d.get("verify") or d.get("verifymode") or d.get("checktype") or "0"
    wc  = d.get("workcode") or ""
    if not (pin and ts):
        return None
    ts = ts.replace("/", "-")
    return (str(pin), ts, str(ver), "0", str(wc))

def _try_ssr_general_log_ex(zk) -> list:
    logs = []
    try: zk.ReadAllGLogData(1)
    except Exception: pass
    safeguard = 0
    while True:
        safeguard += 1
        if safeguard > 1_000_000:
            dlog("Safeguard break in SSR_GetGeneralLogDataEx")
            break
        try:
            s = zk.SSR_GetGeneralLogDataEx(1)
        except Exception as ex:
            dlog(f"SSR_GetGeneralLogDataEx error: {ex}")
            break
        if s is None:
            break
        if isinstance(s, tuple):
            if not s: break
            ok = bool(s[0])
            if not ok: break
            pin   = str(s[1]).strip() if len(s) > 1 else ""
            verify= str(s[2])         if len(s) > 2 else "0"
            if len(s) >= 10:
                y, m, d, hh, mm, ss = int(s[4]), int(s[5]), int(s[6]), int(s[7]), int(s[8]), int(s[9])
                ts = f"{y:04d}-{m:02d}-{d:02d} {hh:02d}:{mm:02d}:{ss:02d}"
            else:
                dlog(f"Tuple missing date parts: {s}")
                continue
            work = str(s[10]) if len(s) > 10 else ""
            if pin and ts:
                logs.append((pin, ts, verify, "0", work))
            else:
                dlog(f"Tuple missing pin/ts: {s}")
        else:
            d = _parse_kv_line(str(s))
            rec = _kv_to_attlog(d)
            if rec: logs.append(rec)
            else: dlog(f"Unparsed SSR_GetGeneralLogDataEx line: {s}")
    if logs:
        print("Strategy: SSR_GetGeneralLogDataEx (tuple) OK:", len(logs))
        return logs
    raise RuntimeError("SSR_GetGeneralLogDataEx returned zero rows.")

def _try_ssr_get_device_data(zk, start: str | None, end: str | None) -> list:
    where = ""
    if start and end: where = f"CheckTime>='{start}' and CheckTime<='{end}'"
    elif start:       where = f"CheckTime>='{start}'"
    elif end:         where = f"CheckTime<='{end}'"
    for fields in ("Pin,CheckTime,VerifyCode,WorkCode", "PIN,Time,VerifyCode,WorkCode", "PIN,Time"):
        try:
            text = _call_with_overloads(zk, "SSR_GetDeviceData", 1, "ATTLOG", fields, where, "")
        except Exception as ex:
            dlog(f"SSR_GetDeviceData error fields='{fields}': {ex}"); continue
        if not text:
            dlog(f"SSR_GetDeviceData empty fields='{fields}'"); continue
        logs = []
        for ln in str(text).splitlines():
            d = _parse_kv_line(ln)
            rec = _kv_to_attlog(d)
            if rec: logs.append(rec)
        if logs:
            print(f"Strategy: SSR_GetDeviceData fields={fields} OK:", len(logs))
            return logs
    raise RuntimeError("SSR_GetDeviceData empty/unparseable on this unit.")

def _fallback_file_export(zk) -> list:
    names = ["attlog.dat", "ATTLOG.dat", "ATTLOG.TXT", "attlog.txt"]
    raw = PULL_DIR / "raw_attlog.dat"
    for name in names:
        try:
            if raw.exists(): raw.unlink()
        except Exception: pass
        try:
            ok = _call_with_overloads(zk, "GetDataFile", 1, name, str(raw))
        except Exception as ex:
            dlog(f"GetDataFile('{name}') error: {ex}"); ok = False
        if ok and raw.exists() and raw.stat().st_size > 0:
            text = raw.read_text(encoding="utf-8", errors="ignore")
            logs = []
            for line in text.splitlines():
                parts = [p.strip() for p in line.split("\t")]
                if len(parts) >= 2 and parts[0] and parts[1]:
                    pin = parts[0]; ts = parts[1].replace("/", "-")
                    verify = parts[2] if len(parts) > 2 and parts[2] else "0"
                    status = parts[3] if len(parts) > 3 and parts[3] else "0"
                    work   = parts[4] if len(parts) > 4 else ""
                    logs.append((pin, ts, verify, status, work))
            if logs:
                print(f"Strategy: GetDataFile({name}) OK:", len(logs))
                return logs
    raise RuntimeError("File export produced no records.")

def pull_logs(zk, start: str | None, end: str | None) -> list:
    try:
        return _try_ssr_general_log_ex(zk)
    except Exception as ex_first:
        dlog(f"SSR_GetGeneralLogDataEx path failed: {ex_first}")
    try:
        return _try_ssr_get_device_data(zk, start, end)
    except Exception as ex_second:
        dlog(f"SSR_GetDeviceData path failed: {ex_second}")
    return _fallback_file_export(zk)

def save_attlog_file(device_sn: str, logs: list) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = PULL_DIR / f"{device_sn}_{stamp}.attlog.txt"
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for pin, dt_str, verify, status, work in logs:
            f.write(f"{pin}\t{dt_str}\t{verify}\t{status}\t{work}\n")
    return path

def replay_file_to_wdms(path: Path, wdms_base: str, device_sn: str) -> tuple[int, str]:
    body = path.read_text(encoding="utf-8")
    base = wdms_base.rstrip("/")
    if not base.lower().endswith("/iclock"):
        base = base + "/iclock"
    url = base + "/cdata?SN=" + device_sn
    with httpx.Client(timeout=20) as cli:
        r = cli.post(url, content=body.encode("utf-8"))
    return r.status_code, r.reason_phrase

def run_once(ip, port, wdms, no_push, clear_after_push, comm_password, start, end):
    zk = None
    pythoncom.CoInitialize()
    try:
        try: DIAG.write_text("", encoding="utf-8")
        except Exception: pass

        zk, serial = connect_zk(ip, port)
        dlog(f"Connected to {ip}:{port} SN={serial}")
        print(f"Connected. Device SN: {serial}")
        print("Reading logs ...")

        try: zk.EnableDevice(1, False)
        except Exception: pass

        logs = pull_logs(zk, start, end)
        print(f"Fetched {len(logs)} log(s). Deduplicating ...")

        deduped, keys = [], []
        for pin, dt_str, verify, status, work in logs:
            key = hash_key(serial, pin, dt_str)
            if not ledger_has(key):
                deduped.append((pin, dt_str, verify, status, work))
                keys.append(key)

        if not deduped:
            print("No new records to save.")
            return 0

        print(f"{len(deduped)} new record(s). Saving file ...")
        fpath = save_attlog_file(serial, deduped)
        print(f"Saved: {fpath}")

        for k in keys:
            ledger_add(k)

        pushed_ok = False
        if not no_push:
            print(f"Pushing {len(deduped)} record(s) to WDMS -> {wdms} ...")
            code, reason = replay_file_to_wdms(fpath, wdms, serial)
            print(f"POST {code} {reason}")
            pushed_ok = (200 <= code < 300)
            # If success, drop sidecar .sent marker for GUI Pulls manager
            if pushed_ok:
                sent_marker = fpath.with_suffix(fpath.suffix + ".sent")
                try:
                    sent_marker.write_text("ok", encoding="utf-8")
                except Exception:
                    pass

        if clear_after_push:
            if pushed_ok or no_push:
                try:
                    print("Clearing device logs ...")
                    ok = zk.ClearGLog(1)
                    print("ClearGLog:", "OK" if ok else "FAILED")
                except Exception as ex:
                    print(f"WARNING: ClearGLog failed: {ex}")
            else:
                print("NOTE: Not clearing logs because push did not return 2xx.")

        return len(deduped)
    finally:
        try:
            if zk is not None:
                try: zk.EnableDevice(1, True)
                except Exception: pass
                try: zk.Disconnect()
                except Exception: pass
                zk = None
        finally:
            pythoncom.CoUninitialize()

def main():
    ap = argparse.ArgumentParser(description="Pull logs from legacy ZKTeco via ZKEMKeeper.")
    ap.add_argument("--ip", required=True)
    ap.add_argument("--port", type=int, default=4370)
    ap.add_argument("--wdms", default=WDMS_BASE)
    ap.add_argument("--no-push", action="store_true")
    ap.add_argument("--clear-after-push", action="store_true")
    ap.add_argument("--comm-password", type=int, default=None)
    ap.add_argument("--from", dest="from_dt", help="Start datetime 'YYYY-MM-DD HH:MM:SS' (inclusive)")
    ap.add_argument("--to", dest="to_dt", help="End datetime 'YYYY-MM-DD HH:MM:SS' (inclusive)")
    args = ap.parse_args()

    ensure_dirs()
    print(f"Connecting to device {args.ip}:{args.port} ...")
    try:
        count = run_once(args.ip, args.port, args.wdms, args.no_push, args.clear_after_push,
                         args.comm_password, args.from_dt, args.to_dt)
    except Exception as ex:
        print(f"ERROR: {ex}")
        sys.exit(3)
    print("Done.")
    sys.exit(0 if count >= 0 else 1)

if __name__ == "__main__":
    main()
