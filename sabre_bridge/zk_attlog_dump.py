# C:\SabreBridge\zk_attlog_dump.py
# Minimal diagnostics for UF200/MB10/F18 via ZKEMKeeper (32-bit).
# - shows record counts (SSR_GetDeviceDataCount)
# - tries multiple SSR_GetDeviceData field sets
# - primes full-range iterators and prints first few lines
# - tries multiple file-export names and writes what it gets
# Results are saved into C:\SabreBridge\pulls\zk_diag_*.txt

import sys
from pathlib import Path
from datetime import datetime

PULL_DIR = Path(r"C:\SabreBridge\pulls")
PULL_DIR.mkdir(parents=True, exist_ok=True)
DIAG = PULL_DIR / "zk_diag_log.txt"

def log(msg):
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} | {msg}\n"
    sys.stdout.write(line)
    sys.stdout.flush()
    with DIAG.open("a", encoding="utf-8") as f:
        f.write(line)

try:
    import win32com.client, pythoncom
except Exception as ex:
    print("ERROR: install pywin32 in 32-bit Python and run: python -m pywin32_postinstall -install")
    raise

def connect(ip, port):
    from win32com.client import gencache, Dispatch
    last = None
    for progid in ("zkemkeeper.ZKEM.1", "zkemkeeper.ZKEM"):
        try:
            try:
                zk = gencache.EnsureDispatch(progid)
            except Exception:
                zk = Dispatch(progid)
            ok = zk.Connect_Net(ip, port)
            if not ok:
                raise RuntimeError("Connect_Net failed")
            try: zk.SetCommPassword(0)
            except Exception: pass
            try: zk.MachineNumber = 1
            except Exception: pass
            try:
                sn = zk.GetSerialNumber()
            except Exception:
                try:
                    sn = zk.GetStrInfo(1)
                except Exception:
                    sn = ""
            if not sn:
                sn = f"ZK_{ip.replace('.', '-')}"
            return zk, sn
        except Exception as ex:
            last = ex
    raise RuntimeError(f"Could not instantiate ZKEMKeeper: {last}")

def ssr_count(zk, where):
    try:
        if hasattr(zk, "SSR_GetDeviceDataCount"):
            c = zk.SSR_GetDeviceDataCount(1, "ATTLOG", where)
            log(f"SSR_GetDeviceDataCount where='{where}': {c}")
            try:
                return int(c)
            except Exception:
                return 0
    except Exception as ex:
        log(f"SSR_GetDeviceDataCount error: {ex}")
    return -1

def try_ssr_getdevdata(zk):
    FIELD_SETS = [
        "Pin,CheckTime,VerifyCode,WorkCode",
        "PIN,Time,VerifyCode,WorkCode",
        "PIN,Time",
    ]
    tried = 0
    for fields in FIELD_SETS:
        try:
            txt = zk.SSR_GetDeviceData(1, "ATTLOG", fields, "", "")
            if not txt:
                log(f"SSR_GetDeviceData fields='{fields}' -> EMPTY")
                continue
            lines = [ln for ln in str(txt).splitlines() if ln.strip()]
            log(f"SSR_GetDeviceData fields='{fields}' -> {len(lines)} lines")
            out = PULL_DIR / ("zk_diag_ssr_" + fields.replace(",", "_").replace(" ", "") + ".txt")
            out.write_text(str(txt), encoding="utf-8", errors="ignore")
            log(f"  wrote: {out}")
            tried += len(lines)
        except Exception as ex:
            log(f"SSR_GetDeviceData fields='{fields}' error: {ex}")
    return tried

def try_iterators(zk):
    printed = 0
    # Full-span prime
    try:
        ok = zk.ReadTimeGLogData(1, "2000-01-01 00:00:00", "2099-12-31 23:59:59")
        log(f"ReadTimeGLogData full-span -> {ok}")
    except Exception as ex:
        log(f"ReadTimeGLogData error: {ex}")

    # Then read strings
    cap = []
    try:
        try: zk.ReadGeneralLogData(1)
        except Exception: pass
        for _ in range(50):  # sample up to 50 lines
            s = zk.GetGeneralLogDataStr(1)
            if not s: break
            cap.append(str(s))
        if cap:
            out = PULL_DIR / "zk_diag_iter_general_str.txt"
            out.write_text("\n".join(cap), encoding="utf-8", errors="ignore")
            log(f"GetGeneralLogDataStr lines: {len(cap)} -> {out}")
            printed += len(cap)
    except Exception as ex:
        log(f"GetGeneralLogDataStr error: {ex}")

    # SSR string ex
    cap2 = []
    try:
        try: zk.ReadAllGLogData(1)
        except Exception: pass
        for _ in range(50):
            s = zk.SSR_GetGeneralLogDataEx(1)
            if not s: break
            cap2.append(str(s))
        if cap2:
            out = PULL_DIR / "zk_diag_iter_ssr_ex.txt"
            out.write_text("\n".join(cap2), encoding="utf-8", errors="ignore")
            log(f"SSR_GetGeneralLogDataEx lines: {len(cap2)} -> {out}")
            printed += len(cap2)
    except Exception as ex:
        log(f"SSR_GetGeneralLogDataEx error: {ex}")
    return printed

def try_file_exports(zk):
    # Try multiple canonical file names (firmware differs)
    names = ["attlog.dat", "ATTLOG.dat", "ATTLOG.TXT", "attlog.txt"]
    total = 0
    for name in names:
        out = PULL_DIR / f"zk_diag_export_{name}"
        try:
            if out.exists():
                out.unlink()
        except Exception:
            pass
        ok = False
        try:
            ok = zk.GetDataFile(1, name, str(out))
            log(f"GetDataFile('{name}') -> {ok} path={out}")
        except Exception as ex:
            log(f"GetDataFile('{name}') error: {ex}")
        if ok and out.exists() and out.stat().st_size > 0:
            size = out.stat().st_size
            log(f"  wrote {size} bytes to {out}")
            total += size
    return total

def main():
    if len(sys.argv) < 3:
        print("Usage: python zk_attlog_dump.py <ip> <port>")
        sys.exit(2)

    ip = sys.argv[1]
    port = int(sys.argv[2])

    DIAG.write_text("", encoding="utf-8")  # reset
    pythoncom.CoInitialize()
    zk = None
    try:
        log(f"Connecting to {ip}:{port} …")
        zk, sn = connect(ip, port)
        log(f"Connected. SN={sn}")

        # Counts
        c_all = ssr_count(zk, "")
        c_rng = ssr_count(zk, "CheckTime>='2000-01-01 00:00:00' and CheckTime<='2099-12-31 23:59:59'")
        log(f"Counts — all:{c_all}  ranged:{c_rng}")

        # Try SSR_GetDeviceData (writes raw text files)
        try:
            try: zk.EnableDevice(1, False)
            except Exception: pass
            got = try_ssr_getdevdata(zk)
        finally:
            try: zk.EnableDevice(1, True)
            except Exception: pass

        # Try iterator/string readers (writes raw text files)
        printed = try_iterators(zk)

        # Try file exports (writes raw files)
        exported = try_file_exports(zk)

        log(f"SUMMARY: ssr_lines={got}  iter_lines={printed}  exported_bytes={exported}")
        print("Done. Check C:\\SabreBridge\\pulls for files named zk_diag_* and zk_diag_log.txt.")
    finally:
        try:
            if zk is not None:
                try: zk.Disconnect()
                except Exception: pass
                zk = None
        finally:
            pythoncom.CoUninitialize()

if __name__ == "__main__":
    main()
