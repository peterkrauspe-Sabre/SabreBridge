from pathlib import Path

src = Path(r"C:\SabreBridge\pulls\zk_diag_iter_ssr_ex.txt")
out = src.with_suffix(".attlog.txt")

def parse_line(s: str):
    # Typical forms: "PIN=1001  Time=2025-09-07 11:03:02  VerifyCode=1  WorkCode=0" (spacing varies)
    s = s.replace("\r","").strip()
    kv = {}
    for token in s.replace(",", " ").split():
        if "=" in token:
            k, _, v = token.partition("=")
            kv[k.strip().lower()] = v.strip()
    pin = kv.get("pin") or kv.get("userid") or kv.get("enrollnumber")
    ts  = kv.get("time") or kv.get("checktime") or kv.get("datetime")
    ver = kv.get("verifycode") or kv.get("verify") or kv.get("verifymode") or "0"
    wc  = kv.get("workcode") or ""
    if pin and ts:
        ts = ts.replace("/", "-")
        return f"{pin}\t{ts}\t{ver}\t0\t{wc}"
    return None

lines = []
for raw in src.read_text(encoding="utf-8", errors="ignore").splitlines():
    rec = parse_line(raw)
    if rec:
        lines.append(rec)

out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
print(f"Wrote {len(lines)} records to {out}")
