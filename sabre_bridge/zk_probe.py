import win32com.client, pythoncom, inspect

try:
    zk = win32com.client.Dispatch("zkemkeeper.ZKEM.1")
except Exception:
    zk = win32com.client.Dispatch("zkemkeeper.ZKEM")

print("Available methods on ZKEMKeeper:")
for name in dir(zk):
    if not name.startswith("_"):
        try:
            attr = getattr(zk, name)
            if callable(attr):
                print("METHOD:", name)
            else:
                print("PROP:", name)
        except Exception as ex:
            print("ERR on", name, ":", ex)

print("\nNow testing which log functions exist:")
for candidate in ["SSR_GetGeneralLogData", "GetGeneralLogData", "ReadGeneralLogData", "GetSuperLogData", "SSR_GetSuperLogData"]:
    if hasattr(zk, candidate):
        print(" ✔", candidate, "is available")
    else:
        print(" ✘", candidate, "not found")
