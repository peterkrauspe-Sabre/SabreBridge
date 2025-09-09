try:
    with MAIN_LOG.open("a", encoding="utf-8") as f:
        f.write(time.strftime("%Y-%m-%d %H:%M:%S") + " [INFO] gui: GUI started\n")
except Exception:
    pass
