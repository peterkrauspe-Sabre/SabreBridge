from __future__ import annotations
import os, sys, re, socket, time, threading, subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import yaml

try:
    import httpx
except Exception:
    httpx = None

# ---------- Layout ----------
PKG_DIR    = Path(__file__).resolve().parent
BRIDGE_DIR = PKG_DIR.parent
LOG_DIR    = BRIDGE_DIR / "logs"
PULL_DIR   = BRIDGE_DIR / "pulls"
DEFAULT_CFG = BRIDGE_DIR / "config.yaml"
MAIN_LOG    = LOG_DIR / "sabre_bridge.log"
SCHED_LOG   = LOG_DIR / "zk_scheduler.log"
DEFAULT_WDMS = "http://cloud.sabreproducts.com:81/iclock"

LOG_DIR.mkdir(parents=True, exist_ok=True)
PULL_DIR.mkdir(parents=True, exist_ok=True)
for _p in (MAIN_LOG, SCHED_LOG):
    if not _p.exists():
        _p.write_text("", encoding="utf-8")

# lazy import zk_scheduler to tolerate path moves
try:
    from .zk_scheduler import get_scheduler, ZKDevice
except Exception:
    import importlib.util
    zp = PKG_DIR / "zk_scheduler.py"
    spec = importlib.util.spec_from_file_location("zk_scheduler", str(zp))
    mod = importlib.module_from_spec(spec)  # type: ignore
    spec.loader.exec_module(mod)            # type: ignore
    get_scheduler, ZKDevice = mod.get_scheduler, mod.ZKDevice

@dataclass
class Row:
    source: str
    name_or_sn: str
    ip: str
    port: str
    enabled: bool
    interval_min: str
    key: str
    subtype: str

FILTER_TAGS = {
    "All": None,
    "ZKLegacy Device": "zklegacy",
    "ZKCloud Device": "zkcloud",
    "Hikvision Device": "hikvision",
    "Dahua Device": "dahua",
}

def _now() -> datetime:
    return datetime.utcnow()

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sabre Bridge")
        self.geometry("1400x940")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.cfg_path: Path = DEFAULT_CFG
        self.cfg: dict = {}

        # Top filters
        self.filter_var = tk.StringVar(value="All")
        self.show_relay_lines = tk.BooleanVar(value=True)
        self.show_wdms_lines  = tk.BooleanVar(value=True)

        # Settings state
        self.v_wdms_url  = tk.StringVar(value=DEFAULT_WDMS)
        self.v_wdms_user = tk.StringVar(value="")
        self.v_wdms_pass = tk.StringVar(value="")
        self.v_test_status = tk.StringVar(value="")
        self.v_monitor_min = tk.StringVar(value="5")

        # Heartbeat controls (Legacy ZK)
        self.v_hb_enabled = tk.BooleanVar(value=False)
        self.v_hb_min     = tk.StringVar(value="5")

        # Relay / Scheduler autostart flags
        self.v_relay_autostart = tk.BooleanVar(value=True)
        self.v_sched_autostart = tk.BooleanVar(value=False)

        # runtime
        self.monitor_thread: threading.Thread | None = None
        self.monitor_stop = threading.Event()
        self.last_seen: dict[str, datetime] = {}

        self.tail_stop = threading.Event()
        self.tail_thread: threading.Thread | None = None
        self.selected_keys: set[str] = set()

        # relay process handle (if spawned by GUI)
        self._relay_proc: subprocess.Popen | None = None

        self._build_menu()
        self._build_ui()
        self._init_tree_tags()

        # Write a boot banner to logs so you see life immediately
        try:
            with MAIN_LOG.open("a", encoding="utf-8") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S") + " [INFO] gui: GUI started\n")
        except Exception:
            pass

        self.load_cfg(self.cfg_path)
        self._start_tail()
        self._start_monitor()

        # Auto-start relay & scheduler as requested
        relay_cfg = self.cfg.get("relay") or {}
        if bool(relay_cfg.get("enabled", True)) and bool(self.v_relay_autostart.get()):
            self._start_relay()
        if bool(self.v_sched_autostart.get()):
            sch = get_scheduler()
            if any(d.enabled for d in sch.devices):
                self._start_sched()

    # ----------------- Menu -----------------
    def _build_menu(self):
        m = tk.Menu(self)
        filem = tk.Menu(m, tearoff=0)
        filem.add_command(label="Open config…", command=self._open_config)
        filem.add_command(label="Open bridge folder", command=lambda: self._open_path(BRIDGE_DIR))
        filem.add_command(label="Open logs folder",   command=lambda: self._open_path(LOG_DIR))
        filem.add_separator()
        filem.add_command(label="Exit", command=self.on_close)
        m.add_cascade(label="File", menu=filem)
        self.config(menu=m)

    # ----------------- UI -----------------
    def _build_ui(self):
        self.nb = ttk.Notebook(self); self.nb.pack(fill="both", expand=True)

        # Devices tab
        self.page_devices = ttk.Frame(self.nb); self.nb.add(self.page_devices, text="Devices")
        top = ttk.Frame(self.page_devices); top.pack(fill="x", padx=8, pady=6)
        self.lbl_cfg = ttk.Label(top, text=f"Config: {self.cfg_path}"); self.lbl_cfg.pack(side="left", padx=6)
        self.lbl_wdms = ttk.Label(top, text="WDMS: (loading...)"); self.lbl_wdms.pack(side="left", padx=12)
        self.lbl_relay = ttk.Label(top, text="Relay: (loading...)"); self.lbl_relay.pack(side="left", padx=12)
        self.lbl_sched = ttk.Label(top, text="ZKLegacy Scheduler: (stopped)"); self.lbl_sched.pack(side="left", padx=12)

        paned = ttk.Panedwindow(self.page_devices, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=8)

        left = ttk.Frame(paned); paned.add(left, weight=2)
        qf = ttk.Frame(left); qf.pack(fill="x", pady=(0,4))
        ttk.Label(qf, text="Quick filter:").pack(side="left", padx=(0,6))
        for label in ["All","ZKLegacy Device","ZKCloud Device","Hikvision Device","Dahua Device"]:
            ttk.Radiobutton(qf, text=label, value=label, variable=self.filter_var,
                            command=self._refresh_tail).pack(side="left", padx=6)

        cols = ("source","name","ip","port","enabled","interval")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", height=18, selectmode="extended")
        for c, w in (("source",170),("name",270),("ip",160),("port",70),("enabled",80),("interval",100)):
            self.tree.heading(c, text=c.upper()); self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._on_select_rows())

        lbtn = ttk.Frame(left); lbtn.pack(fill="x", pady=6)
        ttk.Button(lbtn, text="Add ZKLegacy Device", command=self._dev_add_zk).pack(side="left", padx=2)
        ttk.Button(lbtn, text="Remove Selected (ZK only)", command=self._dev_remove_selected_zk).pack(side="left", padx=6)
        ttk.Separator(lbtn, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(lbtn, text="Add Other Devices", command=self._dev_add_relay).pack(side="left", padx=6)
        ttk.Button(lbtn, text="Remove Selected (Other)", command=self._dev_remove_selected_relay).pack(side="left", padx=6)
        ttk.Separator(lbtn, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(lbtn, text="Start Scheduler", command=self._start_sched).pack(side="left", padx=6)
        ttk.Button(lbtn, text="Stop Scheduler",  command=self._stop_sched).pack(side="left", padx=6)
        ttk.Button(lbtn, text="Open pulls folder", command=lambda: self._open_path(PULL_DIR)).pack(side="left", padx=6)

        right = ttk.Frame(paned); paned.add(right, weight=3)
        editor = ttk.LabelFrame(right, text="Device Settings"); editor.pack(fill="x", padx=2, pady=(0,8))
        grid = ttk.Frame(editor); grid.pack(fill="x", padx=6, pady=6)
        r = 0
        ttk.Label(grid, text="32-bit Python path:").grid(row=r, column=0, sticky="e", padx=4, pady=2)
        self.e_py32 = ttk.Entry(grid, width=60); self.e_py32.grid(row=r, column=1, sticky="we", padx=4, pady=2); r += 1
        ttk.Label(grid, text="Default WDMS URL:").grid(row=r, column=0, sticky="e", padx=4, pady=2)
        self.e_wdms = ttk.Entry(grid, width=60); self.e_wdms.grid(row=r, column=1, sticky="we", padx=4, pady=2); r += 1
        self.v_auto_reg = tk.BooleanVar(value=True)
        ttk.Checkbutton(grid, text="Auto-register device on WDMS after push (ZKLegacy)", variable=self.v_auto_reg).grid(row=r, column=1, sticky="w", padx=4, pady=2); r += 1
        ttk.Separator(editor).pack(fill="x", pady=6)

        # editor fields (populated on selection)
        form = ttk.Frame(editor); form.pack(fill="x", padx=6, pady=6)
        self.e_name = ttk.Entry(form); self.e_ip = ttk.Entry(form); self.e_port = ttk.Entry(form)
        self.v_enabled = tk.BooleanVar(value=True); self.chk_enabled = ttk.Checkbutton(form, variable=self.v_enabled)
        self.e_interval = ttk.Entry(form)
        self.v_clear = tk.BooleanVar(value=True); self.chk_clear = ttk.Checkbutton(form, variable=self.v_clear)
        self.e_wdms_dev = ttk.Entry(form); self.e_note = ttk.Entry(form)
        self.e_alias_sn = ttk.Entry(form)

        ctrl = ttk.Frame(editor); ctrl.pack(fill="x", pady=6)
        ttk.Button(ctrl, text="Save settings", command=self._save_everything).pack(side="left", padx=4)
        ttk.Button(ctrl, text="Run selected now (ZK)", command=self._run_selected_now).pack(side="left", padx=4)

        logbox = ttk.LabelFrame(right, text="Logs (device-aware)")
        logbox.pack(fill="both", expand=True, padx=2, pady=(0,2))
        filters = ttk.Frame(logbox); filters.pack(fill="x")
        ttk.Checkbutton(filters, text="Include ZKCloud/Relay", variable=self.show_relay_lines, command=self._refresh_tail).pack(side="left", padx=6)
        ttk.Checkbutton(filters, text="Include WDMS",        variable=self.show_wdms_lines,  command=self._refresh_tail).pack(side="left", padx=6)
        frm = ttk.Frame(logbox); frm.pack(fill="both", expand=True)
        self.txt_logs = tk.Text(frm, height=18, wrap="none"); self.txt_logs.pack(fill="both", expand=True, side="left")
        sbs = ttk.Scrollbar(frm, command=self.txt_logs.yview); sbs.pack(side="right", fill="y")
        self.txt_logs["yscrollcommand"] = sbs.set

        # Relay/WDMS tab
        self.page_relay = ttk.Frame(self.nb); self.nb.add(self.page_relay, text="Relay / WDMS")
        hdr = ttk.Frame(self.page_relay); hdr.pack(fill="x", padx=8, pady=6)
        self.lbl_relay2 = ttk.Label(hdr, text="Relay: (loading...)"); self.lbl_relay2.pack(side="left", padx=6)
        self.lbl_wdms2  = ttk.Label(hdr, text="WDMS: (loading...)");  self.lbl_wdms2.pack(side="left", padx=12)
        ttk.Button(hdr, text="Open sabre_bridge.log", command=lambda: self._open_path(MAIN_LOG)).pack(side="right", padx=6)
        rbox = ttk.LabelFrame(self.page_relay, text="Relay/WDMS log tail")
        rbox.pack(fill="both", expand=True, padx=8, pady=8)
        self.txt_relay = tk.Text(rbox, height=28, wrap="none"); self.txt_relay.pack(fill="both", expand=True, side="left")
        sbs2 = ttk.Scrollbar(rbox, command=self.txt_relay.yview); sbs2.pack(side="right", fill="y")
        self.txt_relay["yscrollcommand"] = sbs2.set

        # Settings tab
        self.page_settings = ttk.Frame(self.nb); self.nb.add(self.page_settings, text="Settings")

        # WDMS & Monitoring
        s_top = ttk.LabelFrame(self.page_settings, text="WDMS & Monitoring"); s_top.pack(fill="x", padx=8, pady=8)
        gs = ttk.Frame(s_top); gs.pack(fill="x", padx=8, pady=8)
        rr = 0
        ttk.Label(gs, text="WDMS URL:").grid(row=rr, column=0, sticky="e", padx=4, pady=4)
        e_url = ttk.Entry(gs, textvariable=self.v_wdms_url, width=70); e_url.grid(row=rr, column=1, sticky="we", padx=4, pady=4); rr += 1
        ttk.Label(gs, text="Username:").grid(row=rr, column=0, sticky="e", padx=4, pady=4)
        e_user = ttk.Entry(gs, textvariable=self.v_wdms_user, width=40); e_user.grid(row=rr, column=1, sticky="w", padx=4, pady=4); rr += 1
        ttk.Label(gs, text="Password:").grid(row=rr, column=0, sticky="e", padx=4, pady=4)
        e_pass = ttk.Entry(gs, textvariable=self.v_wdms_pass, width=40, show="*"); e_pass.grid(row=rr, column=1, sticky="w", padx=4, pady=4); rr += 1
        ttk.Label(gs, text="Monitor interval (minutes):").grid(row=rr, column=0, sticky="e", padx=4, pady=4)
        e_mon = ttk.Entry(gs, textvariable=self.v_monitor_min, width=8); e_mon.grid(row=rr, column=1, sticky="w", padx=4, pady=4); rr += 1

        # Heartbeat config
        hb_fr = ttk.LabelFrame(self.page_settings, text="Legacy ZK Heartbeat (show device online on WDMS)")
        hb_fr.pack(fill="x", padx=8, pady=(0,8))
        hb_g = ttk.Frame(hb_fr); hb_g.pack(fill="x", padx=8, pady=6)
        ttk.Checkbutton(hb_g, text="Enable heartbeat", variable=self.v_hb_enabled).grid(row=0, column=0, sticky="w", padx=4, pady=4)
        ttk.Label(hb_g, text="Heartbeat interval (minutes):").grid(row=0, column=1, sticky="e", padx=4, pady=4)
        e_hb = ttk.Entry(hb_g, textvariable=self.v_hb_min, width=8); e_hb.grid(row=0, column=2, sticky="w", padx=4, pady=4)

        # Relay controls
        relay_fr = ttk.LabelFrame(self.page_settings, text="Relay (ZKCloud / Hikvision / Dahua Proxy)")
        relay_fr.pack(fill="x", padx=8, pady=(0,8))
        rgrid = ttk.Frame(relay_fr); rgrid.pack(fill="x", padx=8, pady=6)
        ttk.Checkbutton(rgrid, text="Enable Relay at startup", variable=self.v_relay_autostart).grid(row=0, column=0, sticky="w", padx=4, pady=4)
        ttk.Button(rgrid, text="Test Relay health", command=self._test_relay_health).grid(row=0, column=1, sticky="w", padx=6, pady=4)
        ttk.Button(rgrid, text="Start Relay", command=self._start_relay).grid(row=0, column=2, sticky="w", padx=6, pady=4)
        ttk.Button(rgrid, text="Stop Relay",  command=self._stop_relay).grid(row=0, column=3, sticky="w", padx=6, pady=4)
        ttk.Button(rgrid, text="Open relay log", command=lambda: self._open_path(MAIN_LOG)).grid(row=0, column=4, sticky="w", padx=12, pady=4)

        # Scheduler controls
        sched_fr = ttk.LabelFrame(self.page_settings, text="ZKLegacy Scheduler")
        sched_fr.pack(fill="x", padx=8, pady=(0,8))
        sgrid = ttk.Frame(sched_fr); sgrid.pack(fill="x", padx=8, pady=6)
        ttk.Checkbutton(sgrid, text="Auto-start scheduler on launch", variable=self.v_sched_autostart).grid(row=0, column=0, sticky="w", padx=4, pady=4)
        ttk.Button(sgrid, text="Start Scheduler", command=self._start_sched).grid(row=0, column=1, sticky="w", padx=6, pady=4)
        ttk.Button(sgrid, text="Stop Scheduler",  command=self._stop_sched).grid(row=0, column=2, sticky="w", padx=6, pady=4)
        ttk.Button(sgrid, text="Open scheduler log", command=lambda: self._open_path(SCHED_LOG)).grid(row=0, column=3, sticky="w", padx=12, pady=4)

        # Pulls manager
        pulls_fr = ttk.LabelFrame(self.page_settings, text="Legacy ZK Pulls (.attlog.txt)")
        pulls_fr.pack(fill="both", expand=True, padx=8, pady=(0,8))
        pf = ttk.Frame(pulls_fr); pf.pack(fill="x", padx=8, pady=6)
        ttk.Button(pf, text="Refresh list", command=self._pulls_refresh).pack(side="left", padx=4)
        ttk.Button(pf, text="Open selected", command=self._pulls_open_selected).pack(side="left", padx=4)
        ttk.Button(pf, text="Resend selected", command=self._pulls_resend_selected).pack(side="left", padx=4)
        ttk.Button(pf, text="Resend ALL Not-Sent", command=self._pulls_resend_all_unsent).pack(side="left", padx=12)
        ttk.Button(pf, text="Open pulls folder", command=lambda: self._open_path(PULL_DIR)).pack(side="left", padx=12)

        self.pull_cols = ("filename","sn","size","mtime","sent")
        self.pull_list = ttk.Treeview(pulls_fr, columns=self.pull_cols, show="headings", height=12, selectmode="extended")
        for c, w in (("filename",420),("sn",210),("size",90),("mtime",180),("sent",90)):
            self.pull_list.heading(c, text=c.upper()); self.pull_list.column(c, width=w, anchor="w")
        self.pull_list.pack(fill="both", expand=True, padx=8, pady=(0,8))
        self._pulls_refresh()

    def _init_tree_tags(self):
        self.tree.tag_configure("online",  foreground="#008000")
        self.tree.tag_configure("offline", foreground="#000000")

    # ----------------- Config -----------------
    def load_cfg(self, path: Path):
        try:
            self.cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            self.cfg_path = path
            self.lbl_cfg.configure(text=f"Config: {self.cfg_path}")
        except Exception as ex:
            messagebox.showerror("Config error", f"Failed to read:\n{path}\n\n{ex}")
            self.cfg = {}

        # App flags
        app_cfg = self.cfg.get("app") or {}
        self.v_relay_autostart.set(bool(app_cfg.get("relay_autostart", True)))
        self.v_sched_autostart.set(bool(app_cfg.get("scheduler_autostart", False)))

        # WDMS base
        wdms = (self.cfg.get("wdms_url")
                or (self.cfg.get("legacy_pull") or {}).get("wdms_url")
                or DEFAULT_WDMS)
        self.v_wdms_url.set(wdms)
        self.lbl_wdms.configure(text=f"WDMS: {wdms}")
        self.lbl_wdms2.configure(text=f"WDMS: {wdms}")
        auth = self.cfg.get("wdms_auth") or {}
        self.v_wdms_user.set(auth.get("username",""))
        self.v_wdms_pass.set(auth.get("password",""))

        # monitor
        mon = (self.cfg.get("monitor") or {}).get("interval_min", 5)
        try: self.v_monitor_min.set(str(int(mon)))
        except: self.v_monitor_min.set("5")

        # heartbeat
        hb = (self.cfg.get("legacy_pull") or {}).get("heartbeat") or {}
        self.v_hb_enabled.set(bool(hb.get("enabled", False)))
        try: self.v_hb_min.set(str(int(hb.get("interval_min", 5))))
        except: self.v_hb_min.set("5")

        # relay summary label (live color will refresh via monitor)
        r = self.cfg.get("relay") or {}
        relay_on = bool(r.get("enabled", r.get("auto_add", False)))
        relay_port = r.get("port", 9090)
        self.lbl_relay.configure(text=f"Relay: {'ON' if relay_on else 'OFF'} (port {relay_port})")
        self.lbl_relay2.configure(text=f"Relay: {'ON' if relay_on else 'OFF'} (port {relay_port})")

        # scheduler defaults into editor
        sch = get_scheduler()
        sch.load_from_config()
        self.e_py32.delete(0, "end"); self.e_py32.insert(0, sch.py32)
        self.e_wdms.delete(0, "end"); self.e_wdms.insert(0, sch.wdms_default)
        self.v_auto_reg.set(bool(sch.auto_register))

        self._rebuild_table()
        self._refresh_tail()
        self._refresh_relay_tab()

    def _persist_cfg(self):
        try:
            self.cfg_path.write_text(yaml.safe_dump(self.cfg, sort_keys=False), encoding="utf-8")
            return True
        except Exception as ex:
            messagebox.showerror("Save config", f"Could not write config:\n{ex}")
            return False

    # ----------------- Save settings -----------------
    def _save_everything(self):
        # scheduler config
        sch = get_scheduler()
        sch.py32 = self.e_py32.get().strip() or sch.py32
        sch.wdms_default = self.e_wdms.get().strip() or sch.wdms_default
        sch.auto_register = bool(self.v_auto_reg.get())

        # heartbeat -> scheduler
        try: hb_min = int(self.v_hb_min.get().strip() or "5")
        except: hb_min = 5
        sch.hb_enabled = bool(self.v_hb_enabled.get())
        sch.hb_interval_min = hb_min

        # devices from table (keep non-selected as-is)
        rows = self._table_rows()
        new_devs: list[ZKDevice] = []
        for row in rows:
            if row.source == "ZKLegacy Device":
                if row.key in self.selected_keys:
                    name = self.e_name.get().strip() or row.name_or_sn
                    ip = self.e_ip.get().strip() or row.ip
                    port = int(self.e_port.get().strip() or (row.port or "4370"))
                    enabled = bool(self.v_enabled.get())
                    interval = int(self.e_interval.get().strip() or "5")
                    clear = bool(self.v_clear.get())
                    wdms_dev = self.e_wdms_dev.get().strip() or None
                    note = self.e_note.get().strip() or ""
                    new_devs.append(ZKDevice(name=name, ip=ip, port=port, enabled=enabled,
                                             interval_min=interval, clear_after_push=clear,
                                             wdms_url=wdms_dev, note=note))
                else:
                    idx = int(row.key)
                    new_devs.append(get_scheduler().devices[idx])
        sch.devices = new_devs
        sch.save_to_config()

        # persist WDMS URL, auth, monitor, heartbeat block, autostart flags
        url = (self.v_wdms_url.get() or "").strip()
        if not url:
            messagebox.showwarning("Save Settings", "WDMS URL cannot be empty."); return
        self.cfg["wdms_url"] = url
        self.cfg["wdms_auth"] = {"username": self.v_wdms_user.get() or "", "password": self.v_wdms_pass.get() or ""}
        try: mi = int(self.v_monitor_min.get().strip() or "5")
        except: mi = 5
        self.cfg.setdefault("monitor", {})["interval_min"] = mi

        self.cfg.setdefault("legacy_pull", {}).setdefault("heartbeat", {})
        self.cfg["legacy_pull"]["heartbeat"]["enabled"] = bool(self.v_hb_enabled.get())
        self.cfg["legacy_pull"]["heartbeat"]["interval_min"] = hb_min

        self.cfg.setdefault("app", {})
        self.cfg["app"]["relay_autostart"] = bool(self.v_relay_autostart.get())
        self.cfg["app"]["scheduler_autostart"] = bool(self.v_sched_autostart.get())

        if self._persist_cfg():
            self.lbl_wdms.configure(text=f"WDMS: {url}")
            self.lbl_wdms2.configure(text=f"WDMS: {url}")
            messagebox.showinfo("Saved", "Settings saved to config.yaml.")
            # refresh labels
            self._refresh_relay_label()

    # ----------------- Devices table -----------------
    def _rebuild_table(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        rows = self._table_rows()
        for row in rows:
            iid = row.key
            self.tree.insert("", "end", iid=iid,
                             values=(row.source, row.name_or_sn, row.ip, row.port,
                                     "Yes" if row.enabled else "No", row.interval_min),
                             tags=("offline",))
        if rows:
            self.tree.selection_set(rows[0].key)
            self._on_select_rows()

    def _table_rows(self) -> list[Row]:
        rows = []
        sch = get_scheduler()
        for idx, d in enumerate(sch.devices):
            rows.append(Row("ZKLegacy Device", d.name, d.ip, str(d.port), d.enabled,
                            str(d.interval_min), str(idx), "ZK"))
        r = self.cfg.get("relay") or {}
        devmap = r.get("device_sn_map") or {}
        relay_port = str(r.get("port", 9090))
        seen = set()
        for sn in sorted(devmap.keys()):
            if sn in seen: continue
            seen.add(sn)
            subtype = "ZKCloud"
            usn = (sn or "").upper()
            if usn.startswith("HIK"):   subtype = "Hikvision"
            elif usn.startswith("DAHUA"): subtype = "Dahua"
            rows.append(Row(f"ZKCloud Device-{subtype}", sn, "", relay_port, True, "-", sn, subtype))
        for dev in (r.get("devices") or []):
            sn = str(dev.get("sn") or dev.get("serial") or "").strip()
            if not sn or sn in seen: continue
            seen.add(sn)
            kind = (dev.get("type") or "ZKCloud")
            if kind.lower() == "hik": kind = "Hikvision"
            elif kind.lower() == "dahua": kind = "Dahua"
            rows.append(Row(f"ZKCloud Device-{kind}", sn, str(dev.get("ip","")), str(dev.get("port", relay_port)),
                            bool(dev.get("enabled", True)), "-", sn, kind))
        return rows

    def _on_select_rows(self):
        self.selected_keys = set(self.tree.selection())
        self._populate_editor()
        self._refresh_tail()

    def _populate_editor(self):
        for e in [self.e_name, self.e_ip, self.e_port, self.e_interval, self.e_wdms_dev, self.e_note, self.e_alias_sn]:
            e.delete(0, "end")
        self.v_enabled.set(True); self.v_clear.set(True)
        for w in (self.e_name, self.e_ip, self.e_port, self.chk_enabled, self.e_interval,
                  self.chk_clear, self.e_wdms_dev, self.e_note, self.e_alias_sn):
            w.grid_forget()

        rows = self._table_rows()
        selected = [r for r in rows if r.key in self.selected_keys]

        def put(lbl, widget, row):
            ttk.Label(self.e_name.master, text=lbl + ":").grid(row=row, column=0, sticky="e", padx=4, pady=3)
            widget.grid(row=row, column=1, sticky="we", padx=4, pady=3)

        if len(selected) == 1:
            row = selected[0]
            if row.source == "ZKLegacy Device":
                self.e_name.insert(0, row.name_or_sn); put("Name", self.e_name, 0)
                self.e_ip.insert(0, row.ip);          put("IP", self.e_ip, 1)
                self.e_port.insert(0, row.port);      put("Port", self.e_port, 2)
                self.v_enabled.set(row.enabled);      put("Enabled", self.chk_enabled, 3)
                self.e_interval.insert(0, row.interval_min if row.interval_min != "-" else "5"); put("Interval (min)", self.e_interval, 4)
                self.v_clear.set(True);               put("Clear after push", self.chk_clear, 5)
                self.e_wdms_dev.insert(0, "");        put("WDMS URL (override)", self.e_wdms_dev, 6)
                self.e_note.insert(0, "");            put("Note", self.e_note, 7)
            else:
                put("Relay Serial (read-only)", ttk.Label(self.e_name.master, text=row.name_or_sn), 0)
                self.e_alias_sn.insert(0, self._current_alias_for(row.name_or_sn))
                put("Alias SN to push as", self.e_alias_sn, 1)
        else:
            if selected and all(s.source.startswith("ZKCloud Device") for s in selected):
                put("Alias SN to push as (applies to all selected)", self.e_alias_sn, 0)

        self.e_name.master.columnconfigure(1, weight=1)

    def _current_alias_for(self, sn: str) -> str:
        r = self.cfg.get("relay") or {}
        return str((r.get("device_sn_map") or {}).get(sn, ""))

    # ----------------- Add / Remove -----------------
    def _dev_add_zk(self):
        sch = get_scheduler()
        sch.devices.append(ZKDevice(name="New ZKLegacy", ip="192.168.1.100"))
        sch.save_to_config()
        self.load_cfg(self.cfg_path)
        idx = len(sch.devices) - 1
        self.tree.selection_set(str(idx))
        self._on_select_rows()

    def _dev_remove_selected_zk(self):
        sels = [s for s in self.tree.selection() if s.isdigit()]
        if not sels: return
        sch = get_scheduler()
        keep = []
        for i, d in enumerate(sch.devices):
            if str(i) not in sels:
                keep.append(d)
        sch.devices = keep
        sch.save_to_config()
        self.load_cfg(self.cfg_path)
        messagebox.showinfo("Removed", f"Removed {len(sels)} ZKLegacy device(s).")

    def _dev_add_relay(self):
        dlg = tk.Toplevel(self); dlg.title("Add Other Devices"); dlg.resizable(False, False)
        frm = ttk.Frame(dlg, padding=10); frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Serial (SN):").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        e_sn = ttk.Entry(frm, width=36); e_sn.grid(row=0, column=1, padx=4, pady=4)
        ttk.Label(frm, text="Type:").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        cb_type = ttk.Combobox(frm, values=["ZKCloud","Hikvision","Dahua"], width=14, state="readonly")
        cb_type.set("ZKCloud"); cb_type.grid(row=1, column=1, sticky="w", padx=4, pady=4)
        ttk.Label(frm, text="IP (optional):").grid(row=2, column=0, sticky="e", padx=4, pady=4)
        e_ip = ttk.Entry(frm, width=20); e_ip.grid(row=2, column=1, sticky="w", padx=4, pady=4)
        ttk.Label(frm, text="Port (relay listens):").grid(row=3, column=0, sticky="e", padx=4, pady=4)
        e_port = ttk.Entry(frm, width=8); e_port.insert(0, "9090"); e_port.grid(row=3, column=1, sticky="w", padx=4, pady=4)
        v_en = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text="Enabled", variable=v_en).grid(row=4, column=1, sticky="w", padx=4, pady=4)
        btns = ttk.Frame(frm); btns.grid(row=5, column=0, columnspan=2, pady=(8,4))
        def ok():
            sn = e_sn.get().strip(); kind = cb_type.get().strip(); ip = e_ip.get().strip()
            port = int(e_port.get().strip() or "9090")
            if not sn: messagebox.showwarning("Add", "Serial is required."); return
            cfg = self.cfg; relay = cfg.setdefault("relay", {}); devs = relay.setdefault("devices", [])
            k = {"ZKCloud":"ZKCloud", "Hikvision":"Hikvision", "Dahua":"Dahua"}[kind]
            devs.append({"sn": sn, "type": k, "ip": ip, "port": port, "enabled": bool(v_en.get())})
            if self._persist_cfg():
                dlg.destroy(); self.load_cfg(self.cfg_path)
        ttk.Button(btns, text="Add", command=ok).pack(side="left", padx=6)
        ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side="left", padx=6)
        dlg.grab_set(); self.wait_window(dlg)

    def _dev_remove_selected_relay(self):
        sels = [s for s in self.tree.selection() if not s.isdigit()]
        if not sels: return
        relay = self.cfg.get("relay") or {}
        devs = relay.get("devices") or []
        before = len(devs)
        devs = [d for d in devs if str(d.get("sn") or d.get("serial")) not in sels]
        relay["devices"] = devs
        self.cfg["relay"] = relay
        if self._persist_cfg():
            self.load_cfg(self.cfg_path)
            messagebox.showinfo("Removed", f"Removed {before-len(devs)} device(s).")

    # ----------------- Save rows -----------------
    def _save_everything_rows(self):
        pass  # kept for future granular persistence

    # ----------------- Run once -----------------
    def _run_selected_now(self):
        sels = self.tree.selection()
        if not sels:
            messagebox.showwarning("Run now", "Select a ZKLegacy device.")
            return
        sch = get_scheduler()
        any_queued = False
        for key in sels:
            if key.isdigit():
                idx = int(key)
                if 0 <= idx < len(sch.devices):
                    sch.devices[idx].last_run = 0
                    any_queued = True
        if any_queued:
            self._start_sched()
            messagebox.showinfo("Run now", "Queued selected ZKLegacy device(s).")
        else:
            messagebox.showwarning("Run now", "No ZKLegacy devices selected.")

    # ----------------- Start/Stop scheduler -----------------
    def _start_sched(self):
        get_scheduler().start()
        self.lbl_sched.configure(text="ZKLegacy Scheduler: running")

    def _stop_sched(self):
        get_scheduler().stop()
        self.lbl_sched.configure(text="ZKLegacy Scheduler: stopped")

    # ----------------- Tail logs -----------------
    def _start_tail(self):
        if self.tail_thread and self.tail_thread.is_alive(): return
        self.tail_stop.clear()
        self.tail_thread = threading.Thread(target=self._tail_loop, daemon=True)
        self.tail_thread.start()

    def _tail_loop(self):
        last_m = last_s = 0
        while not self.tail_stop.is_set():
            try:
                m = MAIN_LOG.stat().st_size if MAIN_LOG.exists() else 0
                s = SCHED_LOG.stat().st_size if SCHED_LOG.exists() else 0
                if m != last_m or s != last_s:
                    last_m, last_s = m, s
                    self._refresh_tail()
                    self._refresh_relay_tab()
                time.sleep(1.0)
            except Exception:
                time.sleep(2.0)

    def _match_device_line(self, ln: str, selected_rows: list[Row], quick: str | None) -> bool:
        L = ln.lower()
        if quick == "zkcloud" and "relay" not in L and "/iclock" not in L:
            return False
        if quick == "hikvision" and "hik" not in L:
            return False
        if quick == "dahua" and "dahua" not in L:
            return False
        if not self.show_relay_lines.get() and ("relay" in L or "/iclock" in L):
            return False
        if not self.show_wdms_lines.get() and ("zkpush" in L or "/iclock" in L):
            return False
        if not selected_rows:
            return True
        tokens = set()
        for r in selected_rows:
            if r.name_or_sn: tokens.add((r.name_or_sn or "").lower())
            if r.ip: tokens.add((r.ip or "").lower())
        if not tokens: return True
        ok = any(tok in L for tok in tokens)
        if ok:
            sn = self._extract_sn_from_line(ln)
            if sn: self.last_seen[sn] = _now()
        return ok

    def _refresh_tail(self):
        rows = self._table_rows()
        selected = [r for r in rows if r.key in self.selected_keys]
        quick = FILTER_TAGS.get(self.filter_var.get())
        lines = []
        for path in (MAIN_LOG, SCHED_LOG):
            try:
                if path.exists():
                    for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines()[-3000:]:
                        if self._match_device_line(ln, selected, quick):
                            lines.append(ln)
            except Exception:
                pass
        self.txt_logs.delete("1.0", "end")
        if lines:
            self.txt_logs.insert("end", "\n".join(lines) + "\n")
            self.txt_logs.see("end")

    def _refresh_relay_tab(self):
        lines = []
        if MAIN_LOG.exists():
            for ln in MAIN_LOG.read_text(encoding="utf-8", errors="ignore").splitlines()[-2000:]:
                L = ln.lower()
                if ("relay" in L) or ("zkpush" in L) or ("/iclock" in L):
                    lines.append(ln)
        self.txt_relay.delete("1.0", "end")
        if lines:
            self.txt_relay.insert("end", "\n".join(lines) + "\n")
            self.txt_relay.see("end")

    # ----------------- Monitoring -----------------
    def _start_monitor(self):
        if self.monitor_thread and self.monitor_thread.is_alive(): return
        self.monitor_stop.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def _monitor_loop(self):
        while not self.monitor_stop.is_set():
            try:
                try: mins = int(self.v_monitor_min.get().strip() or "5")
                except: mins = 5
                self._do_monitor_tick(window_minutes=max(mins, 1))
                for _ in range(60):
                    if self.monitor_stop.is_set(): break
                    time.sleep(1)
            except Exception:
                time.sleep(5)

    def _do_monitor_tick(self, window_minutes: int):
        base = self._api_base_from_wdms()
        wdms_ok = False
        try:
            if httpx:
                with httpx.Client(timeout=5.0) as c:
                    r = c.get(base.rstrip("/") + "/")
                    wdms_ok = r.status_code in (200, 301, 302, 401)
        except Exception:
            wdms_ok = False
        self._set_label_online(self.lbl_wdms, wdms_ok)
        self._set_label_online(self.lbl_wdms2, wdms_ok)

        relay = (self.cfg.get("relay") or {})
        relay_on = bool(relay.get("enabled", relay.get("auto_add", False)))
        port = int(relay.get("port", 9090))
        relay_ok = False
        if relay_on and httpx:
            try:
                with httpx.Client(timeout=3.0) as c:
                    r = c.get(f"http://127.0.0.1:{port}/relay/health")
                    relay_ok = r.status_code == 200
            except Exception:
                relay_ok = False
        self._set_label_online(self.lbl_relay, relay_ok)
        self._set_label_online(self.lbl_relay2, relay_ok)

        rows = self._table_rows()
        window = timedelta(minutes=window_minutes)
        for row in rows:
            online = False
            if not row.enabled:
                online = False
            else:
                if row.source == "ZKLegacy Device":
                    online = self._probe_tcp(row.ip, int(row.port or "4370"), 2.0)
                else:
                    last = self.last_seen.get(row.key)
                    if last and (_now() - last) < window:
                        online = True
            self._set_row_online(row.key, online)

    # ----------------- Relay helpers -----------------
    def _relay_cmd(self) -> list[str]:
        # run relay as module so relative imports work
        port = int((self.cfg.get("relay") or {}).get("port", 9090))
        wdms = (self.v_wdms_url.get() or "http://cloud.sabreproducts.com:81/iclock")
        return [sys.executable, "-m", "sabre_bridge.relay_server", "--port", str(port), "--wdms", wdms]

    def _start_relay(self):
        if self._relay_proc and self._relay_proc.poll() is None:
            messagebox.showinfo("Relay", "Relay already running."); return
        # ensure config flag enabled so label stays consistent
        self.cfg.setdefault("relay", {})["enabled"] = True
        self._persist_cfg()
        try:
            self._relay_proc = subprocess.Popen(self._relay_cmd(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.6)  # settle
            self._refresh_relay_label()
            messagebox.showinfo("Relay", "Relay started.")
        except Exception as ex:
            messagebox.showerror("Relay", f"Failed to start relay:\n{ex}")

    def _stop_relay(self):
        try:
            if self._relay_proc and self._relay_proc.poll() is None:
                self._relay_proc.terminate()
                try: self._relay_proc.wait(timeout=3)
                except Exception: pass
            self._relay_proc = None
            # reflect disabled in config if user explicitly stopped
            self.cfg.setdefault("relay", {})["enabled"] = False
            self._persist_cfg()
            self._refresh_relay_label()
            messagebox.showinfo("Relay", "Relay stopped.")
        except Exception as ex:
            messagebox.showerror("Relay", f"Failed to stop relay:\n{ex}")

    def _test_relay_health(self):
        port = int((self.cfg.get("relay") or {}).get("port", 9090))
        url = f"http://127.0.0.1:{port}/relay/health"
        if httpx is None:
            messagebox.showwarning("Relay", "httpx not installed; cannot test."); return
        try:
            with httpx.Client(timeout=3.0) as c:
                r = c.get(url)
            ok = (r.status_code == 200)
            self._set_label_online(self.lbl_relay, ok)
            self._set_label_online(self.lbl_relay2, ok)
            messagebox.showinfo("Relay health", f"{url}\n\nStatus: {r.status_code} {r.reason_phrase}")
        except Exception as ex:
            self._set_label_online(self.lbl_relay, False); self._set_label_online(self.lbl_relay2, False)
            messagebox.showerror("Relay health", f"{url}\n\nError: {ex}")

    def _refresh_relay_label(self):
        # ping health quickly to color the label
        try:
            port = int((self.cfg.get("relay") or {}).get("port", 9090))
            if httpx:
                with httpx.Client(timeout=1.5) as c:
                    r = c.get(f"http://127.0.0.1:{port}/relay/health")
                ok = (r.status_code == 200)
            else:
                ok = False
        except Exception:
            ok = False
        self._set_label_online(self.lbl_relay, ok)
        self._set_label_online(self.lbl_relay2, ok)

    # ----------------- Pulls Manager -----------------
    def _parse_sn_from_filename(self, p: Path) -> str:
        # filenames look like SN_YYYYmmdd_HHMMSS.attlog.txt
        base = p.name
        sn = base.split("_", 1)[0]
        return sn

    def _is_sent_marker(self, p: Path) -> bool:
        return (p.with_suffix(p.suffix + ".sent")).exists()

    def _mark_sent(self, p: Path):
        m = p.with_suffix(p.suffix + ".sent")
        try: m.write_text("ok", encoding="utf-8")
        except: pass

    def _pulls_refresh(self):
        for i in self.pull_list.get_children():
            self.pull_list.delete(i)
        files = sorted(PULL_DIR.glob("*.attlog.txt"), key=lambda x: x.stat().st_mtime, reverse=True)
        for p in files:
            st = p.stat()
            sn = self._parse_sn_from_filename(p)
            sent = "Yes" if self._is_sent_marker(p) else "No"
            mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            size = f"{st.st_size:,}"
            self.pull_list.insert("", "end", iid=p.name, values=(p.name, sn, size, mtime, sent))

    def _pulls_selected_paths(self) -> list[Path]:
        sels = self.pull_list.selection()
        paths = []
        for iid in sels:
            paths.append(PULL_DIR / iid)
        return paths

    def _pulls_open_selected(self):
        paths = self._pulls_selected_paths()
        if not paths:
            messagebox.showinfo("Open", "Select at least one file.")
            return
        for p in paths:
            self._open_path(p)

    def _push_file_to_wdms(self, p: Path, wdms_base: str, sn: str) -> tuple[int, str]:
        url = wdms_base.rstrip("/")
        if not url.lower().endswith("/iclock"):
            url = url + "/iclock"
        url = f"{url}/cdata?SN={sn}"
        body = p.read_text(encoding="utf-8", errors="ignore")
        if httpx is None:
            raise RuntimeError("httpx not installed")
        with httpx.Client(timeout=20.0) as c:
            r = c.post(url, content=body.encode("utf-8"))
            return r.status_code, r.reason_phrase

    def _pulls_resend_selected(self):
        paths = self._pulls_selected_paths()
        if not paths:
            messagebox.showinfo("Resend", "Select at least one file."); return
        base = (self.v_wdms_url.get() or DEFAULT_WDMS)
        ok_count = 0; fail = []
        for p in paths:
            try:
                sn = self._parse_sn_from_filename(p)
                code, reason = self._push_file_to_wdms(p, base, sn)
                if 200 <= code < 300:
                    self._mark_sent(p); ok_count += 1
                else:
                    fail.append(f"{p.name} -> {code} {reason}")
            except Exception as ex:
                fail.append(f"{p.name} -> {ex}")
        self._pulls_refresh()
        if fail:
            messagebox.showwarning("Resend", f"Resent {ok_count} file(s), {len(fail)} failed:\n" + "\n".join(fail[:10]))
        else:
            messagebox.showinfo("Resend", f"Resent {ok_count} file(s).")

    def _pulls_resend_all_unsent(self):
        files = sorted(PULL_DIR.glob("*.attlog.txt"), key=lambda x: x.stat().st_mtime)
        base = (self.v_wdms_url.get() or DEFAULT_WDMS)
        ok_count = 0; fail = []
        for p in files:
            if self._is_sent_marker(p): continue
            try:
                sn = self._parse_sn_from_filename(p)
                code, reason = self._push_file_to_wdms(p, base, sn)
                if 200 <= code < 300:
                    self._mark_sent(p); ok_count += 1
                else:
                    fail.append(f"{p.name} -> {code} {reason}")
            except Exception as ex:
                fail.append(f"{p.name} -> {ex}")
        self._pulls_refresh()
        if fail:
            messagebox.showwarning("Resend", f"Resent {ok_count} file(s), {len(fail)} failed:\n" + "\n".join(fail[:10]))
        else:
            messagebox.showinfo("Resend", f"Resent {ok_count} file(s).")

    # ----------------- Helpers -----------------
    def _probe_tcp(self, ip: str, port: int, timeout: float) -> bool:
        if not ip or not port: return False
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except Exception:
            return False

    def _set_row_online(self, iid: str, online: bool) -> bool:
        try:
            cur = self.tree.item(iid, "tags")
            want = ("online",) if online else ("offline",)
            if tuple(cur) != want:
                self.tree.item(iid, tags=want)
                return True
        except Exception:
            pass
        return False

    def _set_label_online(self, label: ttk.Label, online: bool):
        try:
            label.configure(foreground=("#008000" if online else "#000000"))
        except Exception:
            pass

    def _extract_sn_from_line(self, ln: str) -> str | None:
        m = re.search(r"(?:SN=|\"device\"\s*:\s*\"|serial\"\s*:\s*\")([A-Za-z0-9\-_]+)", ln)
        return m.group(1) if m else None

    def _open_config(self):
        p = filedialog.askopenfilename(
            initialdir=str(self.cfg_path.parent if self.cfg_path.exists() else BRIDGE_DIR),
            title="Open config.yaml",
            filetypes=[("YAML files", "*.yaml;*.yml"), ("All files", "*.*")]
        )
        if not p: return
        self.load_cfg(Path(p))

    def _open_path(self, p: Path):
        try:
            os.startfile(str(p))
        except Exception as ex:
            messagebox.showerror("Open", f"Cannot open:\n{p}\n{ex}")

    def _api_base_from_wdms(self) -> str:
        wdms = (self.v_wdms_url.get() or "").strip().rstrip("/")
        return wdms[:-len("/iclock")] if wdms.endswith("/iclock") else wdms

    def _test_login(self):
        if not httpx:
            messagebox.showwarning("Test Login", "httpx is not installed.")
            return
        base = self._api_base_from_wdms()
        user = (self.v_wdms_user.get() or "").strip()
        pw   = (self.v_wdms_pass.get() or "")
        if not base: messagebox.showwarning("Test Login","WDMS URL empty"); return
        if not user: messagebox.showwarning("Test Login","Username empty"); return
        url = base.rstrip("/") + "/jwt-api-token-auth/"
        self.v_test_status.set("Testing…"); self.update_idletasks()
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(url, json={"username": user, "password": pw})
                if resp.status_code == 200 and "token" in resp.json():
                    self.v_test_status.set("Login OK")
                    messagebox.showinfo("Test Login", "Login OK")
                else:
                    self.v_test_status.set(f"Login FAILED ({resp.status_code})")
                    messagebox.showwarning("Test Login", self.v_test_status.get())
        except Exception as ex:
            self.v_test_status.set(f"Login error: {ex}")
            messagebox.showwarning("Test Login", self.v_test_status.get())

    def on_close(self):
        try: self.tail_stop.set()
        except: pass
        try: self.monitor_stop.set()
        except: pass
        try: get_scheduler().stop()
        except: pass
        try: self._stop_relay()
        except: pass
        self.destroy()

def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
