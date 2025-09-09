# sabre_bridge/gui_app.py
# Unified GUI (rev2):
# - Devices tab with ALL devices (LegacyZK + Relay*). Add/remove ZK and Relay devices.
# - Quick filters now: All / LegacyZK / Relay / Hik / Dahua
# - Right editor adapts by device type. Relay editor lets you map an Alias SN.
# - Logs (device-aware) + checkboxes to include "Relay" and "WDMS" lines.
# - New "Relay / WDMS" tab: a focused tail for relay + zkpush traffic with health hints.

from __future__ import annotations
import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import yaml

# Scheduler import with fallback
try:
    from .zk_scheduler import get_scheduler, ZKDevice
except Exception:
    import importlib.util
    here = os.path.dirname(__file__)
    zp = os.path.join(here, "zk_scheduler.py")
    spec = importlib.util.spec_from_file_location("zk_scheduler", zp)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    get_scheduler, ZKDevice = mod.get_scheduler, mod.ZKDevice

BRIDGE_DIR = Path(r"C:\SabreBridge")
DEFAULT_CFG = BRIDGE_DIR / "config.yaml"
MAIN_LOG = BRIDGE_DIR / "sabre_bridge.log"
SCHED_LOG = BRIDGE_DIR / "pulls" / "zk_scheduler.log"
PULL_DIR = BRIDGE_DIR / "pulls"

DEFAULT_WDMS = "http://cloud.sabreproducts.com:81/iclock"

# ----- internal models for the unified device grid -----
@dataclass
class Row:
    source: str         # "LegacyZK" | "Relay-Hik" | "Relay-Dahua" | "Relay-ZKProxy"
    name_or_sn: str     # display name (ZK) or serial (Relay)
    ip: str             # ZK: IP, Relay: optional
    port: str           # ZK port or Relay port
    enabled: bool       # ZK enabled or Relay enabled
    interval_min: str   # ZK interval or "-"
    key: str            # stable key (ZK: index; Relay: sn)
    subtype: str        # "ZK" | "Hik" | "Dahua" | "ZKProxy"

FILTER_TAGS = {
    "All": None,
    "LegacyZK": "legacyzk",
    "Relay": "relay",
    "Hik": "hik",
    "Dahua": "dahua",
}

def _lower(s: str) -> str:
    return (s or "").lower()

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sabre Bridge")
        self.geometry("1320x860")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.cfg_path: Path = DEFAULT_CFG
        self.cfg: dict = {}
        self.filter_var = tk.StringVar(value="All")
        self.tail_stop = threading.Event()
        self.tail_thread: threading.Thread | None = None
        self.selected_keys: set[str] = set()
        self.show_relay_lines = tk.BooleanVar(value=True)
        self.show_wdms_lines  = tk.BooleanVar(value=True)

        self._build_menu()
        self._build()
        self.load_cfg(self.cfg_path)
        self._start_tail()

    # ------------- menu -------------
    def _build_menu(self):
        m = tk.Menu(self)
        filem = tk.Menu(m, tearoff=0)
        filem.add_command(label="Open config…", command=self._open_config)
        filem.add_command(label="Open bridge folder", command=lambda: self._open_path(BRIDGE_DIR))
        filem.add_separator()
        filem.add_command(label="Exit", command=self.on_close)
        m.add_cascade(label="File", menu=filem)
        self.config(menu=m)

    # ------------- UI -------------
    def _build(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        # ============ DEVICES TAB ============
        self.page_devices = ttk.Frame(nb)
        nb.add(self.page_devices, text="Devices")

        top = ttk.Frame(self.page_devices); top.pack(fill="x", padx=8, pady=6)
        self.lbl_cfg = ttk.Label(top, text=f"Config: {self.cfg_path}")
        self.lbl_cfg.pack(side="left", padx=6)
        self.lbl_wdms = ttk.Label(top, text="WDMS: (loading...)"); self.lbl_wdms.pack(side="left", padx=12)
        self.lbl_relay = ttk.Label(top, text="Relay: (loading...)"); self.lbl_relay.pack(side="left", padx=12)
        self.lbl_sched = ttk.Label(top, text="LegacyZK Scheduler: (stopped)"); self.lbl_sched.pack(side="left", padx=12)

        paned = ttk.Panedwindow(self.page_devices, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=8)

        # Left list + controls
        left = ttk.Frame(paned); paned.add(left, weight=2)

        qf = ttk.Frame(left); qf.pack(fill="x", pady=(0,4))
        ttk.Label(qf, text="Quick filter:").pack(side="left", padx=(0,6))
        for label in ["All", "LegacyZK", "Relay", "Hik", "Dahua"]:
            ttk.Radiobutton(qf, text=label, value=label, variable=self.filter_var,
                            command=self._refresh_tail).pack(side="left", padx=6)

        cols = ("source","name","ip","port","enabled","interval")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", height=18, selectmode="extended")
        for c, w in (("source",130),("name",270),("ip",160),("port",70),("enabled",80),("interval",100)):
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._on_select_rows())

        lbtn = ttk.Frame(left); lbtn.pack(fill="x", pady=6)
        ttk.Button(lbtn, text="Add Legacy ZK", command=self._dev_add_zk).pack(side="left", padx=2)
        ttk.Button(lbtn, text="Remove Selected (ZK only)", command=self._dev_remove_selected_zk).pack(side="left", padx=6)
        ttk.Separator(lbtn, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(lbtn, text="Add Relay Device", command=self._dev_add_relay).pack(side="left", padx=6)
        ttk.Button(lbtn, text="Remove Selected (Relay only)", command=self._dev_remove_selected_relay).pack(side="left", padx=6)
        ttk.Separator(lbtn, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(lbtn, text="Start Scheduler", command=self._start_sched).pack(side="left", padx=6)
        ttk.Button(lbtn, text="Stop Scheduler", command=self._stop_sched).pack(side="left", padx=6)
        ttk.Button(lbtn, text="Open pulls folder", command=lambda: self._open_path(PULL_DIR)).pack(side="left", padx=6)

        # Right editor + logs
        right = ttk.Frame(paned); paned.add(right, weight=3)

        editor = ttk.LabelFrame(right, text="Device Settings")
        editor.pack(fill="x", padx=2, pady=(0,8))

        grid = ttk.Frame(editor); grid.pack(fill="x", padx=6, pady=6)
        r = 0
        ttk.Label(grid, text="32-bit Python path:").grid(row=r, column=0, sticky="e", padx=4, pady=2)
        self.e_py32 = ttk.Entry(grid, width=60); self.e_py32.grid(row=r, column=1, sticky="we", padx=4, pady=2); r += 1
        ttk.Label(grid, text="Default WDMS URL:").grid(row=r, column=0, sticky="e", padx=4, pady=2)
        self.e_wdms = ttk.Entry(grid, width=60); self.e_wdms.grid(row=r, column=1, sticky="we", padx=4, pady=2); r += 1
        self.v_auto_reg = tk.BooleanVar(value=True)
        ttk.Checkbutton(grid, text="Auto-register device on WDMS after push (LegacyZK)", variable=self.v_auto_reg).grid(row=r, column=1, sticky="w", padx=4, pady=2); r += 1

        ttk.Separator(editor).pack(fill="x", pady=6)
        form = ttk.Frame(editor); form.pack(fill="x", padx=6, pady=6)

        # common ZK fields
        self.e_name = ttk.Entry(form)
        self.e_ip   = ttk.Entry(form)
        self.e_port = ttk.Entry(form)
        self.v_enabled = tk.BooleanVar(value=True)
        self.chk_enabled = ttk.Checkbutton(form, variable=self.v_enabled)
        self.e_interval = ttk.Entry(form)
        self.v_clear = tk.BooleanVar(value=True)
        self.chk_clear = ttk.Checkbutton(form, variable=self.v_clear)
        self.e_wdms_dev = ttk.Entry(form)
        self.e_note = ttk.Entry(form)
        # relay alias
        self.e_alias_sn = ttk.Entry(form)

        ctrl = ttk.Frame(editor); ctrl.pack(fill="x", pady=6)
        ttk.Button(ctrl, text="Save settings", command=self._save_everything).pack(side="left", padx=4)
        ttk.Button(ctrl, text="Run selected now (ZK)", command=self._run_selected_now).pack(side="left", padx=4)

        # Logs (device-aware)
        logbox = ttk.LabelFrame(right, text="Logs (device-aware)")
        logbox.pack(fill="both", expand=True, padx=2, pady=(0,2))
        filters = ttk.Frame(logbox); filters.pack(fill="x")
        ttk.Checkbutton(filters, text="Include Relay", variable=self.show_relay_lines, command=self._refresh_tail).pack(side="left", padx=6)
        ttk.Checkbutton(filters, text="Include WDMS",  variable=self.show_wdms_lines,  command=self._refresh_tail).pack(side="left", padx=6)

        frm = ttk.Frame(logbox); frm.pack(fill="both", expand=True)
        self.txt_logs = tk.Text(frm, height=18, wrap="none"); self.txt_logs.pack(fill="both", expand=True, side="left")
        sbs = ttk.Scrollbar(frm, command=self.txt_logs.yview); sbs.pack(side="right", fill="y")
        self.txt_logs["yscrollcommand"] = sbs.set

        # ============ RELAY/WDMS TAB ============
        self.page_relay = ttk.Frame(nb)
        nb.add(self.page_relay, text="Relay / WDMS")

        hdr = ttk.Frame(self.page_relay); hdr.pack(fill="x", padx=8, pady=6)
        self.lbl_relay2 = ttk.Label(hdr, text="Relay: (loading...)"); self.lbl_relay2.pack(side="left", padx=6)
        self.lbl_wdms2 = ttk.Label(hdr, text="WDMS: (loading...)"); self.lbl_wdms2.pack(side="left", padx=12)
        ttk.Button(hdr, text="Open sabre_bridge.log", command=lambda: self._open_path(MAIN_LOG)).pack(side="right", padx=6)

        rbox = ttk.LabelFrame(self.page_relay, text="Relay/WDMS log tail")
        rbox.pack(fill="both", expand=True, padx=8, pady=8)
        self.txt_relay = tk.Text(rbox, height=28, wrap="none")
        self.txt_relay.pack(fill="both", expand=True, side="left")
        sbs2 = ttk.Scrollbar(rbox, command=self.txt_relay.yview); sbs2.pack(side="right", fill="y")
        self.txt_relay["yscrollcommand"] = sbs2.set

        # periodic updates
        self.after(1000, self._poll_scheduler_events)

    # ---------- config load/save ----------
    def load_cfg(self, path: Path):
        try:
            self.cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            self.cfg_path = path
            self.lbl_cfg.configure(text=f"Config: {self.cfg_path}")
        except Exception as ex:
            messagebox.showerror("Config error", f"Failed to read:\n{path}\n\n{ex}")
            self.cfg = {}

        wdms = self.cfg.get("wdms_url") or (self.cfg.get("legacy_pull") or {}).get("wdms_url") or DEFAULT_WDMS
        self.lbl_wdms.configure(text=f"WDMS: {wdms}")
        self.lbl_wdms2.configure(text=f"WDMS: {wdms}")

        r = self.cfg.get("relay") or {}
        relay_on = bool(r.get("enabled", r.get("auto_add", False)))
        relay_port = r.get("port", 9090)
        self.lbl_relay.configure(text=f"Relay: {'ON' if relay_on else 'OFF'} (port {relay_port})")
        self.lbl_relay2.configure(text=f"Relay: {'ON' if relay_on else 'OFF'} (port {relay_port})")

        sch = get_scheduler()
        sch.load_from_config()
        self.e_py32.delete(0, "end"); self.e_py32.insert(0, sch.py32)
        self.e_wdms.delete(0, "end"); self.e_wdms.insert(0, sch.wdms_default)
        self.v_auto_reg.set(bool(sch.auto_register))

        self._rebuild_table()
        self._refresh_tail()
        self._refresh_relay_tab()

    def _save_everything(self):
        # scheduler globals
        sch = get_scheduler()
        sch.py32 = self.e_py32.get().strip() or sch.py32
        sch.wdms_default = self.e_wdms.get().strip() or sch.wdms_default
        sch.auto_register = bool(self.v_auto_reg.get())

        # rebuild ZK list from current scheduler (apply edit if selected)
        rows = self._table_rows()
        new_devs: list[ZKDevice] = []
        for row in rows:
            if row.source == "LegacyZK":
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

        # save relay alias mapping if edited
        relay = self.cfg.get("relay") or {}
        sn_map = relay.get("device_sn_map") or {}
        changed = False
        for row in rows:
            if row.source.startswith("Relay") and row.key in self.selected_keys:
                alias = self.e_alias_sn.get().strip()
                if alias:
                    sn_map[row.name_or_sn] = alias
                    changed = True
        if changed:
            relay["device_sn_map"] = sn_map
            self.cfg["relay"] = relay
            try:
                self.cfg_path.write_text(yaml.safe_dump(self.cfg, sort_keys=False), encoding="utf-8")
            except Exception as ex:
                messagebox.showerror("Save config", f"Could not write config:\n{ex}")

        self.load_cfg(self.cfg_path)
        messagebox.showinfo("Saved", "Settings saved.")

    # ---------- table build ----------
    def _rebuild_table(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

        rows = []
        sch = get_scheduler()

        # Legacy ZK devices
        for idx, d in enumerate(sch.devices):
            rows.append(Row("LegacyZK", d.name, d.ip, str(d.port), d.enabled,
                            str(d.interval_min), str(idx), "ZK"))

        # Relay devices from config
        r = self.cfg.get("relay") or {}
        device_sn_map = r.get("device_sn_map") or {}
        relay_port = str(r.get("port", 9090))
        seen = set()

        # From the alias map keys (auto-added typically)
        for sn in sorted(device_sn_map.keys()):
            if sn in seen: continue
            seen.add(sn)
            subtype = "ZKProxy"
            usn = sn.upper()
            if usn.startswith("HIK"): subtype = "Hik"
            elif usn.startswith("DAHUA"): subtype = "Dahua"
            rows.append(Row(f"Relay-{subtype}", sn, "", relay_port, True, "-", sn, subtype))

        # From explicit relay.devices list (manual)
        for dev in (r.get("devices") or []):
            sn = str(dev.get("sn") or dev.get("serial") or "").strip()
            if not sn or sn in seen: continue
            seen.add(sn)
            kind = (dev.get("type") or "ZKProxy")
            rows.append(Row(f"Relay-{kind}", sn, str(dev.get("ip","")), str(dev.get("port", relay_port)),
                            bool(dev.get("enabled", True)), "-", sn, kind))

        for row in rows:
            self.tree.insert("", "end", iid=row.key,
                             values=(row.source, row.name_or_sn, row.ip, row.port,
                                     "Yes" if row.enabled else "No", row.interval_min))

        if rows:
            self.tree.selection_set(rows[0].key)
            self._on_select_rows()

    def _table_rows(self) -> list[Row]:
        rows = []
        sch = get_scheduler()
        for idx, d in enumerate(sch.devices):
            rows.append(Row("LegacyZK", d.name, d.ip, str(d.port), d.enabled,
                            str(d.interval_min), str(idx), "ZK"))
        r = self.cfg.get("relay") or {}
        device_sn_map = r.get("device_sn_map") or {}
        relay_port = str(r.get("port", 9090))
        seen = set()
        for sn in sorted(device_sn_map.keys()):
            if sn in seen: continue
            seen.add(sn)
            subtype = "ZKProxy"
            usn = sn.upper()
            if usn.startswith("HIK"): subtype = "Hik"
            elif usn.startswith("DAHUA"): subtype = "Dahua"
            rows.append(Row(f"Relay-{subtype}", sn, "", relay_port, True, "-", sn, subtype))
        for dev in (r.get("devices") or []):
            sn = str(dev.get("sn") or dev.get("serial") or "").strip()
            if not sn or sn in seen: continue
            seen.add(sn)
            kind = (dev.get("type") or "ZKProxy")
            rows.append(Row(f"Relay-{kind}", sn, str(dev.get("ip","")), str(dev.get("port", relay_port)),
                            bool(dev.get("enabled", True)), "-", sn, kind))
        return rows

    # ---------- selection & editor ----------
    def _on_select_rows(self):
        sels = self.tree.selection()
        self.selected_keys = set(sels)
        self._populate_editor()
        self._refresh_tail()

    def _populate_editor(self):
        # clear form
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
            if row.source == "LegacyZK":
                self.e_name.insert(0, row.name_or_sn); put("Name", self.e_name, 0)
                self.e_ip.insert(0, row.ip);          put("IP", self.e_ip, 1)
                self.e_port.insert(0, row.port);      put("Port", self.e_port, 2)
                self.v_enabled.set(row.enabled);      put("Enabled", self.chk_enabled, 3)
                self.e_interval.insert(0, row.interval_min if row.interval_min != "-" else "5"); put("Interval (min)", self.e_interval, 4)
                self.v_clear.set(True);               put("Clear after push", self.chk_clear, 5)
                self.e_wdms_dev.insert(0, "");        put("WDMS URL (override)", self.e_wdms_dev, 6)
                self.e_note.insert(0, "");            put("Note", self.e_note, 7)
            else:
                put("Relay Serial (read-only)", ttk.Label(self.e_name.master, text=selected[0].name_or_sn), 0)
                self.e_alias_sn.insert(0, self._current_alias_for(selected[0].name_or_sn))
                put("Alias SN to push as", self.e_alias_sn, 1)
        else:
            if selected and all(s.source.startswith("Relay") for s in selected):
                put("Alias SN to push as (applies to all selected)", self.e_alias_sn, 0)

        self.e_name.master.columnconfigure(1, weight=1)

    def _current_alias_for(self, sn: str) -> str:
        relay = self.cfg.get("relay") or {}
        sn_map = relay.get("device_sn_map") or {}
        return str(sn_map.get(sn, ""))

    # ---------- add/remove devices ----------
    def _dev_add_zk(self):
        sch = get_scheduler()
        sch.devices.append(ZKDevice(name="New ZK", ip="192.168.1.100"))
        sch.save_to_config()
        self.load_cfg(self.cfg_path)
        idx = len(sch.devices) - 1
        self.tree.selection_set(str(idx))
        self._on_select_rows()

    def _dev_remove_selected_zk(self):
        sels = [s for s in self.tree.selection() if s.isdigit()]
        if not sels:
            return
        sch = get_scheduler()
        keep = []
        for i, d in enumerate(sch.devices):
            if str(i) not in sels:
                keep.append(d)
        sch.devices = keep
        sch.save_to_config()
        self.load_cfg(self.cfg_path)
        messagebox.showinfo("Removed", f"Removed {len(sels)} Legacy ZK device(s).")

    def _dev_add_relay(self):
        # small dialog to add relay entry to config under relay.devices
        dlg = tk.Toplevel(self)
        dlg.title("Add Relay Device")
        dlg.resizable(False, False)
        frm = ttk.Frame(dlg, padding=10); frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Serial (SN):").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        e_sn = ttk.Entry(frm, width=36); e_sn.grid(row=0, column=1, padx=4, pady=4)

        ttk.Label(frm, text="Type:").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        cb_type = ttk.Combobox(frm, values=["Hik","Dahua","ZKProxy"], width=12, state="readonly")
        cb_type.set("ZKProxy"); cb_type.grid(row=1, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(frm, text="IP (optional):").grid(row=2, column=0, sticky="e", padx=4, pady=4)
        e_ip = ttk.Entry(frm, width=20); e_ip.grid(row=2, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(frm, text="Port (relay listens):").grid(row=3, column=0, sticky="e", padx=4, pady=4)
        e_port = ttk.Entry(frm, width=8); e_port.insert(0, "9090"); e_port.grid(row=3, column=1, sticky="w", padx=4, pady=4)

        v_en = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text="Enabled", variable=v_en).grid(row=4, column=1, sticky="w", padx=4, pady=4)

        btns = ttk.Frame(frm); btns.grid(row=5, column=0, columnspan=2, pady=(8,4))
        def ok():
            sn = e_sn.get().strip()
            kind = cb_type.get().strip()
            ip = e_ip.get().strip()
            port = int(e_port.get().strip() or "9090")
            if not sn:
                messagebox.showwarning("Add Relay", "Serial is required.")
                return
            cfg = self.cfg
            relay = cfg.setdefault("relay", {})
            devs = relay.setdefault("devices", [])
            devs.append({"sn": sn, "type": kind, "ip": ip, "port": port, "enabled": bool(v_en.get())})
            # persist
            try:
                self.cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
            except Exception as ex:
                messagebox.showerror("Save config", f"Could not write config:\n{ex}")
                return
            dlg.destroy()
            self.load_cfg(self.cfg_path)
        ttk.Button(btns, text="Add", command=ok).pack(side="left", padx=6)
        ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side="left", padx=6)

        dlg.grab_set()
        self.wait_window(dlg)

    def _dev_remove_selected_relay(self):
        sels = [s for s in self.tree.selection() if not s.isdigit()]
        if not sels:
            return
        relay = self.cfg.get("relay") or {}
        devs = relay.get("devices") or []
        before = len(devs)
        devs = [d for d in devs if str(d.get("sn") or d.get("serial")) not in sels]
        relay["devices"] = devs
        self.cfg["relay"] = relay
        try:
            self.cfg_path.write_text(yaml.safe_dump(self.cfg, sort_keys=False), encoding="utf-8")
        except Exception as ex:
            messagebox.showerror("Save config", f"Could not write config:\n{ex}")
            return
        self.load_cfg(self.cfg_path)
        messagebox.showinfo("Removed", f"Removed {before-len(devs)} Relay device(s).")

    # ---------- run & scheduler ----------
    def _run_selected_now(self):
        sels = self.tree.selection()
        if not sels:
            messagebox.showwarning("Run now", "Select a Legacy ZK device.")
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
            messagebox.showinfo("Run now", "Queued selected Legacy ZK devices.")
        else:
            messagebox.showwarning("Run now", "No Legacy ZK devices selected.")

    def _start_sched(self):
        get_scheduler().start()
        self.lbl_sched.configure(text="LegacyZK Scheduler: running")

    def _stop_sched(self):
        get_scheduler().stop()
        self.lbl_sched.configure(text="LegacyZK Scheduler: stopped")

    # ---------- tailers ----------
    def _start_tail(self):
        if self.tail_thread and self.tail_thread.is_alive():
            return
        self.tail_stop.clear()
        self.tail_thread = threading.Thread(target=self._tail_loop, daemon=True)
        self.tail_thread.start()

    def _tail_loop(self):
        last_m = 0
        last_s = 0
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
        # quick filters:
        if quick == "legacyzk" and "zk" not in L:
            # treat scheduler and COM traces as legacy
            if "scheduler" not in L and "zkteco" not in L and "pull" not in L:
                return False
        if quick == "relay" and "relay" not in L:
            return False
        if quick == "hik" and "hik" not in L:
            return False
        if quick == "dahua" and "dahua" not in L:
            return False

        # include/omit switches
        if not self.show_relay_lines.get() and "relay" in L:
            return False
        if not self.show_wdms_lines.get() and ("zkpush" in L or "/iclock" in L):
            return False

        # device selection filter
        if not selected_rows:
            return True
        tokens = set()
        for r in selected_rows:
            if r.name_or_sn: tokens.add(_lower(r.name_or_sn))
            if r.ip: tokens.add(_lower(r.ip))
        if not tokens:
            return True
        return any(tok in L for tok in tokens)

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
        # show only relay + wdms lines, last 2000
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

    # drain scheduler events -> log refresh
    def _poll_scheduler_events(self):
        try:
            sch = get_scheduler()
            _ = sch.drain_events()
            self._refresh_tail()
            self._refresh_relay_tab()
        except Exception:
            pass
        self.after(1000, self._poll_scheduler_events)

    # ---------- helpers ----------
    def _open_config(self):
        p = filedialog.askopenfilename(
            initialdir=str(self.cfg_path.parent if self.cfg_path.exists() else BRIDGE_DIR),
            title="Open config.yaml",
            filetypes=[("YAML files", "*.yaml;*.yml"), ("All files", "*.*")]
        )
        if not p:
            return
        self.load_cfg(Path(p))

    def _open_path(self, p: Path):
        try:
            os.startfile(str(p))
        except Exception as ex:
            messagebox.showerror("Open", f"Cannot open:\n{p}\n{ex}")

    def on_close(self):
        try: self.tail_stop.set()
        except Exception: pass
        try: get_scheduler().stop()
        except Exception: pass
        self.destroy()

def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
