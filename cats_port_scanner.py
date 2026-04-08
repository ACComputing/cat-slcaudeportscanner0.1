#!/usr/bin/env python3
"""
Cat's Claude Port Scanner 0.1
A.C Holdings / Team Flames © 1999–2026
Single-file Tkinter network port scanner
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import queue
import time
from datetime import datetime

# ── Common service names ──────────────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    1433: "MSSQL", 11211: "Memcached", 9200: "Elasticsearch", 6443: "k8s-API",
}

PRESET_RANGES = {
    "Top 20":   [21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443],
    "Top 100":  list(range(1, 101)),
    "1–1024":   list(range(1, 1025)),
    "Full":     list(range(1, 65536)),
    "Custom":   [],
}

DARK = {
    "bg":      "#0d0d0d",
    "panel":   "#141414",
    "border":  "#2a2a2a",
    "accent":  "#00c8ff",
    "green":   "#00ff88",
    "red":     "#ff4455",
    "yellow":  "#ffcc00",
    "fg":      "#e0e0e0",
    "dim":     "#666666",
    "hover":   "#1e1e1e",
}


class PortScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cat's Claude Port Scanner 0.1 — A.C Holdings")
        self.configure(bg=DARK["bg"])
        self.resizable(True, True)
        self.minsize(760, 560)

        self._scan_running = False
        self._stop_event   = threading.Event()
        self._result_queue = queue.Queue()
        self._open_ports   = []
        self._total        = 0
        self._scanned      = 0

        self._build_ui()
        self._poll_results()

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=DARK["panel"], pady=8)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🐱 Cat's Claude Port Scanner 0.1",
                 font=("Courier New", 16, "bold"),
                 fg=DARK["accent"], bg=DARK["panel"]).pack(side="left", padx=16)
        tk.Label(hdr, text="A.C Holdings / Team Flames © 1999–2026",
                 font=("Courier New", 9), fg=DARK["dim"],
                 bg=DARK["panel"]).pack(side="right", padx=16)

        # ── Config row ────────────────────────────────────────────────────────
        cfg = tk.Frame(self, bg=DARK["bg"], pady=6)
        cfg.pack(fill="x", padx=12)

        # Target
        tk.Label(cfg, text="Target:", fg=DARK["fg"], bg=DARK["bg"],
                 font=("Courier New", 10)).grid(row=0, column=0, sticky="w", padx=(0,4))
        self._target_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(cfg, textvariable=self._target_var, width=22,
                 bg=DARK["panel"], fg=DARK["accent"], insertbackground=DARK["accent"],
                 relief="flat", font=("Courier New", 10),
                 highlightthickness=1, highlightbackground=DARK["border"]).grid(
                     row=0, column=1, padx=(0,12))

        # Timeout
        tk.Label(cfg, text="Timeout(s):", fg=DARK["fg"], bg=DARK["bg"],
                 font=("Courier New", 10)).grid(row=0, column=2, sticky="w", padx=(0,4))
        self._timeout_var = tk.StringVar(value="0.5")
        tk.Entry(cfg, textvariable=self._timeout_var, width=6,
                 bg=DARK["panel"], fg=DARK["fg"], insertbackground=DARK["fg"],
                 relief="flat", font=("Courier New", 10),
                 highlightthickness=1, highlightbackground=DARK["border"]).grid(
                     row=0, column=3, padx=(0,12))

        # Threads
        tk.Label(cfg, text="Threads:", fg=DARK["fg"], bg=DARK["bg"],
                 font=("Courier New", 10)).grid(row=0, column=4, sticky="w", padx=(0,4))
        self._threads_var = tk.StringVar(value="150")
        tk.Entry(cfg, textvariable=self._threads_var, width=6,
                 bg=DARK["panel"], fg=DARK["fg"], insertbackground=DARK["fg"],
                 relief="flat", font=("Courier New", 10),
                 highlightthickness=1, highlightbackground=DARK["border"]).grid(
                     row=0, column=5, padx=(0,12))

        # Preset
        tk.Label(cfg, text="Range:", fg=DARK["fg"], bg=DARK["bg"],
                 font=("Courier New", 10)).grid(row=0, column=6, sticky="w", padx=(0,4))
        self._preset_var = tk.StringVar(value="Top 20")
        preset_cb = ttk.Combobox(cfg, textvariable=self._preset_var, width=10,
                                 values=list(PRESET_RANGES.keys()), state="readonly",
                                 font=("Courier New", 10))
        preset_cb.grid(row=0, column=7, padx=(0,12))
        preset_cb.bind("<<ComboboxSelected>>", self._on_preset_change)

        # Custom range
        self._custom_frame = tk.Frame(cfg, bg=DARK["bg"])
        self._custom_frame.grid(row=0, column=8, padx=(0,12))
        tk.Label(self._custom_frame, text="From:", fg=DARK["fg"], bg=DARK["bg"],
                 font=("Courier New", 10)).pack(side="left")
        self._from_var = tk.StringVar(value="1")
        tk.Entry(self._custom_frame, textvariable=self._from_var, width=6,
                 bg=DARK["panel"], fg=DARK["fg"], insertbackground=DARK["fg"],
                 relief="flat", font=("Courier New", 10),
                 highlightthickness=1, highlightbackground=DARK["border"]).pack(side="left", padx=2)
        tk.Label(self._custom_frame, text="To:", fg=DARK["fg"], bg=DARK["bg"],
                 font=("Courier New", 10)).pack(side="left")
        self._to_var = tk.StringVar(value="1024")
        tk.Entry(self._custom_frame, textvariable=self._to_var, width=6,
                 bg=DARK["panel"], fg=DARK["fg"], insertbackground=DARK["fg"],
                 relief="flat", font=("Courier New", 10),
                 highlightthickness=1, highlightbackground=DARK["border"]).pack(side="left", padx=2)
        self._custom_frame.grid_remove()

        # Buttons
        btn_frame = tk.Frame(cfg, bg=DARK["bg"])
        btn_frame.grid(row=0, column=9, padx=4)

        self._scan_btn = tk.Button(btn_frame, text="▶  SCAN",
                                   command=self._start_scan,
                                   bg=DARK["accent"], fg=DARK["bg"],
                                   font=("Courier New", 10, "bold"),
                                   relief="flat", padx=10, pady=3,
                                   cursor="hand2", activebackground="#009fc8")
        self._scan_btn.pack(side="left", padx=(0,4))

        self._stop_btn = tk.Button(btn_frame, text="■  STOP",
                                   command=self._stop_scan,
                                   bg=DARK["red"], fg="white",
                                   font=("Courier New", 10, "bold"),
                                   relief="flat", padx=10, pady=3,
                                   cursor="hand2", state="disabled",
                                   activebackground="#cc2233")
        self._stop_btn.pack(side="left")

        # ── Progress ──────────────────────────────────────────────────────────
        prog_frame = tk.Frame(self, bg=DARK["bg"])
        prog_frame.pack(fill="x", padx=12, pady=(0, 4))

        self._prog_var = tk.DoubleVar(value=0)
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Cat.Horizontal.TProgressbar",
                         troughcolor=DARK["panel"],
                         background=DARK["accent"],
                         darkcolor=DARK["accent"],
                         lightcolor=DARK["accent"],
                         bordercolor=DARK["border"])
        self._progress = ttk.Progressbar(prog_frame, variable=self._prog_var,
                                          maximum=100, length=400,
                                          style="Cat.Horizontal.TProgressbar")
        self._progress.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self._prog_label = tk.Label(prog_frame, text="Ready",
                                    fg=DARK["dim"], bg=DARK["bg"],
                                    font=("Courier New", 9))
        self._prog_label.pack(side="left")

        # ── Results pane (Treeview + log) ─────────────────────────────────────
        panes = tk.PanedWindow(self, orient="horizontal",
                               bg=DARK["border"], sashwidth=4,
                               sashrelief="flat")
        panes.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        # Left: open ports tree
        left = tk.Frame(panes, bg=DARK["bg"])
        panes.add(left, minsize=260)

        tk.Label(left, text="OPEN PORTS", fg=DARK["accent"], bg=DARK["bg"],
                 font=("Courier New", 10, "bold")).pack(anchor="w", padx=4, pady=(4, 2))

        cols = ("port", "service", "banner")
        style.configure("Cat.Treeview",
                         background=DARK["panel"],
                         foreground=DARK["fg"],
                         fieldbackground=DARK["panel"],
                         borderwidth=0,
                         font=("Courier New", 10))
        style.configure("Cat.Treeview.Heading",
                         background=DARK["border"],
                         foreground=DARK["accent"],
                         font=("Courier New", 10, "bold"),
                         relief="flat")
        style.map("Cat.Treeview",
                  background=[("selected", DARK["accent"])],
                  foreground=[("selected", DARK["bg"])])

        self._tree = ttk.Treeview(left, columns=cols, show="headings",
                                   style="Cat.Treeview", selectmode="browse")
        self._tree.heading("port",    text="Port")
        self._tree.heading("service", text="Service")
        self._tree.heading("banner",  text="Banner")
        self._tree.column("port",    width=60,  anchor="center")
        self._tree.column("service", width=100, anchor="w")
        self._tree.column("banner",  width=200, anchor="w")

        vsb = ttk.Scrollbar(left, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side="left", fill="both", expand=True, padx=(4, 0), pady=(0, 4))
        vsb.pack(side="left", fill="y", pady=(0, 4))

        # Right: log
        right = tk.Frame(panes, bg=DARK["bg"])
        panes.add(right, minsize=320)

        tk.Label(right, text="SCAN LOG", fg=DARK["accent"], bg=DARK["bg"],
                 font=("Courier New", 10, "bold")).pack(anchor="w", padx=4, pady=(4, 2))

        self._log = scrolledtext.ScrolledText(right,
                                               bg=DARK["panel"], fg=DARK["fg"],
                                               font=("Courier New", 9),
                                               relief="flat", state="disabled",
                                               wrap="word", insertbackground=DARK["fg"])
        self._log.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        self._log.tag_config("open",    foreground=DARK["green"])
        self._log.tag_config("closed",  foreground=DARK["dim"])
        self._log.tag_config("info",    foreground=DARK["accent"])
        self._log.tag_config("warn",    foreground=DARK["yellow"])
        self._log.tag_config("err",     foreground=DARK["red"])

        # ── Status bar ────────────────────────────────────────────────────────
        bar = tk.Frame(self, bg=DARK["panel"], pady=3)
        bar.pack(fill="x")
        self._status_var = tk.StringVar(value="🐱  Cat's Claude Port Scanner 0.1  |  Idle")
        tk.Label(bar, textvariable=self._status_var,
                 fg=DARK["dim"], bg=DARK["panel"],
                 font=("Courier New", 9)).pack(side="left", padx=12)
        self._open_count_var = tk.StringVar(value="Open: 0")
        tk.Label(bar, textvariable=self._open_count_var,
                 fg=DARK["green"], bg=DARK["panel"],
                 font=("Courier New", 9, "bold")).pack(side="right", padx=12)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _on_preset_change(self, _=None):
        if self._preset_var.get() == "Custom":
            self._custom_frame.grid()
        else:
            self._custom_frame.grid_remove()

    def _log_write(self, msg, tag="info"):
        self._log.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self._log.insert("end", f"[{ts}] {msg}\n", tag)
        self._log.see("end")
        self._log.configure(state="disabled")

    def _add_open_port(self, port, service, banner):
        self._tree.insert("", "end", values=(port, service, banner[:60]))
        self._open_ports.append(port)
        self._open_count_var.set(f"Open: {len(self._open_ports)}")

    # ── Scan logic ────────────────────────────────────────────────────────────
    def _resolve_target(self, target):
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None

    def _probe_port(self, ip, port, timeout):
        """Returns (open:bool, banner:str)"""
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                banner = ""
                try:
                    s.sendall(b"\r\n")
                    raw = s.recv(256)
                    banner = raw.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
                return True, banner
        except Exception:
            return False, ""

    def _worker(self, ip, port_q, timeout):
        while not self._stop_event.is_set():
            try:
                port = port_q.get_nowait()
            except queue.Empty:
                break
            open_, banner = self._probe_port(ip, port, timeout)
            self._result_queue.put((port, open_, banner))
            port_q.task_done()

    def _scan_thread(self, target, ports, timeout, n_threads):
        ip = self._resolve_target(target)
        if ip is None:
            self._result_queue.put(("__err__", f"Cannot resolve: {target}"))
            return

        self._result_queue.put(("__info__",
            f"Scanning {target} ({ip})  |  {len(ports)} ports  "
            f"|  timeout={timeout}s  |  threads={n_threads}"))

        port_q = queue.Queue()
        for p in ports:
            port_q.put(p)

        threads = []
        for _ in range(min(n_threads, len(ports))):
            t = threading.Thread(target=self._worker,
                                  args=(ip, port_q, timeout), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self._result_queue.put(("__done__", None))

    def _start_scan(self):
        if self._scan_running:
            return

        target  = self._target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Enter a target host/IP.")
            return

        try:
            timeout  = float(self._timeout_var.get())
            n_threads = int(self._threads_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid timeout or thread count.")
            return

        preset = self._preset_var.get()
        if preset == "Custom":
            try:
                p_from = int(self._from_var.get())
                p_to   = int(self._to_var.get())
                ports  = list(range(p_from, p_to + 1))
            except ValueError:
                messagebox.showerror("Error", "Invalid custom port range.")
                return
        elif preset == "Full":
            ports = list(range(1, 65536))
        else:
            ports = PRESET_RANGES[preset]

        if not ports:
            messagebox.showerror("Error", "Port list is empty.")
            return

        # Reset UI
        self._tree.delete(*self._tree.get_children())
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")
        self._open_ports.clear()
        self._open_count_var.set("Open: 0")
        self._prog_var.set(0)
        self._total   = len(ports)
        self._scanned = 0

        self._scan_running = True
        self._stop_event.clear()
        self._scan_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._status_var.set(f"🔍  Scanning {target} …")

        threading.Thread(target=self._scan_thread,
                          args=(target, ports, timeout, n_threads),
                          daemon=True).start()

    def _stop_scan(self):
        self._stop_event.set()
        self._log_write("⚠  Scan aborted by user.", "warn")
        self._finish_scan()

    def _finish_scan(self):
        self._scan_running = False
        self._scan_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        n_open = len(self._open_ports)
        self._status_var.set(
            f"✔  Done  |  {self._scanned}/{self._total} ports scanned  |  {n_open} open")
        self._prog_label.configure(text="100%", fg=DARK["green"])
        self._prog_var.set(100)

    def _poll_results(self):
        """Main-thread callback that drains the result queue every 30 ms."""
        try:
            while True:
                item = self._result_queue.get_nowait()
                kind = item[0]

                if kind == "__info__":
                    self._log_write(f"ℹ  {item[1]}", "info")

                elif kind == "__err__":
                    self._log_write(f"✗  {item[1]}", "err")
                    self._finish_scan()

                elif kind == "__done__":
                    n_open = len(self._open_ports)
                    self._log_write(
                        f"✔  Scan complete  —  {self._scanned}/{self._total} ports  "
                        f"|  {n_open} open", "info")
                    self._finish_scan()

                else:
                    port, open_, banner = item
                    self._scanned += 1
                    pct = (self._scanned / max(self._total, 1)) * 100
                    self._prog_var.set(pct)
                    self._prog_label.configure(
                        text=f"{self._scanned}/{self._total}  ({pct:.0f}%)",
                        fg=DARK["fg"])
                    if self._scanned % 50 == 0 or open_:
                        self._status_var.set(
                            f"🔍  Scanned {self._scanned}/{self._total}  |  "
                            f"Open: {len(self._open_ports)}")

                    if open_:
                        service = COMMON_PORTS.get(port, "unknown")
                        self._add_open_port(port, service, banner)
                        self._log_write(
                            f"OPEN  {port:>5}/tcp  [{service}]  {banner[:60]}", "open")

        except queue.Empty:
            pass

        self.after(30, self._poll_results)


if __name__ == "__main__":
    app = PortScannerApp()
    app.mainloop()
