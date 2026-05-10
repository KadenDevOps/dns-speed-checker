import tkinter as tk
from tkinter import ttk
import threading
import socket
import time
import statistics
import os
import sys
from dataclasses import dataclass, field
from typing import List, Optional

# ── Colors & Styling ─────────────────────────────────────────────────────────
BG        = "#0f1117"
BG2       = "#1a1d27"
BG3       = "#252836"
ACCENT    = "#6c63ff"
RED       = "#ef4444"
FG        = "#e2e8f0"
FG2       = "#94a3b8"
GOLD      = "#fbbf24"

FONT_FAMILY = "Segoe UI"

DNS_SERVERS = [
    ("Cloudflare",      "1.1.1.1"),
    ("Cloudflare Alt",  "1.0.0.1"),
    ("Google",          "8.8.8.8"),
    ("Google Alt",      "8.8.4.4"),
    ("OpenDNS",         "208.67.222.222"),
    ("OpenDNS Alt",     "208.67.220.220"),
    ("Quad9",           "9.9.9.9"),
    ("Quad9 Alt",       "149.112.112.112"),
    ("AdGuard",         "94.140.14.14"),
    ("AdGuard Alt",     "94.140.15.15"),
    ("DNS.Watch",       "84.200.69.80"),
    ("Comodo",          "8.26.56.26"),
]

TEST_DOMAINS = [
    "google.com",
    "youtube.com",
    "cloudflare.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "wikipedia.org",
    "reddit.com",
]

DEFAULT_ROUNDS = 3


def resource_path(filename: str) -> str:
    """Resolves paths for both dev mode and PyInstaller bundles."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, filename)


@dataclass
class DnsResult:
    name: str
    ip: str
    times: List[float] = field(default_factory=list)
    errors: int = 0

    @property
    def avg(self) -> Optional[float]:
        return statistics.mean(self.times) if self.times else None

    @property
    def median(self) -> Optional[float]:
        return statistics.median(self.times) if self.times else None

    @property
    def jitter(self) -> Optional[float]:
        return statistics.stdev(self.times) if len(self.times) > 1 else 0.0

    @property
    def success_rate(self) -> float:
        total = len(self.times) + self.errors
        return (len(self.times) / total * 100) if total else 0.0

    def score(self) -> float:
        """Lower = better. Weighs latency, jitter and error rate."""
        if self.avg is None:
            return float("inf")
        penalty = (100 - self.success_rate) * 5
        return self.avg + (self.jitter or 0) * 0.5 + penalty


def query_dns(server_ip: str, domain: str, timeout: float = 3.0) -> Optional[float]:
    """Returns DNS query round-trip time in milliseconds, or None on failure."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        txid   = b"\xaa\xbb"
        flags  = b"\x01\x00"
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        question = b""
        for part in domain.split("."):
            question += bytes([len(part)]) + part.encode()
        question += b"\x00\x00\x01\x00\x01"
        packet = txid + flags + counts + question

        start = time.perf_counter()
        sock.sendto(packet, (server_ip, 53))
        sock.recvfrom(512)
        elapsed = (time.perf_counter() - start) * 1000
        sock.close()
        return elapsed
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return None


# ── GUI ──────────────────────────────────────────────────────────────────────

class DnsCheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DNS Speed Checker – FC26 Tools")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.geometry("920x700")
        self.minsize(820, 580)

        # Load icon
        icon_path = resource_path("fc26.ico")
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass

        self._results: List[DnsResult] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None

        self._build_ui()

    def _build_ui(self):
        # ── Header ───────────────────────────────────────────────────────────
        header = tk.Frame(self, bg=BG, pady=18)
        header.pack(fill="x", padx=24)

        tk.Label(header, text="DNS Speed Checker", font=(FONT_FAMILY, 22, "bold"),
                 fg=ACCENT, bg=BG).pack(side="left")
        tk.Label(header, text="FC26 Tools", font=(FONT_FAMILY, 11),
                 fg=FG2, bg=BG).pack(side="left", padx=(10, 0), pady=(6, 0))

        # ── Control bar ──────────────────────────────────────────────────────
        ctrl = tk.Frame(self, bg=BG2, pady=12, padx=24)
        ctrl.pack(fill="x")

        tk.Label(ctrl, text="Rounds:", font=(FONT_FAMILY, 10), fg=FG2, bg=BG2).pack(side="left")
        self._rounds_var = tk.IntVar(value=DEFAULT_ROUNDS)
        tk.Spinbox(ctrl, from_=1, to=10, textvariable=self._rounds_var,
                   width=4, font=(FONT_FAMILY, 10), bg=BG3, fg=FG,
                   buttonbackground=BG3, relief="flat",
                   insertbackground=FG).pack(side="left", padx=(6, 20))

        self._btn = tk.Button(ctrl, text="  Run Test  ", font=(FONT_FAMILY, 11, "bold"),
                              bg=ACCENT, fg="white", relief="flat", cursor="hand2",
                              activebackground="#5a52d5", activeforeground="white",
                              command=self._toggle_test, padx=12, pady=4)
        self._btn.pack(side="left")

        self._status_lbl = tk.Label(ctrl, text="Ready.", font=(FONT_FAMILY, 10),
                                    fg=FG2, bg=BG2)
        self._status_lbl.pack(side="left", padx=20)

        # ── Progress bar ─────────────────────────────────────────────────────
        self._progress = ttk.Progressbar(self, mode="determinate",
                                         style="Custom.Horizontal.TProgressbar")
        self._progress.pack(fill="x", padx=24, pady=(6, 0))

        # ── Results table ─────────────────────────────────────────────────────
        table_frame = tk.Frame(self, bg=BG, padx=24, pady=12)
        table_frame.pack(fill="both", expand=True)

        self._style = ttk.Style(self)
        self._configure_styles()

        cols = ("Rank", "Name", "IP", "Avg ms", "Median ms", "Jitter ms", "Success %", "Score")
        self._tree = ttk.Treeview(table_frame, columns=cols, show="headings",
                                  style="Custom.Treeview", selectmode="browse")

        widths = {"Rank": 55, "Name": 150, "IP": 130, "Avg ms": 90,
                  "Median ms": 100, "Jitter ms": 95, "Success %": 90, "Score": 80}
        for col in cols:
            self._tree.heading(col, text=col, anchor="center")
            self._tree.column(col, width=widths[col], anchor="center", minwidth=50)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._tree.tag_configure("gold",   background="#2a2310", foreground=GOLD)
        self._tree.tag_configure("silver", background="#1e2530", foreground="#cbd5e1")
        self._tree.tag_configure("bronze", background="#1e1a10", foreground="#d97706")
        self._tree.tag_configure("normal", background=BG2,       foreground=FG)
        self._tree.tag_configure("error",  background="#1f1010", foreground=RED)

        # ── Best DNS banner (hidden until test completes) ─────────────────────
        self._banner = tk.Frame(self, bg=BG2, pady=16, padx=24)
        self._banner_title = tk.Label(self._banner, text="", font=(FONT_FAMILY, 12, "bold"),
                                      fg=GOLD, bg=BG2)
        self._banner_title.pack()
        self._banner_detail = tk.Label(self._banner, text="", font=(FONT_FAMILY, 10),
                                       fg=FG2, bg=BG2)
        self._banner_detail.pack()

    def _configure_styles(self):
        s = self._style
        s.theme_use("clam")
        s.configure("Custom.Treeview",
                    background=BG2, foreground=FG, fieldbackground=BG2,
                    rowheight=32, font=(FONT_FAMILY, 10),
                    borderwidth=0, relief="flat")
        s.configure("Custom.Treeview.Heading",
                    background=BG3, foreground=FG2, font=(FONT_FAMILY, 10, "bold"),
                    relief="flat", borderwidth=1)
        s.map("Custom.Treeview",
              background=[("selected", ACCENT)],
              foreground=[("selected", "white")])
        s.configure("Custom.Horizontal.TProgressbar",
                    troughcolor=BG3, background=ACCENT, thickness=6)

    # ── Test logic ────────────────────────────────────────────────────────────

    def _toggle_test(self):
        if self._running:
            self._running = False
            self._btn.configure(text="  Run Test  ", bg=ACCENT)
            self._status("Stopped.")
            return
        self._start_test()

    def _start_test(self):
        self._results = [DnsResult(name=n, ip=ip) for n, ip in DNS_SERVERS]
        self._clear_table()
        self._banner.pack_forget()
        self._running = True
        self._btn.configure(text="  Stop  ", bg=RED)

        rounds = self._rounds_var.get()
        self._progress["maximum"] = len(DNS_SERVERS) * len(TEST_DOMAINS) * rounds
        self._progress["value"] = 0

        self._thread = threading.Thread(target=self._run_tests, args=(rounds,), daemon=True)
        self._thread.start()

    def _run_tests(self, rounds: int):
        step = 0
        for _ in range(rounds):
            for result in self._results:
                if not self._running:
                    break
                for domain in TEST_DOMAINS:
                    if not self._running:
                        break
                    ms = query_dns(result.ip, domain)
                    if ms is not None:
                        result.times.append(ms)
                    else:
                        result.errors += 1
                    step += 1
                    self.after(0, self._update_progress, step, result)
        self.after(0, self._finish)

    def _update_progress(self, step: int, latest: DnsResult):
        self._progress["value"] = step
        avg_str = f"{latest.avg:.1f} ms" if latest.avg else "—"
        self._status(f"Testing {latest.name} ({latest.ip}) … current avg {avg_str}")

    def _finish(self):
        self._running = False
        self._btn.configure(text="  Run Test  ", bg=ACCENT)
        self._populate_table()
        self._show_banner()
        self._status("Done.")

    # ── Table ─────────────────────────────────────────────────────────────────

    def _clear_table(self):
        for row in self._tree.get_children():
            self._tree.delete(row)

    def _populate_table(self):
        self._clear_table()
        sorted_results = sorted(self._results, key=lambda r: r.score())
        tags = ["gold", "silver", "bronze"]

        for rank, res in enumerate(sorted_results, start=1):
            if res.avg is None:
                values = (f"#{rank}", res.name, res.ip, "—", "—", "—",
                          f"{res.success_rate:.0f}%", "—")
                tag = "error"
            else:
                medal = {1: "🥇", 2: "🥈", 3: "🥉"}.get(rank, f"#{rank}")
                values = (
                    medal,
                    res.name,
                    res.ip,
                    f"{res.avg:.1f}",
                    f"{res.median:.1f}",
                    f"{res.jitter:.1f}",
                    f"{res.success_rate:.0f}%",
                    f"{res.score():.1f}",
                )
                tag = tags[rank - 1] if rank <= 3 else "normal"
            self._tree.insert("", "end", values=values, tags=(tag,))

    def _show_banner(self):
        best = min((r for r in self._results if r.avg is not None),
                   key=lambda r: r.score(), default=None)
        if best is None:
            return
        self._banner_title.configure(
            text=f"Best DNS: {best.name}  ({best.ip})"
        )
        self._banner_detail.configure(
            text=(
                f"Avg {best.avg:.1f} ms  |  "
                f"Median {best.median:.1f} ms  |  "
                f"Jitter {best.jitter:.1f} ms  |  "
                f"Success rate {best.success_rate:.0f}%  |  "
                f"Score {best.score():.1f}"
            )
        )
        self._banner.pack(fill="x", padx=24, pady=(0, 16))

    def _status(self, msg: str):
        self._status_lbl.configure(text=msg)


if __name__ == "__main__":
    app = DnsCheckerApp()
    app.mainloop()
