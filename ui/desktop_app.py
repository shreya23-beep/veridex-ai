"""
VeriDex AI - Native Windows Desktop Application
Autonomous On-Device Scam Protection Client
Integrates ONNX Runtime ML engine, NLP manipulation analysis,
AES-256 / DPAPI local encrypted vault, and real-time clipboard protection.
"""

import sys
import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# Ensure path includes root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.ml_engine import engine
from core.nlp_analyzer import nlp_analyzer
from security.threat_db import threat_db
from daemon.clipboard_watcher import interceptor

# Dark Slate & Cyber Security Theme Palette
COLOR_BG = "#0b0f19"
COLOR_CARD = "#111827"
COLOR_INPUT = "#0f172a"
COLOR_CYAN = "#38bdf8"
COLOR_GREEN = "#22c55e"
COLOR_RED = "#ef4444"
COLOR_AMBER = "#f59e0b"
COLOR_TEXT = "#f8fafc"
COLOR_MUTED = "#94a3b8"

class VeridexDesktopApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VeriDex AI — Autonomous On-Device Scam Protection")
        self.root.geometry("880x680")
        self.root.minsize(800, 600)
        self.root.config(bg=COLOR_BG)

        self._build_header()
        self._build_notebook()
        self._build_footer()

        # Start clipboard interceptor by default
        interceptor.on_threat_callback = self._on_clipboard_threat
        interceptor.start()

    def _build_header(self):
        header_frame = tk.Frame(self.root, bg=COLOR_BG, padx=20, pady=12)
        header_frame.pack(fill="x")

        # Title & Branding
        title_box = tk.Frame(header_frame, bg=COLOR_BG)
        title_box.pack(side="left")

        title_label = tk.Label(
            title_box, text="🛡️ VERIDEX AI", font=("Arial", 16, "bold"),
            fg=COLOR_CYAN, bg=COLOR_BG
        )
        title_label.pack(anchor="w")

        subtitle_label = tk.Label(
            title_box, text="Autonomous On-Device Scam Protection • 100% Offline & Zero-Cloud Reliance",
            font=("Arial", 9), fg=COLOR_MUTED, bg=COLOR_BG
        )
        subtitle_label.pack(anchor="w")

        # Status Badges
        badge_box = tk.Frame(header_frame, bg=COLOR_BG)
        badge_box.pack(side="right")

        onnx_badge = tk.Label(
            badge_box, text="⚡ ONNX Runtime (CPU)", font=("Arial", 9, "bold"),
            fg=COLOR_CYAN, bg="#1e293b", padx=10, pady=4
        )
        onnx_badge.pack(side="left", padx=5)

        dpapi_badge = tk.Label(
            badge_box, text="🔐 DPAPI / AES-256 Vault", font=("Arial", 9, "bold"),
            fg=COLOR_GREEN, bg="#14532d", padx=10, pady=4
        )
        dpapi_badge.pack(side="left", padx=5)

    def _build_notebook(self):
        # Configure Notebook Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=COLOR_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=COLOR_CARD, foreground=COLOR_TEXT,
                        padding=[15, 8], font=("Arial", 10, "bold"), borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", COLOR_INPUT)],
                  foreground=[("selected", COLOR_CYAN)])

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=10)

        # Tab 1: URL Scanner
        self.tab_url = tk.Frame(self.notebook, bg=COLOR_CARD, padx=20, pady=15)
        self.notebook.add(self.tab_url, text="  🌐 URL Radar & ML Inspector  ")
        self._build_url_tab()

        # Tab 2: NLP Manipulation Analyzer
        self.tab_nlp = tk.Frame(self.notebook, bg=COLOR_CARD, padx=20, pady=15)
        self.notebook.add(self.tab_nlp, text="  🧠 NLP Manipulation Cues  ")
        self._build_nlp_tab()

        # Tab 3: Encrypted Vault
        self.tab_vault = tk.Frame(self.notebook, bg=COLOR_CARD, padx=20, pady=15)
        self.notebook.add(self.tab_vault, text="  🔐 Encrypted Threat Vault  ")
        self._build_vault_tab()

    def _build_url_tab(self):
        # Input Section
        lbl = tk.Label(self.tab_url, text="Enter Target URL to Inspect (On-Device Inference):",
                       font=("Arial", 11, "bold"), fg=COLOR_TEXT, bg=COLOR_CARD)
        lbl.pack(anchor="w", pady=(0, 6))

        input_box = tk.Frame(self.tab_url, bg=COLOR_CARD)
        input_box.pack(fill="x", pady=(0, 10))

        self.url_entry = tk.Entry(input_box, font=("Arial", 11), bg=COLOR_INPUT,
                                  fg=COLOR_TEXT, insertbackground="white", relief="flat")
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 10))
        self.url_entry.insert(0, "http://paypa1-security-verification.com/login")

        scan_btn = tk.Button(input_box, text="🔍 Inspect On-Device", font=("Arial", 10, "bold"),
                             bg="#0284c7", fg="white", activebackground="#0369a1",
                             relief="flat", padx=16, command=self._scan_url_click)
        scan_btn.pack(side="right")

        # Preset Samples
        preset_frame = tk.Frame(self.tab_url, bg=COLOR_CARD)
        preset_frame.pack(fill="x", pady=(0, 15))

        tk.Label(preset_frame, text="Quick Presets:", font=("Arial", 9, "bold"),
                 fg=COLOR_MUTED, bg=COLOR_CARD).pack(side="left", padx=(0, 8))

        presets = [
            ("⚠️ PayPal Typosquat", "http://paypa1-security-verification.com/login"),
            ("⚠️ Chase Phishing", "http://chase-bank-customer-support-update.top/account/verify"),
            ("⚠️ Bare IP Attack", "http://192.168.1.105/bankofamerica/secure-auth.html"),
            ("✅ Clean GitHub", "https://github.com/torvalds/linux")
        ]
        for name, u in presets:
            btn = tk.Button(preset_frame, text=name, font=("Arial", 8), bg="#1f2937",
                            fg=COLOR_TEXT, relief="flat", padx=6, pady=2,
                            command=lambda target=u: self._load_preset(target))
            btn.pack(side="left", padx=4)

        # Verdict Display Card
        self.verdict_frame = tk.Frame(self.tab_url, bg=COLOR_INPUT, padx=15, pady=15, relief="flat")
        self.verdict_frame.pack(fill="x", pady=10)

        self.verdict_label = tk.Label(
            self.verdict_frame, text="Status: Ready for inspection",
            font=("Arial", 13, "bold"), fg=COLOR_GREEN, bg=COLOR_INPUT
        )
        self.verdict_label.pack(anchor="w")

        self.meta_label = tk.Label(
            self.verdict_frame, text="Latency: -- | Engine: ONNX Runtime | Privacy: 100% Offline",
            font=("Arial", 9), fg=COLOR_MUTED, bg=COLOR_INPUT
        )
        self.meta_label.pack(anchor="w", pady=(4, 0))

        # Explainable AI (XAI) Box
        tk.Label(self.tab_url, text="Explainable AI (XAI) Risk Factors:",
                 font=("Arial", 10, "bold"), fg=COLOR_CYAN, bg=COLOR_CARD).pack(anchor="w", pady=(10, 4))

        self.xai_text = scrolledtext.ScrolledText(
            self.tab_url, height=7, bg=COLOR_INPUT, fg=COLOR_TEXT,
            font=("Consolas", 10), insertbackground="white", relief="flat"
        )
        self.xai_text.pack(fill="both", expand=True)

    def _build_nlp_tab(self):
        lbl = tk.Label(self.tab_nlp, text="Paste Suspicious Email, SMS, or Fake Website Text:",
                       font=("Arial", 11, "bold"), fg=COLOR_TEXT, bg=COLOR_CARD)
        lbl.pack(anchor="w", pady=(0, 6))

        self.nlp_entry = scrolledtext.ScrolledText(
            self.tab_nlp, height=7, bg=COLOR_INPUT, fg=COLOR_TEXT,
            font=("Consolas", 10), insertbackground="white", relief="flat"
        )
        self.nlp_entry.pack(fill="x", pady=(0, 10))
        self.nlp_entry.insert("1.0", "URGENT NOTICE: Your PayPal account is frozen. Confirm your password and verify SSN within 24 hours to prevent permanent account suspension!")

        btn_row = tk.Frame(self.tab_nlp, bg=COLOR_CARD)
        btn_row.pack(fill="x", pady=(0, 10))

        nlp_btn = tk.Button(btn_row, text="🧠 Analyze Manipulation Cues", font=("Arial", 10, "bold"),
                            bg="#0284c7", fg="white", activebackground="#0369a1",
                            relief="flat", padx=16, command=self._scan_nlp_click)
        nlp_btn.pack(side="left")

        # NLP Verdict
        self.nlp_verdict_label = tk.Label(
            self.tab_nlp, text="Threat Level: Ready", font=("Arial", 12, "bold"),
            fg=COLOR_GREEN, bg=COLOR_CARD
        )
        self.nlp_verdict_label.pack(anchor="w", pady=(10, 4))

        self.nlp_results_text = scrolledtext.ScrolledText(
            self.tab_nlp, height=7, bg=COLOR_INPUT, fg=COLOR_TEXT,
            font=("Consolas", 10), insertbackground="white", relief="flat"
        )
        self.nlp_results_text.pack(fill="both", expand=True)

    def _build_vault_tab(self):
        top_bar = tk.Frame(self.tab_vault, bg=COLOR_CARD)
        top_bar.pack(fill="x", pady=(0, 10))

        lbl = tk.Label(top_bar, text="AES-256 / DPAPI Encrypted Vault Audit Log:",
                       font=("Arial", 11, "bold"), fg=COLOR_TEXT, bg=COLOR_CARD)
        lbl.pack(side="left")

        refresh_btn = tk.Button(top_bar, text="🔄 Refresh Vault", font=("Arial", 9),
                                bg="#1f2937", fg=COLOR_TEXT, relief="flat", padx=10,
                                command=self._refresh_vault_table)
        refresh_btn.pack(side="right", padx=5)

        self.vault_tree = ttk.Treeview(
            self.tab_vault,
            columns=("time", "url", "verdict", "risk", "latency", "source"),
            show="headings", height=12
        )
        self.vault_tree.heading("time", text="Timestamp")
        self.vault_tree.heading("url", text="Target URL (Decrypted)")
        self.vault_tree.heading("verdict", text="Verdict")
        self.vault_tree.heading("risk", text="Risk Score")
        self.vault_tree.heading("latency", text="Latency")
        self.vault_tree.heading("source", text="Source")

        self.vault_tree.column("time", width=140)
        self.vault_tree.column("url", width=340)
        self.vault_tree.column("verdict", width=140)
        self.vault_tree.column("risk", width=80)
        self.vault_tree.column("latency", width=70)
        self.vault_tree.column("source", width=90)

        self.vault_tree.pack(fill="both", expand=True)
        self._refresh_vault_table()

    def _build_footer(self):
        footer_frame = tk.Frame(self.root, bg=COLOR_BG, padx=20, pady=8)
        footer_frame.pack(fill="x", side="bottom")

        stats = threat_db.get_vault_statistics()
        self.footer_label = tk.Label(
            footer_frame,
            text=f"Total Local Scans: {stats['total_scans']} | Threats Blocked: {stats['threats_blocked']} | Average Latency: {stats['avg_latency_ms']} ms",
            font=("Arial", 9), fg=COLOR_MUTED, bg=COLOR_BG
        )
        self.footer_label.pack(side="left")

    def _load_preset(self, url: str):
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, url)
        self._scan_url_click()

    def _scan_url_click(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please provide a valid URL to scan.")
            return

        res = engine.inspect_url(url)
        threat_db.log_scan(res, source="DESKTOP_UI")

        # Update UI
        color = COLOR_RED if res["is_threat"] else COLOR_GREEN
        self.verdict_label.config(
            text=f"{res['verdict']} (Risk: {res['risk_score']}%)",
            fg=color
        )
        self.meta_label.config(
            text=f"Latency: {res['latency_ms']} ms | Engine: {res['engine']} | Hardware: CPU (Zero-Cloud)"
        )

        # XAI
        self.xai_text.delete("1.0", tk.END)
        self.xai_text.insert(tk.END, "=== EXPLAINABLE AI RISK BREAKDOWN ===\n\n")
        for f in res["risk_factors"]:
            symbol = "🚨" if res["is_threat"] else "✅"
            self.xai_text.insert(tk.END, f"{symbol} {f}\n")

        self._refresh_vault_table()

    def _scan_nlp_click(self):
        text = self.nlp_entry.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Input Error", "Please enter text to analyze.")
            return

        res = nlp_analyzer.analyze_text(text)
        color = COLOR_RED if res["threat_level"] in ("CRITICAL", "SUSPICIOUS") else COLOR_GREEN
        self.nlp_verdict_label.config(
            text=f"Threat Level: {res['threat_level']} (Manipulation Score: {res['risk_score']}%)",
            fg=color
        )

        self.nlp_results_text.delete("1.0", tk.END)
        self.nlp_results_text.insert(tk.END, f"Summary: {res['summary']}\n\n")
        self.nlp_results_text.insert(tk.END, "=== DETECTED MANIPULATION CUES ===\n")
        for cue in res["detected_cues"]:
            self.nlp_results_text.insert(
                tk.END,
                f"\n[+] {cue['category']} (+{cue['category_risk']}%)\n    Desc: {cue['description']}\n    Matches: {', '.join(cue['matched_tokens'])}\n"
            )

    def _refresh_vault_table(self):
        for item in self.vault_tree.get_children():
            self.vault_tree.delete(item)

        scans = threat_db.get_recent_scans(50)
        for s in scans:
            self.vault_tree.insert("", "end", values=(
                s["timestamp"], s["url"], s["verdict"],
                f"{s['risk_score']}%", f"{s['latency_ms']}ms", s["source"]
            ))

        stats = threat_db.get_vault_statistics()
        if hasattr(self, "footer_label"):
            self.footer_label.config(
                text=f"Total Local Scans: {stats['total_scans']} | Threats Blocked: {stats['threats_blocked']} | Average Latency: {stats['avg_latency_ms']} ms"
            )

    def _on_clipboard_threat(self, result: dict):
        # Called when clipboard interceptor detects a threat
        self.root.after(0, lambda: self._handle_clipboard_event(result))

    def _handle_clipboard_event(self, result: dict):
        self._refresh_vault_table()
        messagebox.showwarning(
            "VeriDex AI — Threat Intercepted",
            f"Alert! Dangerous link intercepted from clipboard:\n\n{result['url']}\n\nVerdict: {result['verdict']}\nRisk: {result['risk_score']}%\n\nThreat logged to your DPAPI encrypted vault."
        )

if __name__ == "__main__":
    root = tk.Tk()
    app = VeridexDesktopApp(root)
    root.mainloop()
