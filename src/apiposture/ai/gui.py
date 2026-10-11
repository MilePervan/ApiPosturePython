"""
Graficko sucelje (GUI) za AI filter lazno pozitivnih nalaza.

Pokretanje:
    python -m apiposture.ai.gui          # stvarno skeniranje
    python -m apiposture.ai.gui --demo   # demo podaci (bez skeniranja)

Sucelje omogucuje:
  - odabir projekta i skeniranje u pozadini (sucelje se ne zamrzava)
  - pregled svakog nalaza: alarm, ozbiljnost, izvorni kod, AI prijedlog
  - odluku klikom ili precem tipkovnice (F / T / S)
  - spremanje odluka u dataset (petlja ucenja)
  - zavrsni sazetak i spremanje PDF izvjestaja

Koristi samo Tkinter (dio standardne Python biblioteke).
"""

import sys
import json
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

# Omogucuje pokretanje na bilo koji nacin (python -m, direktno putanjom,
# gumbom "Run" u VS Codeu, dvoklikom): mapa src dodaje se u putanju,
# pa se paket apiposture pronalazi i kad nije instaliran pip-om.
_SRC = Path(__file__).resolve().parents[2]
if (_SRC / "apiposture").is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# ---------------------------------------------------------------- izgled
C = {
    "bg": "#f4f6f8", "header": "#2c3e50", "card": "#ffffff",
    "text": "#2c3e50", "muted": "#7f8c8d", "border": "#dfe4ea",
    "green": "#27ae60", "green_h": "#219150",
    "red": "#c0392b", "red_h": "#a93226",
    "grey": "#7f8c8d", "grey_h": "#6c7a7d",
    "disabled": "#d5dbdf", "code_bg": "#1e272e", "code_fg": "#dfe6e9",
    "blue": "#2980b9", "soft_green": "#e9f7ef", "soft_red": "#fdedec",
    "soft_grey": "#f2f3f4",
}
SEVERITY = {
    "critical": ("KRITIČNO", "#c0392b"),
    "high": ("VISOKO", "#e67e22"),
    "medium": ("SREDNJE", "#d4ac0d"),
    "low": ("NISKO", "#2980b9"),
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
FONT = "Segoe UI"
MONO = "Consolas"


def load_alarm_names() -> dict:
    """Ucitava nazive alarma iz alarm_descriptions.json (ako postoji)."""
    path = Path(__file__).parent / "alarm_descriptions.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {k: v.get("name", k) for k, v in data.items()}
    except Exception:
        return {}


# ---------------------------------------------------------------- skeniranje
def collect_findings(project_path: str) -> list:
    """
    Pokrece skener i AI filter te vraca nalaze s AI prijedlogom.
    Koristi sirove nalaze (prije filtera) kako bi se za svaki nalaz
    mogao prikazati prijedlog filtera i donijeti ljudska odluka.
    """
    from apiposture.core.analysis.project_analyzer import (
        ProjectAnalyzer, deduplicate_endpoints)
    from apiposture.core.models.scan_result import ScanResult
    from apiposture.ai.filter import process_findings, read_endpoint_code
    from apiposture.ai.config import AIFilterConfig

    analyzer = ProjectAnalyzer()
    path = Path(project_path)
    result = ScanResult(scan_path=path)
    for fp in analyzer._get_files(path):
        analyzer._scan_file(fp, result)
    result.endpoints = deduplicate_endpoints(result.endpoints)
    analyzer.classifier.classify_all(result.endpoints)
    raw = analyzer.rule_engine.evaluate_all(result.endpoints)
    raw = [f for f in raw if analyzer.config.is_rule_enabled(f.rule_id)]

    config = AIFilterConfig(use_llm=True, mode="automatic", use_rules=True,
                            auto_suppress_threshold=90, protect_critical=True)
    ai = process_findings(raw, config=config)

    items = []
    for f, suggested_fp in ([(x, True) for x in ai["suppressed"]] +
                            [(x, False) for x in ai["kept"]]):
        f["code"] = read_endpoint_code(f.get("file_path", ""), f.get("line", 1))
        f["suggest_fp"] = suggested_fp
        items.append(f)
    items.sort(key=lambda x: (SEV_ORDER.get(str(x.get("severity", "")).lower(), 9),
                              x.get("route", "")))
    return items


def demo_findings() -> list:
    """Demo podaci za prikaz sucelja bez skeniranja."""
    return [
        {"alarm": "AP004", "method": "POST", "route": "/deserialize",
         "severity": "critical", "suggest_fp": False, "ai_source": "none",
         "confidence": 0,
         "code": "@app.route('/deserialize', methods=['POST'])\n"
                 "def deserialize_data():\n"
                 "    serialized = request.form.get('serialized_data', '')\n"
                 "    decoded = base64.b64decode(serialized)\n"
                 "    user = pickle.loads(decoded)\n"
                 "    return render_template('result.html', user=user)"},
        {"alarm": "AP001", "method": "GET", "route": "/admin/config",
         "severity": "high", "suggest_fp": False, "ai_source": "none",
         "confidence": 0,
         "code": "@app.route('/admin/config')\n"
                 "def admin_config():\n"
                 "    \"\"\"Admin config - should not be public.\"\"\"\n"
                 "    return jsonify({'config': {}})"},
        {"alarm": "AP001", "method": "GET", "route": "/",
         "severity": "high", "suggest_fp": True, "ai_source": "rule",
         "confidence": 95,
         "code": "@app.route('/')\n"
                 "def index():\n"
                 "    return render_template('index.html')"},
        {"alarm": "AP008", "method": "GET", "route": "/lab",
         "severity": "high", "suggest_fp": True, "ai_source": "rule",
         "confidence": 95,
         "code": "@app.route('/lab')\n"
                 "def lab():\n"
                 "    return render_template('lab.html')"},
    ]


# ---------------------------------------------------------------- dugme
class FlatButton(tk.Label):
    """Ravno dugme s citljivim neaktivnim stanjem i hover efektom."""

    def __init__(self, parent, text, color, hover, command, **kw):
        super().__init__(parent, text=text, bg=color, fg="white",
                         font=(FONT, 11, "bold"), padx=22, pady=10,
                         cursor="hand2", **kw)
        self.color, self.hover, self.command = color, hover, command
        self.enabled = True
        self.bind("<Button-1>", lambda e: self.enabled and self.command())
        self.bind("<Enter>", lambda e: self.enabled and self.config(bg=self.hover))
        self.bind("<Leave>", lambda e: self.enabled and self.config(bg=self.color))

    def set_enabled(self, on: bool):
        self.enabled = on
        self.config(bg=self.color if on else C["disabled"],
                    fg="white" if on else "#9aa5ad",
                    cursor="hand2" if on else "arrow")


# ---------------------------------------------------------------- sucelje
class FilterGUI:
    def __init__(self, root, demo=False):
        self.root = root
        self.demo = demo
        self.alarm_names = load_alarm_names()
        self.items, self.index = [], 0
        self.decisions = {}            # index -> "FALSE" | "TRUE" | "SKIP"
        self.project = None

        root.title("ApiPosture - AI filter lažno pozitivnih nalaza")
        root.geometry("1180x760")
        root.minsize(1000, 680)
        root.configure(bg=C["bg"])

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("G.Horizontal.TProgressbar", troughcolor=C["border"],
                        background=C["green"], bordercolor=C["border"],
                        lightcolor=C["green"], darkcolor=C["green"])
        style.configure("B.Horizontal.TProgressbar", troughcolor=C["border"],
                        background=C["blue"], bordercolor=C["border"],
                        lightcolor=C["blue"], darkcolor=C["blue"])

        self._build_header()
        self._build_footer()
        self._build_body()
        self._show_empty()

        for key, choice in (("f", "FALSE"), ("t", "TRUE"), ("s", "SKIP")):
            root.bind(f"<KeyPress-{key}>", lambda e, c=choice: self.decide(c))

        if demo:
            root.after(100, lambda: self._on_scan_done(demo_findings(), "demo projekt"))

    # ------------------------------------------------------------ gradnja
    def _build_header(self):
        h = tk.Frame(self.root, bg=C["header"], height=64)
        h.pack(fill="x")
        h.pack_propagate(False)
        tk.Label(h, text="ApiPosture", bg=C["header"], fg="white",
                 font=(FONT, 17, "bold")).pack(side="left", padx=(20, 4))
        tk.Label(h, text="AI filter", bg=C["header"], fg="#95a5a6",
                 font=(FONT, 17)).pack(side="left", padx=(0, 24))
        self.scan_btn = FlatButton(h, "Odaberi projekt i skeniraj", C["green"],
                                   C["green_h"], self.on_scan)
        self.scan_btn.pack(side="left", pady=12)
        self.project_lbl = tk.Label(h, text="Nije odabran projekt", bg=C["header"],
                                    fg="#bdc3c7", font=(FONT, 10))
        self.project_lbl.pack(side="left", padx=16)
        self.save_var = tk.BooleanVar(value=True)
        tk.Checkbutton(h, text="Spremaj odluke u dataset", variable=self.save_var,
                       bg=C["header"], fg="white", selectcolor=C["header"],
                       activebackground=C["header"], activeforeground="white",
                       font=(FONT, 10)).pack(side="right", padx=20)

    def _build_body(self):
        body = tk.Frame(self.root, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=20, pady=(16, 0))

        # ---- bocna traka
        side = tk.Frame(body, bg=C["card"], width=270,
                        highlightbackground=C["border"], highlightthickness=1)
        side.pack(side="right", fill="y", padx=(16, 0))
        side.pack_propagate(False)
        tk.Label(side, text="NAPREDAK", bg=C["card"], fg=C["muted"],
                 font=(FONT, 9, "bold")).pack(anchor="w", padx=16, pady=(16, 4))
        self.prog_lbl = tk.Label(side, text="0 / 0", bg=C["card"], fg=C["text"],
                                 font=(FONT, 20, "bold"))
        self.prog_lbl.pack(anchor="w", padx=16)
        self.prog = ttk.Progressbar(side, style="G.Horizontal.TProgressbar",
                                    maximum=1, value=0)
        self.prog.pack(fill="x", padx=16, pady=(6, 14))

        self.stat_lbls = {}
        for key, label, color in (("TRUE", "Zadržano (ranjivost)", C["red"]),
                                  ("FALSE", "Sakriveno (lažni alarm)", C["green"]),
                                  ("SKIP", "Preskočeno", C["grey"])):
            row = tk.Frame(side, bg=C["card"])
            row.pack(fill="x", padx=16, pady=2)
            tk.Label(row, text="●", fg=color, bg=C["card"],
                     font=(FONT, 11)).pack(side="left")
            tk.Label(row, text=label, bg=C["card"], fg=C["text"],
                     font=(FONT, 10)).pack(side="left", padx=6)
            v = tk.Label(row, text="0", bg=C["card"], fg=C["text"],
                         font=(FONT, 10, "bold"))
            v.pack(side="right")
            self.stat_lbls[key] = v

        tk.Frame(side, bg=C["border"], height=1).pack(fill="x", padx=16, pady=14)
        tk.Label(side, text="NALAZI", bg=C["card"], fg=C["muted"],
                 font=(FONT, 9, "bold")).pack(anchor="w", padx=16, pady=(0, 4))
        lf = tk.Frame(side, bg=C["card"])
        lf.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.listbox = tk.Listbox(lf, font=(MONO, 9), bd=0, highlightthickness=0,
                                  activestyle="none", selectbackground="#d6eaf8",
                                  selectforeground=C["text"], fg=C["text"])
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.listbox.yview)
        self.listbox.config(yscrollcommand=sb.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.listbox.bind("<<ListboxSelect>>", self._on_list_select)

        # ---- glavna kartica
        self.card = tk.Frame(body, bg=C["card"],
                             highlightbackground=C["border"], highlightthickness=1)
        self.card.pack(side="left", fill="both", expand=True)

        # prazno stanje
        self.empty = tk.Frame(self.card, bg=C["card"])
        tk.Label(self.empty, text="🔍", bg=C["card"], font=(FONT, 40)).pack(pady=(110, 6))
        tk.Label(self.empty, text="Nijedan projekt nije skeniran", bg=C["card"],
                 fg=C["text"], font=(FONT, 16, "bold")).pack()
        tk.Label(self.empty, bg=C["card"], fg=C["muted"], font=(FONT, 11),
                 justify="center",
                 text="Klikni »Odaberi projekt i skeniraj« i odaberi mapu projekta.\n"
                      "Za svaki nalaz prikazat će se izvorni kod i prijedlog AI filtera,\n"
                      "a ti odlučuješ je li riječ o stvarnoj ranjivosti.").pack(pady=10)

        # ucitavanje
        self.loading = tk.Frame(self.card, bg=C["card"])
        tk.Label(self.loading, text="Skeniranje u tijeku…", bg=C["card"],
                 fg=C["text"], font=(FONT, 15, "bold")).pack(pady=(160, 10))
        tk.Label(self.loading, text="Pokreću se skener, pravila i jezični model.",
                 bg=C["card"], fg=C["muted"], font=(FONT, 11)).pack()
        self.spin = ttk.Progressbar(self.loading, style="B.Horizontal.TProgressbar",
                                    mode="indeterminate", length=320)
        self.spin.pack(pady=18)

        # pregled nalaza
        self.view = tk.Frame(self.card, bg=C["card"])
        top = tk.Frame(self.view, bg=C["card"])
        top.pack(fill="x", padx=24, pady=(20, 4))
        self.alarm_lbl = tk.Label(top, bg=C["card"], fg=C["text"],
                                  font=(FONT, 18, "bold"))
        self.alarm_lbl.pack(side="left")
        self.alarm_name = tk.Label(top, bg=C["card"], fg=C["muted"], font=(FONT, 12))
        self.alarm_name.pack(side="left", padx=10)
        self.sev_badge = tk.Label(top, fg="white", font=(FONT, 9, "bold"),
                                  padx=10, pady=3)
        self.sev_badge.pack(side="right")

        ep = tk.Frame(self.view, bg=C["card"])
        ep.pack(fill="x", padx=24, pady=(2, 12))
        self.method_badge = tk.Label(ep, bg=C["blue"], fg="white",
                                     font=(MONO, 10, "bold"), padx=8, pady=2)
        self.method_badge.pack(side="left")
        self.route_lbl = tk.Label(ep, bg=C["card"], fg=C["text"], font=(MONO, 12))
        self.route_lbl.pack(side="left", padx=10)

        tk.Label(self.view, text="Izvorni kod", bg=C["card"], fg=C["muted"],
                 font=(FONT, 9, "bold")).pack(anchor="w", padx=24)
        cf = tk.Frame(self.view, bg=C["code_bg"])
        cf.pack(fill="both", expand=True, padx=24, pady=(4, 14))
        self.code = tk.Text(cf, bg=C["code_bg"], fg=C["code_fg"], font=(MONO, 10),
                            bd=0, padx=12, pady=10, wrap="none",
                            insertbackground=C["code_fg"], height=12)
        csb = ttk.Scrollbar(cf, orient="vertical", command=self.code.yview)
        self.code.config(yscrollcommand=csb.set)
        self.code.pack(side="left", fill="both", expand=True)
        csb.pack(side="right", fill="y")
        self.code.tag_configure("danger", foreground="#ff7675")

        self.ai_box = tk.Frame(self.view, bg=C["soft_grey"])
        self.ai_box.pack(fill="x", padx=24, pady=(0, 20))
        self.ai_bar = tk.Frame(self.ai_box, width=5, bg=C["grey"])
        self.ai_bar.pack(side="left", fill="y")
        inner = tk.Frame(self.ai_box, bg=C["soft_grey"])
        inner.pack(side="left", fill="both", expand=True, padx=14, pady=10)
        self.ai_title = tk.Label(inner, bg=C["soft_grey"], fg=C["text"],
                                 font=(FONT, 11, "bold"), anchor="w")
        self.ai_title.pack(fill="x")
        self.ai_text = tk.Label(inner, bg=C["soft_grey"], fg=C["text"],
                                font=(FONT, 10), anchor="w", justify="left",
                                wraplength=700)
        self.ai_text.pack(fill="x", pady=(2, 0))
        self.inner_ai = inner

        # sazetak
        self.summary = tk.Frame(self.card, bg=C["card"])

    def _build_footer(self):
        f = tk.Frame(self.root, bg=C["bg"])
        f.pack(side="bottom", fill="x", padx=20, pady=16)
        self.btn_false = FlatButton(f, "Lažni alarm (sakrij)   F", C["green"],
                                    C["green_h"], lambda: self.decide("FALSE"))
        self.btn_true = FlatButton(f, "Prava ranjivost (zadrži)   T", C["red"],
                                   C["red_h"], lambda: self.decide("TRUE"))
        self.btn_skip = FlatButton(f, "Preskoči   S", C["grey"], C["grey_h"],
                                   lambda: self.decide("SKIP"))
        for b in (self.btn_false, self.btn_true, self.btn_skip):
            b.pack(side="left", padx=(0, 10))
        self.status = tk.Label(f, text="", bg=C["bg"], fg=C["muted"], font=(FONT, 10))
        self.status.pack(side="right")
        self._set_buttons(False)

    # ------------------------------------------------------------ stanja
    def _set_buttons(self, on):
        for b in (self.btn_false, self.btn_true, self.btn_skip):
            b.set_enabled(on)

    def _switch(self, frame):
        for fr in (self.empty, self.loading, self.view, self.summary):
            fr.pack_forget()
        frame.pack(fill="both", expand=True)

    def _show_empty(self):
        self._switch(self.empty)
        self._set_buttons(False)

    # ------------------------------------------------------------ skeniranje
    def on_scan(self):
        path = filedialog.askdirectory(title="Odaberi projekt za skeniranje")
        if not path:
            return
        self.project = path
        self.project_lbl.config(text=Path(path).name, fg="white")
        self.scan_btn.set_enabled(False)
        self._set_buttons(False)
        self._switch(self.loading)
        self.spin.start(12)
        self.status.config(text="Skeniranje…")

        def worker():
            try:
                items = collect_findings(path)
                self.root.after(0, lambda: self._on_scan_done(items, Path(path).name))
            except Exception as e:
                self.root.after(0, lambda err=e: self._on_scan_error(err))

        threading.Thread(target=worker, daemon=True).start()

    def _on_scan_error(self, err):
        self.spin.stop()
        self.scan_btn.set_enabled(True)
        self._show_empty()
        self.status.config(text="")
        msg = str(err)
        if isinstance(err, ModuleNotFoundError):
            msg += ("\n\nPython koji pokreće sučelje:\n" + sys.executable +
                    "\n\nAko nedostaje paket (npr. ollama ili yaml), instaliraj ga "
                    "za ovaj Python:\n\"" + sys.executable + "\" -m pip install "
                    + (err.name or "ime_paketa"))
        messagebox.showerror("Greška pri skeniranju", msg)

    def _on_scan_done(self, items, name):
        self.spin.stop()
        self.scan_btn.set_enabled(True)
        self.items, self.index, self.decisions = items, 0, {}
        self.project_lbl.config(text=name, fg="white")
        self.listbox.delete(0, "end")
        for it in items:
            self.listbox.insert("end", f"○ {it['alarm']} {it['method']:<6} {it['route']}")
        self.prog.config(maximum=max(len(items), 1))
        self._refresh_stats()
        if not items:
            self._show_empty()
            self.status.config(text="Skener nije pronašao nalaze.")
            return
        self._show_item()

    # ------------------------------------------------------------ prikaz
    def _show_item(self):
        if self.index >= len(self.items):
            self._show_summary()
            return
        it = self.items[self.index]
        self._switch(self.view)
        self._set_buttons(True)

        self.alarm_lbl.config(text=it["alarm"])
        self.alarm_name.config(text=self.alarm_names.get(it["alarm"], ""))
        sev = str(it.get("severity", "")).lower()
        txt, col = SEVERITY.get(sev, (sev.upper() or "?", C["grey"]))
        self.sev_badge.config(text=txt, bg=col)
        self.method_badge.config(text=it["method"],
                                 bg=C["red"] if it["method"] != "GET" else C["blue"])
        self.route_lbl.config(text=it["route"])

        self.code.config(state="normal")
        self.code.delete("1.0", "end")
        self.code.insert("1.0", it.get("code") or "(izvorni kod nije dostupan)")
        for word in ("pickle.loads", "eval(", "exec(", "b64decode"):
            start = "1.0"
            while True:
                pos = self.code.search(word, start, stopindex="end")
                if not pos:
                    break
                end = f"{pos}+{len(word)}c"
                self.code.tag_add("danger", pos, end)
                start = end
        self.code.config(state="disabled")

        self._show_suggestion(it)
        self.listbox.selection_clear(0, "end")
        self.listbox.selection_set(self.index)
        self.listbox.see(self.index)
        self.status.config(text=f"Nalaz {self.index + 1} od {len(self.items)}")

    def _show_suggestion(self, it):
        if it.get("suggest_fp"):
            src = {"rule": "validiranim pravilom", "llm": "jezičnim modelom"}.get(
                it.get("ai_source"), "filterom")
            color, bg = C["green"], C["soft_green"]
            title = f"AI prijedlog: lažni alarm  ·  sigurnost {it.get('confidence', 0)}%"
            text = (f"Nalaz je prepoznat {src} kao lažno pozitivan. "
                    "Ako se slažeš, odaberi »Lažni alarm«.")
        else:
            critical = str(it.get("severity", "")).lower() == "critical"
            color, bg = C["red"], C["soft_red"]
            title = "AI prijedlog: zadržati i pregledati"
            text = ("Ni pravila ni jezični model nisu s dovoljnom sigurnošću "
                    "potvrdili da je riječ o lažnom alarmu.")
            if critical:
                text += " Alarm je kritičan i nikad se ne sakriva automatski."
        for w in (self.ai_box, self.inner_ai, self.ai_title, self.ai_text):
            w.config(bg=bg)
        self.ai_bar.config(bg=color)
        self.ai_title.config(text=title, fg=color)
        self.ai_text.config(text=text)

    def _on_list_select(self, _event):
        sel = self.listbox.curselection()
        if sel and self.items and self.index < len(self.items):
            self.index = sel[0]
            self._show_item()

    # ------------------------------------------------------------ odluke
    def decide(self, choice):
        if not self.btn_false.enabled or self.index >= len(self.items):
            return
        it = self.items[self.index]
        self.decisions[self.index] = choice
        mark, color = {"FALSE": ("✓", C["green"]), "TRUE": ("!", C["red"]),
                       "SKIP": ("–", C["grey"])}[choice]
        self.listbox.delete(self.index)
        self.listbox.insert(self.index,
                            f"{mark} {it['alarm']} {it['method']:<6} {it['route']}")
        self.listbox.itemconfig(self.index, fg=color)

        if choice != "SKIP" and self.save_var.get() and not self.demo:
            try:
                from apiposture.ai.filter import save_to_dataset
                label = "FALSE_POSITIVE" if choice == "FALSE" else "TRUE_POSITIVE"
                save_to_dataset(it, label, 100)
            except Exception as e:
                self.status.config(text=f"Odluka nije spremljena: {e}")

        self._refresh_stats()
        nxt = [i for i in range(len(self.items)) if i not in self.decisions]
        self.index = nxt[0] if nxt else len(self.items)
        self._show_item()

    def _refresh_stats(self):
        done = len(self.decisions)
        self.prog_lbl.config(text=f"{done} / {len(self.items)}")
        self.prog.config(value=done)
        for key, lbl in self.stat_lbls.items():
            lbl.config(text=str(sum(1 for v in self.decisions.values() if v == key)))

    # ------------------------------------------------------------ sazetak
    def _show_summary(self):
        self._set_buttons(False)
        for w in self.summary.winfo_children():
            w.destroy()
        n = len(self.items)
        cnt = {k: sum(1 for v in self.decisions.values() if v == k)
               for k in ("TRUE", "FALSE", "SKIP")}
        tk.Label(self.summary, text="Pregled završen", bg=C["card"], fg=C["text"],
                 font=(FONT, 18, "bold")).pack(pady=(70, 4))
        tk.Label(self.summary, text=f"Projekt: {self.project_lbl.cget('text')}",
                 bg=C["card"], fg=C["muted"], font=(FONT, 11)).pack()

        tiles = tk.Frame(self.summary, bg=C["card"])
        tiles.pack(pady=26)
        for label, value, color in (("Ukupno", n, C["text"]),
                                    ("Zadržano", cnt["TRUE"], C["red"]),
                                    ("Sakriveno", cnt["FALSE"], C["green"]),
                                    ("Preskočeno", cnt["SKIP"], C["grey"])):
            t = tk.Frame(tiles, bg=C["soft_grey"], width=130, height=90)
            t.pack(side="left", padx=8)
            t.pack_propagate(False)
            tk.Label(t, text=str(value), bg=C["soft_grey"], fg=color,
                     font=(FONT, 24, "bold")).pack(pady=(12, 0))
            tk.Label(t, text=label, bg=C["soft_grey"], fg=C["muted"],
                     font=(FONT, 10)).pack()
        if n:
            tk.Label(self.summary, bg=C["card"], fg=C["text"], font=(FONT, 11),
                     text=f"Udio lažno pozitivnih nalaza: {cnt['FALSE'] / n * 100:.1f}%"
                     ).pack(pady=(0, 18))

        row = tk.Frame(self.summary, bg=C["card"])
        row.pack()
        FlatButton(row, "Spremi PDF izvještaj", C["blue"], "#2471a3",
                   self._export_pdf).pack(side="left", padx=6)
        FlatButton(row, "Novo skeniranje", C["green"], C["green_h"],
                   self.on_scan).pack(side="left", padx=6)
        self._switch(self.summary)
        self.status.config(text="Gotovo")

    def _export_pdf(self):
        try:
            from apiposture.ai.pdf_report import generate_pdf_report
        except Exception as e:
            messagebox.showerror("PDF", f"Modul pdf_report nije dostupan: {e}")
            return
        kept, supp = [], []
        for i, it in enumerate(self.items):
            d = self.decisions.get(i, "SKIP")
            row = dict(it)
            if d == "FALSE":
                row.update(ai_source="developer", confidence=100)
                supp.append(row)
            else:
                kept.append(row)
        ai_result = {"kept": kept, "suppressed": supp,
                     "stats": {"total": len(self.items), "kept": len(kept),
                               "suppressed": len(supp), "by_rule": 0,
                               "by_llm": 0, "by_developer": len(supp)}}
        out = generate_pdf_report(ai_result, scan_path=self.project or "demo")
        if out:
            messagebox.showinfo("PDF", f"Izvještaj spremljen:\n{out}")


def main():
    root = tk.Tk()
    FilterGUI(root, demo="--demo" in sys.argv)
    root.mainloop()


if __name__ == "__main__":
    main()