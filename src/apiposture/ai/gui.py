"""
Grafičko sučelje (GUI) za AI filter lažno pozitivnih nalaza.

Pokretanje:
    python -m apiposture.ai.gui

Sučelje omogućuje:
  - odabir projekta za skeniranje
  - prikaz nalaza s bojama po ozbiljnosti
  - donošenje odluka (lažni / pravi / preskoči) klikom na dugme
  - prikaz statistike na kraju

Koristi Tkinter koji je ugrađen u Python - nema dodatne instalacije.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path

SEVERITY_COLORS = {
    "critical": "#c0392b",   
    "high": "#e67e22",       
    "medium": "#f1c40f",   
    "low": "#3498db",       
    "unknown": "#7f8c8d",    
}

class FilterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ApiPosture - AI Filter lažno pozitivnih nalaza")
        self.root.geometry("900x650")
        self.root.configure(bg="#f5f5f5")

        self.findings = []        
        self.current_index = 0   
        self.kept = []            
        self.suppressed = []      
        self.scan_path = None

        self._build_ui()

    def _build_ui(self):
    
        top = tk.Frame(self.root, bg="#2c3e50", pady=12)
        top.pack(fill="x")

        tk.Label(top, text="AI Filter", bg="#2c3e50", fg="white",
                 font=("Arial", 16, "bold")).pack(side="left", padx=15)

        tk.Button(top, text="Odaberi projekt i skeniraj", command=self.on_scan,
                  bg="#27ae60", fg="white", font=("Arial", 11, "bold"),
                  relief="flat", padx=15, pady=6, cursor="hand2").pack(side="left", padx=10)

        self.path_label = tk.Label(top, text="Nije odabran projekt",
                                   bg="#2c3e50", fg="#bdc3c7", font=("Arial", 10))
        self.path_label.pack(side="left", padx=10)

        self.middle = tk.Frame(self.root, bg="#f5f5f5")
        self.middle.pack(fill="both", expand=True, padx=15, pady=10)

        self.progress_label = tk.Label(self.middle, text="",
                                       bg="#f5f5f5", font=("Arial", 10))
        self.progress_label.pack(anchor="w")

        self.card = tk.Frame(self.middle, bg="white", relief="solid", bd=1)
        self.card.pack(fill="both", expand=True, pady=8)

        self.alarm_label = tk.Label(self.card, text="", bg="white",
                                    font=("Arial", 14, "bold"))
        self.alarm_label.pack(anchor="w", padx=15, pady=(15, 5))

        self.endpoint_label = tk.Label(self.card, text="", bg="white",
                                       font=("Arial", 12))
        self.endpoint_label.pack(anchor="w", padx=15)

        self.severity_label = tk.Label(self.card, text="", bg="white",
                                       font=("Arial", 11, "bold"))
        self.severity_label.pack(anchor="w", padx=15, pady=5)

        # Kod
        tk.Label(self.card, text="Izvorni kod:", bg="white",
                 font=("Arial", 10, "bold")).pack(anchor="w", padx=15, pady=(10, 2))
        self.code_box = scrolledtext.ScrolledText(self.card, height=10,
                                                  font=("Consolas", 9), bg="#f8f8f8",
                                                  relief="solid", bd=1)
        self.code_box.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        # LLM sugestija
        self.llm_label = tk.Label(self.card, text="", bg="white",
                                  font=("Arial", 10, "italic"), fg="#555",
                                  wraplength=820, justify="left")
        self.llm_label.pack(anchor="w", padx=15, pady=(0, 10))

        # --- Donja traka: dugmad za odluke ---
        self.buttons = tk.Frame(self.root, bg="#f5f5f5", pady=12)
        self.buttons.pack(fill="x")

        self.btn_false = tk.Button(self.buttons, text="Lažni alarm (sakrij)",
                                   command=lambda: self.decide("FALSE"),
                                   bg="#27ae60", fg="white", font=("Arial", 11, "bold"),
                                   relief="flat", padx=20, pady=8, cursor="hand2",
                                   state="disabled")
        self.btn_false.pack(side="left", padx=(15, 8))

        self.btn_true = tk.Button(self.buttons, text="Prava ranjivost (zadrži)",
                                  command=lambda: self.decide("TRUE"),
                                  bg="#c0392b", fg="white", font=("Arial", 11, "bold"),
                                  relief="flat", padx=20, pady=8, cursor="hand2",
                                  state="disabled")
        self.btn_true.pack(side="left", padx=8)

        self.btn_skip = tk.Button(self.buttons, text="Preskoči",
                                  command=lambda: self.decide("SKIP"),
                                  bg="#7f8c8d", fg="white", font=("Arial", 11, "bold"),
                                  relief="flat", padx=20, pady=8, cursor="hand2",
                                  state="disabled")
        self.btn_skip.pack(side="left", padx=8)


    def on_scan(self):
        """Odabir projekta i pokretanje skeniranja."""
        path = filedialog.askdirectory(title="Odaberi projekt za skeniranje")
        if not path:
            return

        self.scan_path = path
        self.path_label.config(text=Path(path).name)

        try:
            findings = self._run_real_scan(path)
        except Exception as e:
            messagebox.showinfo("Demo način",
                                f"Pokrecem demo podatke (stvarni skener nije dostupan: {e})")
            findings = self._demo_findings()

        self.findings = findings
        self.current_index = 0
        self.kept = []
        self.suppressed = []

        if not findings:
            messagebox.showinfo("Rezultat", "Nema nalaza za pregled.")
            return

        self._show_current()

    def _run_real_scan(self, path):
        """Pokrece stvarni skener i filter. Vraca listu nalaza za pregled."""
        from apiposture.core.analysis.project_analyzer import ProjectAnalyzer
        from apiposture.ai.filter import extract_features, parse_location, read_endpoint_code

        analyzer = ProjectAnalyzer()
        result = analyzer.analyze(Path(path))

        findings = []
        for f in result.findings:
            methods = getattr(f.endpoint, "methods", [])
            method = methods[0] if methods else "GET"
            method = method.value if hasattr(method, "value") else str(method)
            loc = getattr(f, "location", "") or ""
            fp, ln = parse_location(loc)
            code = read_endpoint_code(fp, ln) if fp else ""
            findings.append({
                "route": f.endpoint.full_route,
                "method": method.upper(),
                "alarm": f.rule_id,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "code": code,
                "llm": "",
            })
        return findings

    def _demo_findings(self):
        """Demo podaci za prikaz kad stvarni skener nije dostupan."""
        return [
            {"route": "/", "method": "GET", "alarm": "AP001", "severity": "high",
             "code": "@app.route('/')\ndef index():\n    return render_template('index.html')",
             "llm": "Pocetna stranica - vjerojatno javna po dizajnu."},
            {"route": "/deserialize", "method": "POST", "alarm": "AP004", "severity": "critical",
             "code": "@app.route('/deserialize', methods=['POST'])\ndef deserialize():\n    data = request.form.get('data')\n    user = pickle.loads(base64.b64decode(data))",
             "llm": "pickle.loads na korisnickom unosu - moguce izvrsavanje proizvoljnog koda (RCE)."},
            {"route": "/admin/config", "method": "GET", "alarm": "AP007", "severity": "medium",
             "code": "@app.route('/admin/config')\ndef admin_config():\n    return jsonify(config)",
             "llm": "Admin ruta javno dostupna - osjetljiva funkcionalnost bez zastite."},
        ]

    def _show_current(self):
        """Prikazuje trenutni nalaz."""
        if self.current_index >= len(self.findings):
            self._show_summary()
            return

        f = self.findings[self.current_index]
        total = len(self.findings)

        self.progress_label.config(
            text=f"Nalaz {self.current_index + 1} od {total}   |   "
                 f"Zadržano: {len(self.kept)}   Sakriveno: {len(self.suppressed)}")

        self.alarm_label.config(text=f"{f['alarm']}")
        self.endpoint_label.config(text=f"{f['method']} {f['route']}")

        sev = str(f.get("severity", "unknown")).lower()
        color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["unknown"])
        self.severity_label.config(text=f"Ozbiljnost: {sev.upper()}", fg=color)

        self.code_box.delete("1.0", "end")
        self.code_box.insert("1.0", f.get("code", "(kod nije dostupan)"))

        llm = f.get("llm", "")
        self.llm_label.config(text=f"AI sugestija: {llm}" if llm else "")

        for b in (self.btn_false, self.btn_true, self.btn_skip):
            b.config(state="normal")

    def decide(self, choice):
        """Obrada odluke za trenutni nalaz."""
        f = self.findings[self.current_index]
        if choice == "FALSE":
            self.suppressed.append(f)
        elif choice == "TRUE":
            self.kept.append(f)

        self.current_index += 1
        self._show_current()

    def _show_summary(self):
        """Prikazuje zavrsni sazetak."""
        for b in (self.btn_false, self.btn_true, self.btn_skip):
            b.config(state="disabled")

        total = len(self.findings)
        kept = len(self.kept)
        supp = len(self.suppressed)

        self.alarm_label.config(text="Pregled završen")
        self.endpoint_label.config(text="")
        self.severity_label.config(text="")
        self.llm_label.config(text="")

        self.code_box.delete("1.0", "end")
        summary = (
            f"REZULTAT PREGLEDA\n"
            f"{'=' * 40}\n\n"
            f"Ukupno nalaza:        {total}\n"
            f"Zadržano (prave):     {kept}\n"
            f"Sakriveno (lažni):    {supp}\n"
            f"Preskočeno:           {total - kept - supp}\n\n"
        )
        if total:
            summary += f"Stopa lažno pozitivnih: {supp / total * 100:.1f}%\n"
        self.code_box.insert("1.0", summary)

        self.progress_label.config(text="Gotovo")


def main():
    root = tk.Tk()
    FilterGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()