"""
Pomocna skripta za pokretanje evaluacije, usporedbe modela i PDF izvjestaja.

Pokretanje iz korijena projekta:
    python pokreni.py evaluacija putanja/do/projekta
    python pokreni.py pdf putanja/do/projekta
    python pokreni.py usporedba putanja/do/projekta

Primjeri:
    python pokreni.py pdf REST-auth
    python pokreni.py evaluacija REST-auth

Napomena: za evaluaciju i usporedbu treba postojati test_set.json
u mapi src/apiposture/ai/.
"""

import sys
from pathlib import Path


def dobij_sirove_nalaze(projekt_path):
    """Pokrece skener i vraca SIROVE nalaze (prije AI filtera)."""
    from apiposture.core.analysis.project_analyzer import ProjectAnalyzer
    from apiposture.core.models.scan_result import ScanResult

    analyzer = ProjectAnalyzer()
    path = Path(projekt_path)

    # Rucno ponovimo korake skeniranja da dobijemo sirove nalaze
    result = ScanResult(scan_path=path)
    files = analyzer._get_files(path)
    result.files_scanned = files
    for fp in files:
        analyzer._scan_file(fp, result)

    from apiposture.core.analysis.project_analyzer import deduplicate_endpoints
    result.endpoints = deduplicate_endpoints(result.endpoints)
    analyzer.classifier.classify_all(result.endpoints)
    findings = analyzer.rule_engine.evaluate_all(result.endpoints)
    findings = [f for f in findings if analyzer.config.is_rule_enabled(f.rule_id)]
    return findings


def pokreni_pdf(projekt_path):
    """Skenira i napravi PDF izvjestaj."""
    from apiposture.ai.filter import process_findings
    from apiposture.ai.config import AIFilterConfig
    from apiposture.ai.pdf_report import generate_pdf_report

    print(f"Skeniram {projekt_path}...")
    findings = dobij_sirove_nalaze(projekt_path)

    config = AIFilterConfig.automatic()
    ai_result = process_findings(findings, config=config)

    putanja = generate_pdf_report(ai_result, scan_path=projekt_path)
    print(f"\nGotovo. PDF: {putanja}")


def pokreni_evaluaciju(projekt_path):
    """Skenira i pokrene evaluaciju protiv test_set.json."""
    from apiposture.ai.filter import process_findings
    from apiposture.ai.config import AIFilterConfig
    from apiposture.ai.run_evaluation import run

    test_set = "src/apiposture/ai/test_set.json"
    if not Path(test_set).exists():
        print(f"GRESKA: ne postoji {test_set}")
        print("Napravi test_set.json s tocnim odgovorima prije evaluacije.")
        return

    print(f"Skeniram {projekt_path}...")
    findings = dobij_sirove_nalaze(projekt_path)

    run(findings, test_set)


def pokreni_usporedbu(projekt_path):
    """Skenira i usporedi vise modela."""
    from apiposture.ai.compare_models import compare

    test_set = "src/apiposture/ai/test_set.json"
    if not Path(test_set).exists():
        print(f"GRESKA: ne postoji {test_set}")
        return

    print(f"Skeniram {projekt_path}...")
    findings = dobij_sirove_nalaze(projekt_path)

    modeli = ["qwen2.5-coder:7b", "codellama"]  # dodaj modele koje imas
    compare(findings, test_set, models=modeli)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    akcija = sys.argv[1]
    projekt = sys.argv[2]

    if akcija == "pdf":
        pokreni_pdf(projekt)
    elif akcija == "evaluacija":
        pokreni_evaluaciju(projekt)
    elif akcija == "usporedba":
        pokreni_usporedbu(projekt)
    else:
        print(f"Nepoznata akcija: {akcija}")
        print("Dostupno: pdf, evaluacija, usporedba")