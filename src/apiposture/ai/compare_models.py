"""
Usporedba više LLM modela na istom test skupu.

Pokreće filter s više modela zaredom i mjeri za svaki:
  - točnost (accuracy)
  - preciznost (precision)
  - koliko pravih ranjivosti je pogrešno sakrio (najvažnije)
  - prosječno vrijeme po nalazu (brzina)

Rezultat je tablica pogodna za diplomski rad.

Pokretanje (iz koda):
    from apiposture.ai.compare_models import compare
    compare(findings, "test_set.json",
            models=["codellama", "qwen2.5-coder:7b", "deepseek-coder-v2:16b"])

Napomena: svaki model mora biti prethodno skinut:
    ollama pull codellama
    ollama pull qwen2.5-coder:7b
    ollama pull deepseek-coder-v2:16b
"""

import time
from apiposture.ai.config import AIFilterConfig
from apiposture.ai.filter import process_findings
from apiposture.ai.evaluation import evaluate


def _decisions_from_result(ai_result: dict) -> dict:
    """Pretvara izlaz filtera u rjecnik odluka za evaluaciju."""
    decisions = {}
    for f in ai_result["suppressed"]:
        decisions[(f["route"], f["method"], f["alarm"])] = "SUPPRESSED"
    for f in ai_result["kept"]:
        decisions[(f["route"], f["method"], f["alarm"])] = "KEPT"
    return decisions


def compare(apiposture_findings: list, test_set_path: str,
            models: list) -> list:
    """
    Usporedjuje vise modela na istom test skupu.

    Args:
        apiposture_findings: nalazi iz skenera
        test_set_path: putanja do test_set.json s tocnim odgovorima
        models: lista imena modela za usporedbu

    Returns:
        lista rezultata po modelu
    """
    results = []

    for model in models:
        print(f"\n{'=' * 60}")
        print(f"TESTIRANJE MODELA: {model}")
        print(f"{'=' * 60}")

        # Konfiguracija s ovim modelom, automatski mod (bez covjeka)
        # i bez pravila, da mjerimo CIST ucinak LLM-a
        config = AIFilterConfig(
            use_llm=True,
            llm_model=model,
            mode="automatic",
            use_rules=False,            # iskljuceno da mjerimo samo LLM
            auto_suppress_threshold=70,
            protect_critical=False,     # iskljuceno da vidimo sirovu procjenu
        )

        # Mjeri vrijeme
        start = time.time()
        try:
            ai_result = process_findings(apiposture_findings, config=config)
        except Exception as e:
            print(f"  Greska s modelom {model}: {e}")
            results.append({
                "model": model, "error": str(e),
                "accuracy": 0, "precision": 0,
                "hidden_real_vulns": None, "avg_time": 0,
            })
            continue
        elapsed = time.time() - start

        # Evaluacija
        decisions = _decisions_from_result(ai_result)
        out = evaluate(test_set_path, decisions)
        m = out["metrics"]

        n = len(apiposture_findings) or 1
        results.append({
            "model": model,
            "accuracy": m["accuracy"],
            "precision": m["precision"],
            "recall": m["recall"],
            "f1": m["f1"],
            "hidden_real_vulns": m["hidden_real_vulns"],
            "avg_time": elapsed / n,
            "total_time": elapsed,
        })

    _print_comparison(results)
    return results


def _print_comparison(results: list) -> None:
    """Ispisuje usporednu tablicu."""
    print("\n" + "=" * 78)
    print("USPOREDBA MODELA")
    print("=" * 78)

    # Zaglavlje
    print(f"{'Model':<24} {'Tocnost':>9} {'Precizn.':>9} "
          f"{'F1':>7} {'Sakriv.PR':>10} {'Vrij/nalaz':>11}")
    print("-" * 78)

    for r in results:
        if r.get("error"):
            print(f"{r['model']:<24} {'GRESKA: ' + r['error'][:40]}")
            continue
        hidden = r["hidden_real_vulns"]
        hidden_str = str(hidden) if hidden is not None else "-"
        print(f"{r['model']:<24} "
              f"{r['accuracy']*100:>8.1f}% "
              f"{r['precision']*100:>8.1f}% "
              f"{r['f1']*100:>6.1f}% "
              f"{hidden_str:>10} "
              f"{r['avg_time']:>9.2f}s")

    print("-" * 78)
    print("Sakriv.PR = sakrivene prave ranjivosti (manje = bolje, 0 = idealno)")
    print("Vrij/nalaz = prosjecno vrijeme analize po nalazu")

    # Preporuka
    valid = [r for r in results if not r.get("error")]
    if valid:
        # Najbolji po tocnosti, uz uvjet da nije sakrio prave ranjivosti
        safe = [r for r in valid if r["hidden_real_vulns"] == 0]
        pool = safe if safe else valid
        best = max(pool, key=lambda r: r["accuracy"])
        print(f"\nNajbolji model: {best['model']} "
              f"(tocnost {best['accuracy']*100:.1f}%, "
              f"sakrivenih pravih ranjivosti: {best['hidden_real_vulns']})")


if __name__ == "__main__":
    print("""
Ova skripta se pokrece iz koda.

Primjer:
    from apiposture.ai.compare_models import compare

    findings = scanner.scan(putanja)   # nalazi iz skenera
    compare(findings, "test_set.json",
            models=["codellama",
                    "qwen2.5-coder:7b",
                    "deepseek-coder-v2:16b"])

Prije pokretanja skini modele:
    ollama pull codellama
    ollama pull qwen2.5-coder:7b
    ollama pull deepseek-coder-v2:16b
""")