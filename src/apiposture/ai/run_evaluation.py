"""
Pokretanje stvarne evaluacije: skenira projekte, pokrene filter,
usporedi s testnim skupom tocnih odgovora.

Ovo je skripta koju pokreces da dobijes brojke za diplomski rad.
Povezuje filter (process_findings) s evaluacijskim modulom.
"""

from apiposture.ai.evaluation import evaluate, print_report
from apiposture.ai.config import AIFilterConfig
from apiposture.ai.filter import process_findings


def decisions_from_filter_result(ai_result: dict) -> dict:
    """Pretvara izlaz filtera u rjecnik odluka za evaluaciju."""
    decisions = {}
    for f in ai_result["suppressed"]:
        key = (f["route"], f["method"], f["alarm"])
        decisions[key] = "SUPPRESSED"
    for f in ai_result["kept"]:
        key = (f["route"], f["method"], f["alarm"])
        decisions[key] = "KEPT"
    return decisions


def run(apiposture_findings: list, test_set_path: str,
        config: AIFilterConfig | None = None) -> dict:
    """
    Cjelokupna evaluacija.

    Args:
        apiposture_findings: nalazi iz skenera (isti projekti kao test skup)
        test_set_path: putanja do test_set.json s tocnim odgovorima
        config: konfiguracija filtera (automatic ako je None)

    Returns:
        izlaz evaluacije (metrics + baseline)
    """
    # Automatic mod za evaluaciju, bez covjeka u petlji
    # (zelimo mjeriti filter sam, ne developera)
    if config is None:
        config = AIFilterConfig.automatic()

    ai_result = process_findings(apiposture_findings, config=config)
    decisions = decisions_from_filter_result(ai_result)
    out = evaluate(test_set_path, decisions)
    print_report(out["metrics"], out["baseline"])
    return out


if __name__ == "__main__":
    print("""
Ova skripta se pokrece iz koda, ne samostalno.

Primjer upotrebe:

    from apiposture.ai.run_evaluation import run

    # 1. Dobij nalaze iz skenera (isti projekti kao u test skupu)
    findings = scanner.scan(putanja)

    # 2. Pokreni evaluaciju
    rezultat = run(findings, "test_set.json")

    # 3. Rezultat sadrzi metrics i baseline za rad

""")