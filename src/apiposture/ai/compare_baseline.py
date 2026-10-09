"""
Usporedba: ApiPosture SAM vs ApiPosture + AI FILTER.

Ovo je glavna usporedba za diplomski - pokazuje vrijednost AI filtera.
Mjeri koliko filter smanjuje lažno pozitivne nalaze, uz provjeru da ne
skriva prave ranjivosti.

Koristi test_set.json s točnim odgovorima kako bi se znalo što je stvarno
lažan alarm, a što prava ranjivost.

Pokretanje (iz koda):
    from apiposture.ai.compare_baseline import compare_with_without_filter
    compare_with_without_filter(findings, "test_set.json")
"""

from apiposture.ai.config import AIFilterConfig
from apiposture.ai.filter import process_findings
from apiposture.ai.evaluation import load_test_set


def _truth_map(test_set: list) -> dict:
    """Rjecnik (route, method, alarm) -> 'REAL' ili 'FALSE'."""
    m = {}
    for e in test_set:
        m[(e["route"], e["method"], e["alarm"])] = e["truth"]
    return m


def compare_with_without_filter(apiposture_findings: list,
                                test_set_path: str,
                                config: AIFilterConfig | None = None) -> dict:
    """
    Usporedjuje stanje bez i s AI filterom.

    Args:
        apiposture_findings: nalazi iz skenera
        test_set_path: putanja do test_set.json s tocnim odgovorima
        config: konfiguracija filtera (automatic ako je None)

    Returns:
        rjecnik s rezultatima usporedbe
    """
    if config is None:
        config = AIFilterConfig.automatic()

    test_set = load_test_set(test_set_path)
    truth = _truth_map(test_set)

    # ----- SCENARIO A: skener sam (bez filtera) -----
    # Svi nalazi prolaze do korisnika.
    total = len(apiposture_findings)

    # Prebroji stvarno lazne i stvarno prave medju nalazima
    real_vulns = 0
    false_alarms = 0
    for f in apiposture_findings:
        methods = getattr(f.endpoint, "methods", [])
        method = methods[0] if methods else "GET"
        method = method.value if hasattr(method, "value") else str(method)
        key = (f.endpoint.full_route, method.upper(), f.rule_id)
        t = truth.get(key)
        if t == "REAL":
            real_vulns += 1
        elif t == "FALSE":
            false_alarms += 1

    # Bez filtera: korisnik vidi SVE lazne alarme
    false_seen_without = false_alarms

    # ----- SCENARIO B: skener + filter -----
    ai_result = process_findings(apiposture_findings, config=config)

    # Koji su nalazi prosli (kept)?
    kept_keys = set()
    for f in ai_result["kept"]:
        kept_keys.add((f["route"], f["method"], f["alarm"]))

    # S filterom: koliko LAZNIH alarma je OSTALO (nije sakriveno)?
    false_seen_with = 0
    hidden_real = 0
    for f in apiposture_findings:
        methods = getattr(f.endpoint, "methods", [])
        method = methods[0] if methods else "GET"
        method = method.value if hasattr(method, "value") else str(method)
        key = (f.endpoint.full_route, method.upper(), f.rule_id)
        t = truth.get(key)
        is_kept = key in kept_keys

        if t == "FALSE" and is_kept:
            false_seen_with += 1   # lazni alarm je prosao (nije sakriven)
        elif t == "REAL" and not is_kept:
            hidden_real += 1       # prava ranjivost sakrivena - opasno!

    # Smanjenje laznih alarma
    reduction = ((false_seen_without - false_seen_with) / false_seen_without * 100
                 if false_seen_without else 0.0)

    result = {
        "total_findings": total,
        "real_vulns": real_vulns,
        "false_alarms": false_alarms,
        "false_seen_without_filter": false_seen_without,
        "false_seen_with_filter": false_seen_with,
        "reduction_percent": reduction,
        "hidden_real_vulns": hidden_real,
    }

    _print_comparison(result)
    return result


def _print_comparison(r: dict) -> None:
    """Ispisuje usporednu tablicu."""
    print("\n" + "=" * 64)
    print("USPOREDBA: SKENER SAM vs SKENER + AI FILTER")
    print("=" * 64)

    print(f"\nUkupno nalaza:                    {r['total_findings']}")
    print(f"  Od toga prave ranjivosti:       {r['real_vulns']}")
    print(f"  Od toga lazni alarmi:           {r['false_alarms']}")

    print(f"\n{'':32} {'SKENER SAM':>12} {'+ FILTER':>12}")
    print("-" * 64)
    print(f"{'Lazni alarmi koje korisnik vidi':<32} "
          f"{r['false_seen_without_filter']:>12} "
          f"{r['false_seen_with_filter']:>12}")

    print("-" * 64)
    print(f"\nSmanjenje laznih alarma:          {r['reduction_percent']:.1f}%")

    if r["hidden_real_vulns"] == 0:
        print(f"Sakrivene prave ranjivosti:       0  (nijedna - ispravno)")
    else:
        print(f"Sakrivene prave ranjivosti:       {r['hidden_real_vulns']}  <-- PROBLEM")

    # Zakljucak za rad
    print("\n" + "=" * 64)
    if r["hidden_real_vulns"] == 0 and r["reduction_percent"] > 0:
        print(f"ZAKLJUCAK: Filter je smanjio lazne alarme za "
              f"{r['reduction_percent']:.1f}% bez skrivanja pravih ranjivosti.")
    elif r["hidden_real_vulns"] > 0:
        print(f"ZAKLJUCAK: Filter smanjuje lazne alarme, ali je sakrio "
              f"{r['hidden_real_vulns']} pravih ranjivosti - treba popraviti.")
    else:
        print("ZAKLJUCAK: Filter nije smanjio lazne alarme na ovom skupu.")


if __name__ == "__main__":
    print("""

    from apiposture.ai.compare_baseline import compare_with_without_filter

    findings = scanner.scan(putanja)   # nalazi iz skenera
    compare_with_without_filter(findings, "test_set.json")

""")