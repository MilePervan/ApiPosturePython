"""
Evaluation module for the AI false-positive filter.

Compares the filter's decisions against a ground-truth set (manually
labelled correct answers) and computes standard classification metrics.

Terminology (from the filter's point of view, where the "positive" class
is "this is a FALSE POSITIVE that should be suppressed"):
  - TP (true positive):  filter suppressed, and it really was a false alarm
  - FP (false positive): filter suppressed, but it was a REAL vulnerability  <-- dangerous
  - TN (true negative):  filter kept, and it really was a real vulnerability
  - FN (false negative): filter kept, but it was a false alarm (harmless miss)

The most important number for a security tool is the count of real
vulnerabilities the filter wrongly suppressed (hidden real vulnerabilities).
"""

import json
from pathlib import Path


def load_ground_truth(path: str) -> list:
    """
    Load the ground-truth set.

    Expected format (list of entries):
    [
      {
        "route": "/admin/config",
        "method": "GET",
        "alarm": "AP001",
        "truth": "REAL"        # REAL = prava ranjivost, FALSE = lazni alarm
      },
      ...
    ]
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Ground truth not found: {path}")
    return json.loads(p.read_text(encoding="utf-8"))


def compute_metrics(results: list) -> dict:
    """
    Compute classification metrics.

    Args:
        results: list of dicts, each with:
            "truth"    - "REAL" or "FALSE" (ground truth)
            "decision" - "SUPPRESSED" or "KEPT" (what the filter did)

    Returns:
        dict with counts and metrics.
    """
    tp = fp = tn = fn = 0

    for r in results:
        truth = r["truth"]          # REAL / FALSE
        decision = r["decision"]    # SUPPRESSED / KEPT

        # "positive" = filter says FALSE POSITIVE (suppressed)
        if decision == "SUPPRESSED" and truth == "FALSE":
            tp += 1   # correctly suppressed a false alarm
        elif decision == "SUPPRESSED" and truth == "REAL":
            fp += 1   # WRONGLY suppressed a real vulnerability (dangerous!)
        elif decision == "KEPT" and truth == "REAL":
            tn += 1   # correctly kept a real vulnerability
        elif decision == "KEPT" and truth == "FALSE":
            fn += 1   # missed a false alarm (harmless - just noise remains)

    total = tp + fp + tn + fn

    # Precision: of all suppressed, how many were truly false alarms
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    # Recall: of all true false alarms, how many were caught
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    # F1: harmonic mean
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    # Accuracy: overall correct decisions
    accuracy = (tp + tn) / total if total else 0.0

    return {
        "total": total,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "hidden_real_vulns": fp,   # the critical number
    }


def compare_baseline(results: list) -> dict:
    """
    Compare the situation before and after the filter.

    Before: the scanner alone reports ALL alarms (nothing suppressed).
    After:  the filter suppresses some alarms.

    Returns counts of false alarms reaching the user in each case.
    """
    total = len(results)
    real = sum(1 for r in results if r["truth"] == "REAL")
    false_alarms = sum(1 for r in results if r["truth"] == "FALSE")

    false_before = false_alarms

    false_after = sum(1 for r in results
                      if r["truth"] == "FALSE" and r["decision"] == "KEPT")

    reduction = (false_before - false_after) / false_before * 100 if false_before else 0.0

    return {
        "total_alarms": total,
        "real_vulns": real,
        "false_alarms_before": false_before,
        "false_alarms_after": false_after,
        "reduction_percent": reduction,
    }


def print_report(metrics: dict, baseline: dict) -> None:
    """Print a readable evaluation report."""
    print("=" * 60)
    print("EVALUACIJA AI FILTERA")
    print("=" * 60)

    print("\nMatrica konfuzije:")
    print(f"  Ispravno sakriveni lažni alarmi (TP):      {metrics['tp']}")
    print(f"  POGREŠNO sakrivene prave ranjivosti (FP):  {metrics['fp']}  <-- opasno")
    print(f"  Ispravno zadržane prave ranjivosti (TN):   {metrics['tn']}")
    print(f"  Propušteni lažni alarmi (FN):              {metrics['fn']}")

    print("\nMetrike:")
    print(f"  Preciznost (precision):  {metrics['precision']*100:.1f}%")
    print(f"  Odziv (recall):          {metrics['recall']*100:.1f}%")
    print(f"  F1 rezultat:             {metrics['f1']*100:.1f}%")
    print(f"  Točnost (accuracy):      {metrics['accuracy']*100:.1f}%")

    print("\nNAJVAŽNIJE:")
    if metrics["hidden_real_vulns"] == 0:
        print(f"  Sakrivenih pravih ranjivosti: 0  (filter nije sakrio nijednu pravu ranjivost)")
    else:
        print(f"  Sakrivenih pravih ranjivosti: {metrics['hidden_real_vulns']}  <-- treba ispraviti!")

    print("\n" + "=" * 60)
    print("USPOREDBA: SKENER SAM vs SKENER + FILTER")
    print("=" * 60)
    print(f"  Ukupno alarma:                    {baseline['total_alarms']}")
    print(f"  Od toga prave ranjivosti:         {baseline['real_vulns']}")
    print(f"  Lažni alarmi PRIJE filtera:       {baseline['false_alarms_before']}")
    print(f"  Lažni alarmi POSLIJE filtera:     {baseline['false_alarms_after']}")
    print(f"  Smanjenje lažnih alarma:          {baseline['reduction_percent']:.1f}%")


def evaluate(ground_truth_path: str, decisions: dict) -> dict:
    """
    Run the full evaluation.

    Args:
        ground_truth_path: path to ground_truth.json
        decisions: dict mapping (route, method, alarm) -> "SUPPRESSED" or "KEPT",
                   i.e. what the filter decided for each finding.

    Returns:
        dict with "metrics" and "baseline".
    """
    gt = load_ground_truth(ground_truth_path)

    results = []
    for entry in gt:
        key = (entry["route"], entry["method"], entry["alarm"])
        decision = decisions.get(key, "KEPT")  # default: kept if filter said nothing
        results.append({
            "route": entry["route"],
            "method": entry["method"],
            "alarm": entry["alarm"],
            "truth": entry["truth"],
            "decision": decision,
        })

    metrics = compute_metrics(results)
    baseline = compare_baseline(results)
    return {"metrics": metrics, "baseline": baseline, "results": results}

if __name__ == "__main__":

    import sys
    gt_path = sys.argv[1] if len(sys.argv) > 1 else "ground_truth_example.json"

    gt = load_ground_truth(gt_path)
    demo_decisions = {}
    for e in gt:
        key = (e["route"], e["method"], e["alarm"])
        demo_decisions[key] = "SUPPRESSED" if e["truth"] == "FALSE" else "KEPT"

    out = evaluate(gt_path, demo_decisions)
    print_report(out["metrics"], out["baseline"])