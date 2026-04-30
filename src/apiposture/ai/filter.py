import json
from pathlib import Path
from collections import defaultdict

DATASET_PATH = Path(__file__).parent / "dataset.json"

def extract_features(route: str, method: str) -> dict:
  
    r = route.lower()
    if any(x in r for x in ["/login", "/logout", "/signup", "/register"]):
        category = "AUTH"
    elif any(x in r for x in ["/admin", "/dashboard", "/internal"]):
        category = "ADMIN"
    elif any(x in r for x in ["/debug", "/health", "/status", "/metrics"]):
        category = "DEBUG"
    elif method == "GET" and any(x in r for x in ["/static/", "/public/", "/assets/"]):
        category = "STATIC"
    elif method == "GET":
        category = "DATA_READ"
    else:
        category = "WRITE"
    return {"method": method, "category": category}

def load_dataset() -> list:
   
    if not DATASET_PATH.exists():
        return []
    return json.loads(DATASET_PATH.read_text(encoding="utf-8"))

def generate_rules(dataset: list) -> list:
  
    counter = defaultdict(int)

    for entry in dataset:
        if entry.get("label") != "FALSE_POSITIVE":
            continue
        f   = entry.get("features", {})
        key = (f.get("method", "GET"), f.get("category", "UNKNOWN"), entry.get("alarm", ""))
        counter[key] += 1

    rules = []
    for (method, category, alarm), count in counter.items():
        if count >= 2:
            rules.append({
                "method":   method,
                "category": category,
                "alarm":    alarm,
                "support":  count,
            })
            print(f"{method}, {category}, {alarm} support={count}")
    return sorted(rules, key=lambda r: -r["support"])

def process_findings(apiposture_findings: list) -> dict:
 
    findings = []
    for f in apiposture_findings:
        methods = getattr(f.endpoint, "methods", [])
        method  = methods[0] if methods else "GET"
        method  = method.value if hasattr(method, "value") else str(method)
        method  = method.upper()

        findings.append({
            "route":     f.endpoint.full_route,
            "method":    method,
            "alarm":     f.rule_id,
            "severity":  f.severity.value,
            "features":  extract_features(f.endpoint.full_route, method),
            "_original": f,
        })
    dataset = load_dataset()
    rules   = generate_rules(dataset)

    if not rules:
        print("nema pravila")
        return {"kept": findings, "suppressed": []}

    kept, suppressed = [], []
    for finding in findings:
        feat    = finding["features"]
        matched = False
        for rule in rules:
            if (rule["method"]   == feat["method"] and
                rule["category"] == feat["category"] and
                rule["alarm"]    == finding["alarm"]):
                finding["ai_status"] = "FALSE_POSITIVE"
                suppressed.append(finding)
                matched = True
                break
        if not matched:
            finding["ai_status"] = "NOT_MATCHED"
            kept.append(finding)

    total = len(kept) + len(suppressed)
    print(f"\n{total} nalaza, {len(kept)} aktivnih, "
          f"{len(suppressed)} uklonjeno kao false positive.")
    for f in suppressed:
        print(f"{f['alarm']} {f['method']} {f['route']}")

    return {"kept": kept, "suppressed": suppressed}