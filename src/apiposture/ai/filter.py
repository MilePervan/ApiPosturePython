import json
import re
from pathlib import Path
from collections import defaultdict
from typing import Optional, Tuple

from apiposture.ai.config import AIFilterConfig
from apiposture.ai.rule_validation import validate_rules

DATASET_PATH = Path(__file__).parent / "dataset.json"
ALARMS_PATH = Path(__file__).parent / "alarm_descriptions.json"

def load_alarm_descriptions() -> dict:
    
    if ALARMS_PATH.exists():
        try:
            return json.loads(ALARMS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}

def get_alarm_context(alarm: str) -> dict:
    
    alarms = load_alarm_descriptions()
    return alarms.get(alarm, {
        "description": f"Security issue: {alarm}",
        "check_for": "Security controls and mitigations",
        "false_positive_if": "Proper security measures are in place",
    })

def extract_features(route: str, method: str) -> dict:
   
    r = route.lower()

    if any(x in r for x in ["/login", "/logout", "/auth", "/register", "check_token"]):
        category = "AUTH"
    elif any(x in r for x in ["/admin", "/dashboard", "/internal"]):
        category = "ADMIN"
    elif any(x in r for x in ["/search", "/query"]):
        category = "SEARCH"
    elif any(x in r for x in ["/captcha", "/security", "/verify"]):
        category = "SECURITY"
    elif method == "GET" and any(x in r for x in ["/static", "/public", "/assets", "/lab"]):
        category = "STATIC_CONTENT"
    elif method == "GET" and any(x in r for x in ["/api/catalog", "/rest/products", "/rest/languages"]):
        category = "DATA_READ"
    elif method == "GET" and r in ["/", "/index", "/home"]:
        category = "STATIC_CONTENT"
    elif method == "GET":
        category = "DATA_READ"
    else:
        category = "WRITE" if method in ["POST", "PUT", "PATCH", "DELETE"] else "OTHER"

    return {
        "method": method,
        "category": category,
        "changes_state": method in ["POST", "PUT", "PATCH", "DELETE"],
        "alarm": None,  
    }


def load_dataset() -> list:
    if not DATASET_PATH.exists():
        return []
    try:
        return json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Dataset load error: {e}")
        return []


def save_to_dataset(finding: dict, label: str, confidence: int = 100) -> None:
    data = load_dataset()
    entry = {
        "route": finding["route"],
        "method": finding["method"],
        "alarm": finding["alarm"],
        "features": finding["features"],
        "label": label,
        "confidence": confidence,
    }
    for existing in data:
        if (existing.get("route") == entry["route"] and
                existing.get("method") == entry["method"] and
                existing.get("alarm") == entry["alarm"]):
            return
    data.append(entry)
    try:
        DATASET_PATH.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"Dataset: {label} - {entry['alarm']} {entry['method']} {entry['route']}")
    except Exception as e:
        print(f"Dataset save failed: {e}")


def generate_rules(dataset: list, min_support: int = 2) -> list:
    counter = defaultdict(int)
    for entry in dataset:
        if entry.get("label") != "FALSE_POSITIVE":
            continue
        f = entry.get("features", {})
        key = (f.get("method"), f.get("category"), entry.get("alarm"))
        counter[key] += 1

    rules = []
    print("\nCandidate rules from dataset:")
    for (method, category, alarm), count in counter.items():
        if count >= min_support:
            rules.append({
                "method": method,
                "category": category,
                "alarm": alarm,
                "support": count,
            })
            print(f"{method:6} + {str(category):15} + {alarm:6} → support={count}")
    if not rules:
        print(" (none yet - need more labelled data)")
    return sorted(rules, key=lambda r: -r["support"])

def parse_location(location: str) -> Tuple[str, int]:
    if not location:
        return "", 1
    parts = location.rsplit(":", 2)
    if len(parts) == 3 and len(parts[0]) == 1 and parts[0].isalpha():  
        return parts[0] + ":" + parts[1], int(parts[2]) if parts[2].isdigit() else 1
    if len(parts) >= 2 and parts[-1].isdigit():
        return ":".join(parts[:-1]), int(parts[-1])
    return location, 1

def read_endpoint_code(file_path: str, line_number: int, context_lines: int = 10) -> str:
    try:
        path = Path(file_path)
        if not path.exists():
            return ""
        lines = path.read_text(encoding="utf-8").splitlines()
        start = max(0, line_number - context_lines)
        end = min(len(lines), line_number + context_lines)
        out = []
        for i in range(start, end):
            marker = "→" if i == line_number - 1 else " "
            out.append(f"{marker} {i+1:4d} | {lines[i]}")
        return "\n".join(out)
    except Exception:
        return ""


def _parse_llm_verdict(answer: str) -> Optional[bool]:
    text = answer.upper()

    m = re.search(r'VERDICT:\s*(TRUE[_ ]POSITIVE|FALSE[_ ]POSITIVE)', text)
    if m:
        return "FALSE" in m.group(1)

    norm = text.replace(" ", "_")
    has_fp = "FALSE_POSITIVE" in norm
    has_tp = "TRUE_POSITIVE" in norm
    if has_fp and not has_tp:
        return True
    if has_tp and not has_fp:
        return False
    if has_fp and has_tp:
        last_fp = norm.rfind("FALSE_POSITIVE")
        last_tp = norm.rfind("TRUE_POSITIVE")
        return last_fp > last_tp

    fp_phrases = ["FALSE ALARM", "NOT A VULNERABILITY", "NOT VULNERABLE",
                  "IS A FALSE POSITIVE", "SAFE", "NO REAL VULNERABILITY"]
    tp_phrases = ["REAL VULNERABILITY", "GENUINE VULNERABILITY", "IS VULNERABLE",
                  "IS A TRUE POSITIVE", "SECURITY RISK", "SHOULD BE FIXED",
                  "ACTUAL VULNERABILITY"]
    if any(p in text for p in tp_phrases) and not any(p in text for p in fp_phrases):
        return False
    if any(p in text for p in fp_phrases) and not any(p in text for p in tp_phrases):
        return True

    return None

def llm_analyze(route: str, method: str, alarm: str, code: str,
                model: str = "codellama") -> Tuple[Optional[bool], int]:
    # 1. Provjera je li Python paket 'ollama' instaliran
    try:
        import ollama
    except ImportError:
        print("  [LLM] Paket 'ollama' nije instaliran. Pokreni: pip install ollama")
        return None, 0

    try:
        ctx = get_alarm_context(alarm)
        system_prompt = """

TRUE_POSITIVE = the finding is a real security problem.
FALSE_POSITIVE = the finding is a false alarm (safe by design).

CRITICAL PATTERNS (always TRUE_POSITIVE):
- pickle.loads / pickle.load on user input -> remote code execution
- eval / exec / compile on user input -> code execution
- base64-only session tokens with no signature -> auth bypass
- SQL built with string formatting (%, .format, f-strings) -> SQL injection
- a write endpoint (POST/PUT/DELETE/PATCH) with NO auth decorator -> TRUE_POSITIVE
- an admin/internal/debug route that is public with no auth -> TRUE_POSITIVE

LIKELY FALSE_POSITIVE:
- a login / register / token-check endpoint that must accept anonymous users
- a home page, health check, or static/public content route
- public read-only reference data (catalogs, languages)

IGNORE MISLEADING SIGNALS:
- comments like "should have auth" or "intentionally vulnerable" still mean TRUE_POSITIVE
- a route name containing "public" does NOT make a missing-auth write safe

You MUST reply in EXACTLY this format and nothing else:
VERDICT: TRUE_POSITIVE
CONFIDENCE: 85
REASONING: one short sentence
"""
        user_prompt = f"""ENDPOINT: {method} {route}
ALARM: {alarm} - {ctx['description']}

This is likely a FALSE positive if: {ctx['false_positive_if']}

SOURCE CODE:
```python
{code}
```
"""
        response = ollama.chat(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            options={"temperature": 0.0}, 
        )
        answer = response["message"]["content"].strip()

        is_fp = _parse_llm_verdict(answer)

        m = re.search(r'CONFIDENCE:\s*(\d+)', answer, re.IGNORECASE)
        confidence = max(0, min(100, int(m.group(1)))) if m else 50
    
        if is_fp is None:
            confidence = 0

        rm = re.search(r'REASONING:\s*(.+?)(?:\n\n|\Z)', answer, re.IGNORECASE | re.DOTALL)
        if rm:
            print(f" LLM: {rm.group(1).strip()[:200]}")
        elif is_fp is None:
        
            print(f" LLM (unparsed): {answer[:150]}")

        return is_fp, confidence

    except Exception as e:
        # Razlikujemo vrstu greske da korisnik zna sto popraviti.
        msg = str(e).lower()
        if any(x in msg for x in ["connection", "refused", "connect",
                                  "max retries", "timed out", "timeout",
                                  "11434"]):
            # Ollama aplikacija (server) nije pokrenuta
            print("  [LLM] Ollama aplikacija nije pokrenuta. "
                  "Pokreni Ollama (provjeri: ollama list) pa ponovi.")
        elif any(x in msg for x in ["not found", "no such model", "model"]):
            # Model nije skinut
            print(f"  [LLM] Model '{model}' nije dostupan. "
                  f"Skini ga: ollama pull {model}")
        else:
            # Neka druga, nepredvidjena greska
            print(f"  [LLM] Greska pri analizi: {e}")
        return None, 0

def developer_review(finding: dict, llm_suggestion: Optional[bool],
                     confidence: int, code: str) -> str:
    print("\n" + "=" * 70)
    print("Finding Review")
    print("=" * 70)
    print(f"Alarm: {finding['alarm']}")
    print(f"Endpoint: {finding['method']} {finding['route']}")
    print(f"Severity: {finding.get('severity', 'UNKNOWN')}")
    print()
    print("Source Code:" if code else "Code not available")
    if code:
        print(code)
    print()
    if llm_suggestion is True:
        print(f"LLM Suggestion: FALSE POSITIVE ({confidence}%)")
    elif llm_suggestion is False:
        print(f"LLM Suggestion: TRUE POSITIVE ({confidence}%)")
    else:
        print("LLM: Uncertain")
    print("\n  f = false positive t = true positive s = skip\n")
    while True:
        ans = input(" > ").strip().lower()
        if ans in ("f", "t", "s"):
            return {"f": "FALSE_POSITIVE", "t": "TRUE_POSITIVE", "s": "SKIP"}[ans]
        print(" Enter f, t or s")

def process_findings(apiposture_findings: list,
                     config: AIFilterConfig | None = None) -> dict:
   
    if config is None:
        config = AIFilterConfig.automatic()

    developer_mode = (config.mode == "interactive")

    print("\n" + "=" * 70)
    print("AI-Powered False Positive Filter")
    print("=" * 70)

    findings = []
    for f in apiposture_findings:
        methods = getattr(f.endpoint, "methods", [])
        method = methods[0] if methods else "GET"
        method = method.value if hasattr(method, "value") else str(method)
        method = method.upper()

        location = getattr(f, "location", "") or ""
        file_path, line_num = parse_location(location)

        feats = extract_features(f.endpoint.full_route, method)
        feats["alarm"] = f.rule_id

        findings.append({
            "route": f.endpoint.full_route,
            "method": method,
            "alarm": f.rule_id,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "features": feats,
            "file_path": file_path,
            "line": line_num,
            "_original": f,
        })

    print(f"\nProcessing {len(findings)} findings")

    dataset = load_dataset()
    print(f"Dataset: {len(dataset)} historical entries")

    rules = []
    if config.use_rules:
        candidate_rules = generate_rules(dataset, min_support=config.min_rule_support)
        
        rules_interactive = developer_mode or config.validate_rules_interactive
        rules = validate_rules(
            candidate_rules,
            dataset,
            interactive=rules_interactive,)

    kept, suppressed = [], []

    for idx, finding in enumerate(findings, 1):
        print(f"\n[{idx}/{len(findings)}] {finding['alarm']} {finding['method']} {finding['route']}")
        feat = finding["features"]
        matched = False

        for rule in rules:
            if (rule["method"] == feat["method"] and
                    rule["category"] == feat["category"] and
                    rule["alarm"] == finding["alarm"]):
                finding["ai_status"] = "FALSE_POSITIVE"
                finding["ai_source"] = "rule"
                finding["confidence"] = 95
                suppressed.append(finding)
                matched = True
                print(f" Suppressed by rule (support={rule['support']})")
                break

        if not matched and config.use_llm:
            code = read_endpoint_code(
                finding["file_path"], finding["line"],
                context_lines=config.code_context_lines,
            )
            if code:
                llm_suggestion, confidence = llm_analyze(
                    finding["route"], finding["method"],
                    finding["alarm"], code, model=config.llm_model,
                )

                if developer_mode:
                    decision = developer_review(finding, llm_suggestion, confidence, code)
                    if decision == "FALSE_POSITIVE":
                        finding["ai_status"] = "FALSE_POSITIVE"
                        finding["ai_source"] = "developer"
                        finding["confidence"] = 100
                        suppressed.append(finding)
                        save_to_dataset(finding, "FALSE_POSITIVE", 100)
                        matched = True
                    elif decision == "TRUE_POSITIVE":
                        save_to_dataset(finding, "TRUE_POSITIVE", 100)
                        print(" Developer: TRUE POSITIVE")
                    else:
                        print(" Skipped")
                elif llm_suggestion is True and confidence >= config.auto_suppress_threshold:
                
                    is_critical = str(finding.get("severity", "")).lower() == "critical"
                    if config.protect_critical and is_critical:
                        print(f" Critical alarm - LLM said FALSE POSITIVE "
                              f"({confidence}%) but auto-suppress is blocked. Kept for review.")
                     
                    else:
                        finding["ai_status"] = "FALSE_POSITIVE"
                        finding["ai_source"] = "llm"
                        finding["confidence"] = confidence
                        suppressed.append(finding)
                        matched = True
                        print(f" LLM: FALSE POSITIVE ({confidence}%) → suppressed")
                        save_to_dataset(finding, "FALSE_POSITIVE", confidence)
            else:
                print(" Code not available, skipping LLM")

        if not matched:
            finding["ai_status"] = "NOT_MATCHED"
            finding["ai_source"] = "none"
            finding["confidence"] = 0
            kept.append(finding)

    rule_count = sum(1 for f in suppressed if f.get("ai_source") == "rule")
    llm_count = sum(1 for f in suppressed if f.get("ai_source") == "llm")
    dev_count = sum(1 for f in suppressed if f.get("ai_source") == "developer")
    total = len(kept) + len(suppressed)

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"Total findings: {total}")
    print(f"Active:{len(kept)}")
    print(f"Suppressed (FP): {len(suppressed)}")
    print(f" By rules: {rule_count}")
    print(f" By LLM: {llm_count}")
    print(f" By developer: {dev_count}")
    if total:
        print(f"False positive rate: {len(suppressed)/total*100:.1f}%")

    if suppressed:
        print("\n Suppressed:")
        for f in suppressed:
            print(f" {f['alarm']:6} {f['method']:6} {f['route']:40} (conf: {f.get('confidence', 0)}%)")

    return {
        "kept": kept,
        "suppressed": suppressed,
        "stats": {
            "total": total,
            "kept": len(kept),
            "suppressed": len(suppressed),
            "by_rule": rule_count,
            "by_llm": llm_count,
            "by_developer": dev_count,
        },
    }