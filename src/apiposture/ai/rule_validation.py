from enum import Enum
import json
from pathlib import Path

DECISIONS_PATH = Path(__file__).parent / "rule_decisions.json"

SAFE_CATEGORIES = {"STATIC_CONTENT", "DATA_READ", "SEARCH"}

DANGEROUS_CATEGORIES = {"WRITE", "DELETE", "ADMIN"}

STRONG_SUPPORT = 3   
WEAK_SUPPORT = 2     

def _rule_key(rule: dict) -> str:
    return f"{rule['method']}|{rule['category']}|{rule['alarm']}"


def load_rule_decisions() -> dict:
    if not DECISIONS_PATH.exists():
        return {}
    try:
        return json.loads(DECISIONS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_rule_decision(rule: dict, decision: str) -> None:
    decisions = load_rule_decisions()
    decisions[_rule_key(rule)] = decision
    try:
        DECISIONS_PATH.write_text(
            json.dumps(decisions, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    except Exception as e:
        print(f"Could not save rule decision: {e}")


class ValidationStatus(Enum):
    AUTO_APPROVED = "auto_approved"   
    AUTO_REJECTED = "auto_rejected"  
    NEEDS_REVIEW = "needs_review"     


def find_conflicts(rule: dict, dataset: list) -> int:
   
    conflicts = 0
    for entry in dataset:
        if entry.get("label") != "TRUE_POSITIVE":
            continue
        f = entry.get("features", {})
        if (f.get("method") == rule["method"] and
                f.get("category") == rule["category"] and
                entry.get("alarm") == rule["alarm"]):
            conflicts += 1
    return conflicts

def auto_validate_rule(rule: dict, dataset: list) -> tuple[ValidationStatus, str]:

    category = rule["category"]
    support = rule["support"]

    conflicts = find_conflicts(rule, dataset)
    if conflicts > 0:
        return (
            ValidationStatus.AUTO_REJECTED,
            f"Conflict: {conflicts} TRUE_POSITIVE entries match this pattern. "
            f"Applying it could hide real vulnerabilities."
        )

    if category in DANGEROUS_CATEGORIES:
        return (
            ValidationStatus.AUTO_REJECTED,
            f"Dangerous category '{category}'."
            f"should not be auto-suppressed."
        )

    if support >= STRONG_SUPPORT and category in SAFE_CATEGORIES:
        return (
            ValidationStatus.AUTO_APPROVED,
            f"Strong support ({support}) and safe category '{category}', no conflicts."
        )

    return (
        ValidationStatus.NEEDS_REVIEW,
        f"Borderline: support={support}, category='{category}'. Needs confirmation."
    )

def developer_validate_rule(rule: dict, reason: str) -> bool:
    
    print("\n" + "=" * 70)
    print("RULE NEEDS VALIDATION")
    print("=" * 70)
    print(f"Rule:    {rule['method']} + {rule['category']} + {rule['alarm']}")
    print(f"Support: {rule['support']} occurrences")
    print(f"Reason:  {reason}")
    print()
    print("Approve only if you're confident these are genuine false positives.")
    print("a = APPROVE (add rule to engine)")
    print("r = REJECT (do not use this rule)")
    print()
    while True:
        ans = input("  > ").strip().lower()
        if ans == "a":
            print("  Rule approved")
            return True
        if ans == "r":
            print("  Rule rejected")
            return False
        print("  Enter 'a' or 'r'")


def validate_rules(candidate_rules: list, dataset: list,
                   interactive: bool = True) -> list:
   
    print("\n" + "=" * 70)
    print("RULE VALIDATION PHASE")
    print("=" * 70)
    print(f"Validating {len(candidate_rules)} candidate rules...\n")

    remembered = load_rule_decisions()
    approved = []
    auto_approved = auto_rejected = dev_approved = dev_rejected = 0
    remembered_count = 0

    for rule in candidate_rules:
        status, reason = auto_validate_rule(rule, dataset)
        label = f"{rule['method']} + {rule['category']} + {rule['alarm']}"

        if status == ValidationStatus.AUTO_APPROVED:
            approved.append(rule)
            auto_approved += 1
            print(f"AUTO-APPROVED: {label}")
            print(f"{reason}")
        elif status == ValidationStatus.AUTO_REJECTED:
            auto_rejected += 1
            print(f"  AUTO-REJECTED: {label}")
            print(f"{reason}")
        else:  
            prior = remembered.get(_rule_key(rule))
            if prior == "approve":
                approved.append(rule)
                remembered_count += 1
                print(f"REMEMBERED-APPROVE: {label} (previously approved)")
            elif prior == "reject":
                remembered_count += 1
                print(f"REMEMBERED-REJECT: {label} (previously rejected)")
            elif interactive:
                print(f"NEEDS REVIEW: {label}")
                if developer_validate_rule(rule, reason):
                    approved.append(rule)
                    dev_approved += 1
                    save_rule_decision(rule, "approve")
                else:
                    dev_rejected += 1
                    save_rule_decision(rule, "reject")
            else:
                dev_rejected += 1
                print(f" NEEDS REVIEW: {label}")
                print(f" Rejected (non-interactive mode)")

    print("\n" + "=" * 70)
    print("VALIDATION RESULTS")
    print("=" * 70)
    print(f"Candidate rules: {len(candidate_rules)}")
    print(f"Approved: {len(approved)}")
    print(f"Auto-approved: {auto_approved}")
    print(f"Dev-approved: {dev_approved}")
    print(f"Rejected: {auto_rejected + dev_rejected}")
    print(f"Auto-rejected: {auto_rejected}")
    print(f"Dev-rejected: {dev_rejected}")
    if remembered_count:
        print(f"From remembered decisions: {remembered_count} "
              f"(not asked again - edit rule_decisions.json to change)")

    if approved:
        print("\nApproved rules added to engine:")
        for rule in approved:
            print(f"{rule['method']} + {rule['category']} + "
                  f"{rule['alarm']} (support={rule['support']})")

    return approved