import yara
import os

def scan_yara(filepath: str) -> dict:
    """Scan PE file against YARA rulesets in rules/ folder. Return matched rules."""
    try:
        # RULES_DIR is relative to the project root: tools/../rules -> rules/
        rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")
        
        # 1. Collect all .yar or .yara files recursively
        rule_files = []
        if os.path.exists(rules_dir):
            for root, _, files in os.walk(rules_dir):
                for f in files:
                    if f.endswith((".yar", ".yara")):
                        rule_files.append(os.path.join(root, f))

        # 2. If no rule files found:
        if not rule_files:
            return {
                "matches": [],
                "total": 0,
                "failed_rules": 0,
                "note": "No YARA rules found in rules/ directory. Download signature-base."
            }

        # 3. Compile rules individually (skip syntax errors, count failed rules)
        compiled_rules = []
        failed_rules = 0
        for rf in rule_files:
            try:
                rule = yara.compile(filepath=rf, error_on_warning=False)
                compiled_rules.append(rule)
            except (yara.SyntaxError, yara.Error):
                failed_rules += 1
                continue
            except Exception:
                failed_rules += 1
                continue

        # 4. Scan the target file with each compiled rule set
        all_matches = []
        for rule in compiled_rules:
            try:
                matches = rule.match(filepath)
                for m in matches:
                    entry = {
                        "rule": m.rule,
                        "tags": list(m.tags),
                        "description": m.meta.get("description", "") if m.meta else ""
                    }
                    all_matches.append(entry)
            except Exception:
                continue

        # 5. Cap at 50 matches
        capped_matches = all_matches[:50]

        return {
            "matches": capped_matches,
            "total": len(capped_matches),
            "failed_rules": failed_rules
        }

    except Exception as e:
        return {
            "error": f"YARA scan failed: {str(e)}",
            "failed_rules": 0
        }
