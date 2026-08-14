from sigma.rule import SigmaRule
from sigma_rule_matcher import RuleMatcher

def test_rule(label, yaml, event):
    rule = SigmaRule.from_yaml(yaml)
    matcher = RuleMatcher(rule)
    result = matcher.match(event)
    print(f"{label}: {result}")
    return result

def run_spike():
    results = {}

    # Test 1: Flat field names (no dots) - equality
    results["flat_equality"] = test_rule("Flat Equality", '''
title: eq
logsource:
    category: process_creation
    product: linux
detection:
    sel:
        EventType: execve
    condition: sel
''', {"EventType": "execve", "CommandLine": "cat /etc/shadow"})

    # Test 2: Nested dict (dot-separated) - equality
    results["nested_equality"] = test_rule("Nested Equality", '''
title: eq_nested
logsource:
    category: process_creation
    product: linux
detection:
    sel:
        evt.type: execve
    condition: sel
''', {"evt": {"type": "execve"}})

    # Test 3: Flat field - contains modifier
    results["flat_contains"] = test_rule("Flat Contains", '''
title: cont
logsource:
    category: process_creation
    product: linux
detection:
    sel:
        CommandLine|contains: shadow
    condition: sel
''', {"CommandLine": "cat /etc/shadow"})

    # Test 4: Flat field - endswith modifier
    results["flat_endswith"] = test_rule("Flat Endswith", '''
title: ends
logsource:
    category: process_creation
    product: linux
detection:
    sel:
        ProcessName|endswith: sh
    condition: sel
''', {"ProcessName": "bash"})

    # Test 5: Boolean OR across selections
    results["boolean_or"] = test_rule("Boolean OR", '''
title: or_test
logsource:
    category: process_creation
    product: linux
detection:
    sel1:
        EventType: execve
    sel2:
        EventType: openat
    condition: sel1 or sel2
''', {"EventType": "openat"})

    # Test 6: Boolean AND across selections
    results["boolean_and"] = test_rule("Boolean AND", '''
title: and_test
logsource:
    category: process_creation
    product: linux
detection:
    sel1:
        EventType: execve
    sel2:
        CommandLine|contains: shadow
    condition: sel1 and sel2
''', {"EventType": "execve", "CommandLine": "cat /etc/shadow"})

    # Test 7: No match (negative test)
    results["no_match"] = test_rule("No Match", '''
title: No Match Test
logsource:
    category: process_creation
    product: linux
detection:
    sel:
        EventType: execve
    condition: sel
''', {"EventType": "openat"})

    print("\n=== SPIKE SUMMARY ===")
    all_pass = True
    expected = {
        "flat_equality": True,
        "nested_equality": True,
        "flat_contains": True,
        "flat_endswith": True,
        "boolean_or": True,
        "boolean_and": True,
        "no_match": False,
    }
    for key, exp in expected.items():
        status = "PASS" if results[key] == exp else "FAIL"
        if status == "FAIL":
            all_pass = False
        print(f"  {key}: got={results[key]}, expected={exp} -> {status}")

    if all_pass:
        print("\nSPIKE SUCCESS: All constructs verified.")
    else:
        print("\nSPIKE PARTIAL: Some constructs failed. See above.")

if __name__ == "__main__":
    run_spike()
