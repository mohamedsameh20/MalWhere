import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.hash_lookup import hash_lookup
from tools.threat_intel import threat_intel_lookup

# Standard EICAR string SHA256 (for checking known malware)
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
RANDOM_SHA256 = "c84f188a37397bf5b607eb02a4bfde0500000000000000000000000000000000"

def test_hash_lookup():
    print("[TEST] Running hash_lookup on unknown/random hash...")
    res = hash_lookup(RANDOM_SHA256)
    assert "is_known_malware" in res, "Missing is_known_malware key"
    assert res["is_known_malware"] is False, "Random hash shouldn't be known"
    print("  ✓ hash_lookup (unknown hash) succeeded")

def test_threat_intel_lookup():
    print("[TEST] Running threat_intel_lookup on random hash...")
    res = threat_intel_lookup(RANDOM_SHA256)
    # Even if API keys are missing, OTX should still return pulse list (usually empty)
    assert "alienvault_otx" in res, "Missing alienvault_otx key"
    print("  ✓ threat_intel_lookup succeeded")

if __name__ == "__main__":
    print("=== STARTING THREAT INTEL TESTS ===")
    test_hash_lookup()
    test_threat_intel_lookup()
    print("=== ALL THREAT INTEL TESTS PASSED ===\n")
