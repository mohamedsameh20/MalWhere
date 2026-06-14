import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.pe_info import get_pe_info
from tools.imports import analyze_imports
from tools.entropy import scan_section_entropy
from tools.strings_extractor import extract_strings
from tools.visualize import visualize_pe
from tools.ml_score import ml_risk_score

TEST_FILE = "TestFiles/npp.8.9.6.2.Installer.x64.exe"

def test_pe_info():
    print("[TEST] Running get_pe_info...")
    res = get_pe_info(TEST_FILE)
    assert "sha256" in res, "Missing SHA256 in PE info"
    assert res["is_exe"] is True, "Benign installer should be classified as EXE"
    print("  ✓ get_pe_info succeeded:", res["sha256"][:12] + "...")

def test_imports():
    print("[TEST] Running analyze_imports...")
    res = analyze_imports(TEST_FILE)
    assert "total_imports" in res, "Missing total_imports"
    assert "flagged" in res, "Missing flagged imports"
    print(f"  ✓ analyze_imports succeeded: {res['total_imports']} imports, {len(res['flagged'])} flagged")

def test_entropy():
    print("[TEST] Running scan_section_entropy...")
    res = scan_section_entropy(TEST_FILE)
    assert "sections" in res, "Missing sections list"
    assert len(res["sections"]) > 0, "No sections parsed"
    print(f"  ✓ scan_section_entropy succeeded: {len(res['sections'])} sections")

def test_strings():
    print("[TEST] Running extract_strings...")
    res = extract_strings(TEST_FILE)
    assert "total_extracted" in res, "Missing total_extracted"
    assert "strings" in res, "Missing strings list"
    print(f"  ✓ extract_strings succeeded: {res['total_extracted']} strings found")

def test_visualize():
    print("[TEST] Running visualize_pe...")
    res = visualize_pe(TEST_FILE)
    assert "image_base64" in res, "Missing image_base64 string"
    assert len(res["image_base64"]) > 100, "Base64 string too short"
    print(f"  ✓ visualize_pe succeeded: Base64 len = {len(res['image_base64'])}")

def test_ml_score():
    print("[TEST] Running ml_risk_score...")
    res = ml_risk_score(TEST_FILE)
    assert "score" in res, "Missing score"
    assert 0.0 <= res["score"] <= 1.0, "Score not in probability bounds"
    print(f"  ✓ ml_risk_score succeeded: Score = {res['score']}, Verdict = {res['verdict']} ({res['model']})")

if __name__ == "__main__":
    if not os.path.exists(TEST_FILE):
        print(f"[ERROR] Test file {TEST_FILE} not found. Drop it first.")
        sys.exit(1)
        
    print("=== STARTING STATIC TOOLS TESTS ===")
    test_pe_info()
    test_imports()
    test_entropy()
    test_strings()
    test_visualize()
    test_ml_score()
    print("=== ALL STATIC TOOLS TESTS PASSED ===\n")
