import os
import sys
import shutil

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.db_cache import init_db, lookup_cache, store_result

DB_PATH = "malscope.db"

def test_cache_operations():
    print("[TEST] Initializing SQLite database...")
    init_db()
    assert os.path.exists(DB_PATH), "Database file not created"

    # Delete test_hash if it exists from previous run
    test_hash = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM analyses WHERE sha256 = ?", (test_hash,))
    conn.commit()
    conn.close()

    # Test cache miss
    test_hash = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    print("[TEST] Testing cache lookup (expecting miss)...")
    res = lookup_cache(test_hash)
    assert res is None, f"Expected cache miss, got {res}"

    # Test cache insertion
    dummy_payload = {
        "steps": [{"tool": "get_pe_info", "reason": "test"}],
        "report": {"verdict": "clean", "confidence": 95, "summary": "Looks good"}
    }
    print("[TEST] Storing result in cache...")
    store_result(test_hash, "test_app.exe", dummy_payload)

    # Test cache hit
    print("[TEST] Testing cache lookup (expecting hit)...")
    cached = lookup_cache(test_hash)
    assert cached is not None, "Expected cache hit, got None"
    assert cached["report"]["verdict"] == "clean", "Cached data mismatch"
    assert cached["original_filename"] == "test_app.exe", "Filename key mismatch in SQLite return payload"
    
    print("  ✓ DB cache store, hit, and miss logic verified successfully!")

if __name__ == "__main__":
    print("=== STARTING DB CACHE TESTS ===")
    test_cache_operations()
    print("=== ALL DB CACHE TESTS PASSED ===\n")
