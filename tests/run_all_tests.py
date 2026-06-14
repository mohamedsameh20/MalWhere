import subprocess
import sys
import os

def run_test_script(script_name):
    print(f"\nRunning {script_name}...")
    try:
        res = subprocess.run([sys.executable, f"tests/{script_name}"], check=True, capture_output=True, text=True)
        print(res.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[FAILED] {script_name} failed with code {e.returncode}")
        print("Stdout:")
        print(e.stdout)
        print("Stderr:")
        print(e.stderr)
        return False

def main():
    print("==================================================")
    print("           MALWHERE TEST SUITE RUNNER             ")
    print("==================================================")
    
    # Check if test file is present
    test_file = "TestFiles/npp.8.9.6.2.Installer.x64.exe"
    if not os.path.exists(test_file):
        print(f"Error: Test file {test_file} not found.")
        print("Please place a real PE binary (like Notepad++ installer) at that location first.")
        sys.exit(1)
        
    scripts = [
        "test_static_tools.py",
        "test_db_cache.py",
        "test_threat_intel.py",
        "test_model.py"
    ]
    
    passed_all = True
    for script in scripts:
        success = run_test_script(script)
        if not success:
            passed_all = False
            
    print("==================================================")
    if passed_all:
        print("       ALL UNIT TEST MODULES PASSED SUCCESSFULLY! ")
    else:
        print("       SOME TEST MODULES FAILED. CHECK LOGS ABOVE.")
    print("==================================================")

if __name__ == "__main__":
    main()
