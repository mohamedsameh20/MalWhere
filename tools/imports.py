import pefile

DANGEROUS_APIS = {
    "WriteProcessMemory":          {"risk": "high",   "technique": "T1055 - Process Injection"},
    "VirtualAllocEx":              {"risk": "high",   "technique": "T1055 - Remote Memory Allocation"},
    "CreateRemoteThread":          {"risk": "high",   "technique": "T1055 - Remote Thread Execution"},
    "IsDebuggerPresent":           {"risk": "medium", "technique": "T1622 - Anti-Debug"},
    "CheckRemoteDebuggerPresent":  {"risk": "medium", "technique": "T1622 - Anti-Debug"},
    "NtQueryInformationProcess":   {"risk": "medium", "technique": "T1622 - Anti-Debug"},
    "RegSetValueExA":              {"risk": "medium", "technique": "T1547 - Persistence"},
    "RegSetValueExW":              {"risk": "medium", "technique": "T1547 - Persistence"},
    "InternetOpenA":               {"risk": "medium", "technique": "T1071 - Network Communication"},
    "InternetOpenW":               {"risk": "medium", "technique": "T1071 - Network Communication"},
    "URLDownloadToFileA":          {"risk": "high",   "technique": "T1105 - Dropper"},
    "URLDownloadToFileW":          {"risk": "high",   "technique": "T1105 - Dropper"},
    "CryptEncrypt":                {"risk": "medium", "technique": "T1486 - Encryption"},
    "ShellExecuteA":               {"risk": "medium", "technique": "T1059 - Execution"},
    "ShellExecuteW":               {"risk": "medium", "technique": "T1059 - Execution"},
    "WinExec":                     {"risk": "high",   "technique": "T1059 - Execution"},
}

def analyze_imports(filepath: str) -> dict:
    """Extract PE import table. Flag dangerous Windows APIs."""
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError as e:
        return {"error": f"Not a valid PE file: {str(e)}"}
    except Exception as e:
        return {"error": f"Failed to analyze imports: {str(e)}"}

    try:
        imports_by_dll = {}
        total_imports = 0

        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            pe.close()
            return {"imports": {}, "flagged": [], "total_imports": 0}

        # 3. Build imports dict
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode("utf-8", errors="replace")
                else:
                    func_name = f"ordinal_{imp.ordinal}"
                funcs.append(func_name)
                total_imports += 1
            imports_by_dll[dll_name] = funcs

        # 4. Build flagged list
        flagged = []
        for dll_name, funcs in imports_by_dll.items():
            for func_name in funcs:
                if func_name in DANGEROUS_APIS:
                    flagged.append({
                        "api": func_name,
                        "dll": dll_name,
                        "risk": DANGEROUS_APIS[func_name]["risk"],
                        "technique": DANGEROUS_APIS[func_name]["technique"]
                    })

        # 5. Cap imports_by_dll if total functions > 200
        if total_imports > 200:
            for dll_name in imports_by_dll:
                imports_by_dll[dll_name] = imports_by_dll[dll_name][:20]

        pe.close()

        return {
            "imports": imports_by_dll,
            "flagged": flagged,
            "total_imports": total_imports
        }

    except Exception as e:
        try:
            pe.close()
        except Exception:
            pass
        return {"error": f"Failed to analyze imports: {str(e)}"}
