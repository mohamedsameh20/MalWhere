import re

PATTERNS = {
    "url":        re.compile(r'https?://[^\s<>"]+|ftp://[^\s<>"]+'),
    "ip":         re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "file_path":  re.compile(r'[A-Za-z]:\\[^\s<>"]+'),
    "registry":   re.compile(r'HKEY_[A-Z_]+(?:\\[^\s<>"]+)*'),
    "suspicious": re.compile(r'\b(?:encrypt|ransom|bitcoin|shadow|delete|inject|payload|backdoor|keylog|exfiltrate)\b', re.IGNORECASE),
}

WINDOWS_APIS = {
    "WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread",
    "IsDebuggerPresent", "NtQueryInformationProcess", "RegSetValueEx",
    "InternetOpen", "URLDownloadToFile", "CryptEncrypt", "ShellExecute",
    "WinExec", "LoadLibrary", "GetProcAddress", "VirtualAlloc",
    "CreateProcess", "OpenProcess", "VirtualProtect",
}

def extract_strings(filepath: str) -> dict:
    """Extract printable ASCII strings from file bytes. Classify by pattern. Return top 50."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        
        # Extract ASCII strings of 5+ chars
        raw_strings = re.findall(rb'[\x20-\x7e]{5,}', data)
        strings = []
        # Keep unique strings to avoid clutter
        seen = set()
        for s in raw_strings:
            decoded = s.decode("ascii", errors="replace").strip()
            if decoded and decoded not in seen:
                seen.add(decoded)
                strings.append(decoded)

        classified = []
        generic = []

        for s in strings:
            category = None
            for cat_name, pattern in PATTERNS.items():
                if pattern.search(s):
                    category = cat_name
                    break
            
            if category is None:
                for api in WINDOWS_APIS:
                    if api in s:
                        category = "windows_api"
                        break

            entry = {"value": s, "category": category or "generic"}
            if category:
                classified.append(entry)
            else:
                generic.append(entry)

        # Build final list: prioritize classified, then fill with generic up to 50
        result = classified[:50]
        remaining = 50 - len(result)
        if remaining > 0:
            result.extend(generic[:remaining])

        return {
            "strings": result,
            "total_extracted": len(strings),
            "showing": len(result)
        }
    except Exception as e:
        return {"error": f"Failed to extract strings: {str(e)}"}
