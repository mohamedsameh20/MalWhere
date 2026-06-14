import pefile
import hashlib
import os
from datetime import datetime, timezone

def get_pe_info(filepath: str) -> dict:
    """Extract basic PE file metadata + compute file hashes."""
    try:
        # 1. Compute MD5 and SHA256
        with open(filepath, "rb") as f:
            data = f.read()
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        file_size = len(data)

        # 2. Parse with pefile
        pe = pefile.PE(data=data)
    except pefile.PEFormatError as e:
        return {"error": f"Not a valid PE file: {str(e)}"}
    except Exception as e:
        return {"error": f"Failed to analyze PE: {str(e)}"}

    try:
        # 3. Extract fields from PE object
        # Convert timestamp to ISO 8601 UTC
        try:
            compile_time = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc).isoformat()
        except Exception:
            compile_time = "Unknown"

        num_sections = pe.FILE_HEADER.NumberOfSections
        
        # Check if DLL flag (0x2000) is set in Characteristics
        characteristics = pe.FILE_HEADER.Characteristics
        is_dll = bool(characteristics & 0x2000)
        is_exe = not is_dll

        linker_version = f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
        dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
        entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        # 4. Close PE object
        pe.close()

        return {
            "md5": md5,
            "sha256": sha256,
            "file_size": file_size,
            "compile_time": compile_time,
            "num_sections": num_sections,
            "is_dll": is_dll,
            "is_exe": is_exe,
            "linker_version": linker_version,
            "dll_characteristics": dll_characteristics,
            "entry_point": entry_point
        }
    except Exception as e:
        try:
            pe.close()
        except Exception:
            pass
        return {"error": f"Failed to analyze PE: {str(e)}"}
