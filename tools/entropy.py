import pefile
import math
from collections import Counter

def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a bytes sequence."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def scan_section_entropy(filepath: str) -> dict:
    """Compute Shannon entropy of each PE section. Flag packed/encrypted sections."""
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError as e:
        return {"error": f"Not a valid PE file: {str(e)}"}
    except Exception as e:
        return {"error": f"Failed to scan entropy: {str(e)}"}

    try:
        sections = []
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="replace").strip("\x00")
            raw_data = section.get_data()
            entropy = _shannon_entropy(raw_data)
            
            flag = "normal"
            if entropy > 7.5:
                flag = "encrypted_or_compressed"
            elif entropy > 7.0:
                flag = "likely_packed"
            
            sections.append({
                "name": name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": entropy,
                "flag": flag
            })
        
        pe.close()

        return {
            "sections": sections,
            "total_sections": len(sections)
        }
    except Exception as e:
        try:
            pe.close()
        except Exception:
            pass
        return {"error": f"Failed to scan entropy: {str(e)}"}
