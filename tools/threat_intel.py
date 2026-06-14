import requests
import os
from dotenv import load_dotenv

load_dotenv()

def threat_intel_lookup(sha256: str) -> dict:
    """Deep threat intelligence lookup on a known SHA256 hash.
    Query AlienVault OTX and ThreatFox."""
    if not sha256:
        return {"error": "No SHA256 hash provided"}

    # 1. Query AlienVault OTX
    otx_key = os.getenv("OTX_API_KEY", "").strip()
    otx_result = None
    
    headers = {}
    if otx_key:
        headers["X-OTX-API-KEY"] = otx_key
    
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general"
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get("pulse_info", {}).get("pulses", [])
            otx_result = {
                "status": "found" if pulses else "no_pulses",
                "pulse_count": len(pulses),
                "threat_actors": [],
                "campaigns": [],
                "tags": []
            }
            seen_tags = set()
            for pulse in pulses[:10]:  # cap at 10
                for tag in pulse.get("tags", []):
                    if tag not in seen_tags:
                        seen_tags.add(tag)
                        otx_result["tags"].append(tag)
                
                adversary = pulse.get("adversary", "")
                if adversary and adversary not in otx_result["threat_actors"]:
                    otx_result["threat_actors"].append(adversary)
                
                targeted = pulse.get("targeted_countries", [])
                for country in targeted:
                    if country not in otx_result["campaigns"]:
                        otx_result["campaigns"].append(country)
            
            otx_result["tags"] = otx_result["tags"][:20]
        elif resp.status_code == 404:
            otx_result = {"status": "not_found"}
        else:
            otx_result = {"status": "error", "http_code": resp.status_code}
    except Exception as e:
        otx_result = {"status": "error", "detail": str(e)}

    # 2. Query ThreatFox (needs Auth-Key)
    tf_result = None
    tf_key = os.getenv("THREATFOX_API_KEY", "").strip()
    if not tf_key:
        # Fallback to MALWAREBAZAAR_API_KEY since both are abuse.ch
        tf_key = os.getenv("MALWAREBAZAAR_API_KEY", "").strip()

    if tf_key:
        try:
            url = "https://threatfox-api.abuse.ch/api/v1/"
            payload = {"query": "search_hash", "hash": sha256}
            headers_tf = {"Auth-Key": tf_key}
            resp = requests.post(url, json=payload, headers=headers_tf, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok" and data.get("data"):
                    entries = data["data"][:10]
                    tf_result = {
                        "status": "found",
                        "iocs": []
                    }
                    for entry in entries:
                        tf_result["iocs"].append({
                            "ioc_type": entry.get("ioc_type", ""),
                            "ioc_value": entry.get("ioc", ""),
                            "threat_type": entry.get("threat_type", ""),
                            "malware": entry.get("malware_printable", ""),
                            "confidence": entry.get("confidence_level", 0),
                            "reporter": entry.get("reporter", ""),
                            "tags": entry.get("tags", [])
                        })
                elif data.get("query_status") == "no_result":
                    tf_result = {"status": "no_results"}
                else:
                    tf_result = {"status": "error", "detail": data.get("query_status", "unknown")}
            else:
                tf_result = {"status": "error", "detail": f"HTTP_{resp.status_code}"}
        except Exception as e:
            tf_result = {"status": "error", "detail": str(e)}
    else:
        tf_result = {"status": "skipped", "reason": "THREATFOX_API_KEY/MALWAREBAZAAR_API_KEY not set"}

    return {
        "sha256": sha256,
        "alienvault_otx": otx_result,
        "threatfox": tf_result
    }
