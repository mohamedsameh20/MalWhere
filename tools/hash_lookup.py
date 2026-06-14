import requests
import os
from dotenv import load_dotenv

load_dotenv()

def hash_lookup(sha256: str) -> dict:
    """Look up file SHA256 on MalwareBazaar and VirusTotal."""
    if not sha256:
        return {"error": "No SHA256 hash provided"}
        
    try:
        # 1. Query MalwareBazaar (optional, if key set)
        mb_result = None
        mb_key = os.getenv("MALWAREBAZAAR_API_KEY", "").strip()
        if mb_key:
            mb_url = "https://mb-api.abuse.ch/api/v1/"
            payload = {"query": "get_info", "hash": sha256}
            headers = {"Auth-Key": mb_key}
            try:
                resp = requests.post(mb_url, data=payload, headers=headers, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("query_status") == "hash_not_found":
                        mb_result = {"status": "unknown"}
                    elif data.get("query_status") == "ok" and data.get("data"):
                        sample = data["data"][0]
                        mb_result = {
                            "status": "known",
                            "malware_family": sample.get("signature", "unknown"),
                            "file_type": sample.get("file_type", ""),
                            "first_seen": sample.get("first_seen", ""),
                            "tags": sample.get("tags", []),
                            "reporter": sample.get("reporter", "")
                        }
                    else:
                        mb_result = {"status": "error", "detail": data.get("query_status", "unknown error")}
                else:
                    mb_result = {"status": "error", "detail": f"HTTP_{resp.status_code}"}
            except Exception as e:
                mb_result = {"status": "error", "detail": f"connection_error: {str(e)}"}
        else:
            mb_result = {"status": "skipped", "reason": "MALWAREBAZAAR_API_KEY not set"}

        # 2. Query VirusTotal (if API key is set)
        vt_result = None
        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        
        if vt_key:
            try:
                headers = {"x-apikey": vt_key}
                resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers, timeout=10)
                if resp.status_code == 200:
                    vt_data = resp.json().get("data", {}).get("attributes", {})
                    stats = vt_data.get("last_analysis_stats", {})
                    vt_result = {
                        "status": "found",
                        "detections": stats.get("malicious", 0),
                        "total_engines": sum(stats.values()),
                        "popular_threat_name": vt_data.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
                        "first_submission": vt_data.get("first_submission_date", ""),
                        "tags": vt_data.get("tags", [])[:10]
                    }
                elif resp.status_code == 404:
                    vt_result = {"status": "not_found"}
                else:
                    vt_result = {"status": "error", "http_code": resp.status_code}
            except Exception as e:
                vt_result = {"status": "error", "detail": str(e)}
        else:
            vt_result = {"status": "skipped", "reason": "VIRUSTOTAL_API_KEY not set"}

        # 3. Determine overall known status using proper thresholds
        is_known = False
        if mb_result and mb_result.get("status") == "known":
            is_known = True
        
        vt_detections = 0
        vt_total = 0
        vt_detection_ratio = 0.0
        if vt_result and vt_result.get("status") == "found":
            vt_detections = vt_result.get("detections", 0)
            vt_total = vt_result.get("total_engines", 1)
            vt_detection_ratio = round(vt_detections / max(vt_total, 1), 4)
            # Require >= 5 detections AND >= 10% detection rate to flag as known malware
            # Low counts (1-4) with low ratios are usually false positives
            if vt_detections >= 5 and vt_detection_ratio >= 0.10:
                is_known = True

        return {
            "sha256": sha256,
            "is_known_malware": is_known,
            "detection_ratio": f"{vt_detections}/{vt_total} ({vt_detection_ratio:.1%})",
            "malware_bazaar": mb_result,
            "virustotal": vt_result
        }

    except Exception as e:
        return {"error": f"Hash lookup failed: {str(e)}"}
