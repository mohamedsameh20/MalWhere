import os
import json
import numpy as np

try:
    import numpy as np
    if not hasattr(np, "int"):
        np.int = int

    import lief
    if not hasattr(lief, "bad_format"):
        class DummyLiefError(Exception):
            pass
        lief.bad_format = getattr(lief, "exception", DummyLiefError)
        lief.bad_file = getattr(lief, "exception", DummyLiefError)
        lief.pe_error = getattr(lief, "exception", DummyLiefError)
        lief.parser_error = getattr(lief, "exception", DummyLiefError)
        lief.read_out_of_bound = getattr(lief, "exception", DummyLiefError)

    from sklearn.feature_extraction import FeatureHasher
    original_transform = FeatureHasher.transform
    def patched_transform(self, raw_X):
        if getattr(self, "input_type", "") == "string" and isinstance(raw_X, list):
            new_X = []
            for x in raw_X:
                if isinstance(x, str):
                    new_X.append([x])
                else:
                    new_X.append(x)
            raw_X = new_X
        return original_transform(self, raw_X)
    FeatureHasher.transform = patched_transform

    import ember
    import lightgbm as lgb
    EMBER_AVAILABLE = True
except Exception:
    EMBER_AVAILABLE = False

def ml_risk_score(filepath: str) -> dict:
    """Score PE file using EMBER LightGBM model. No fallback allowed."""
    if not EMBER_AVAILABLE:
        return {
            "error": "EMBER dependency is not available. Fallback is disabled.",
            "score": None,
            "model": "EMBER LightGBM"
        }
    return _ember_score(filepath)

def _ember_score(filepath: str) -> dict:
    """Real EMBER scoring — only runs if ember package is available."""
    try:
        with open(filepath, "rb") as f:
            file_data = f.read()
        extractor = ember.features.PEFeatureExtractor(feature_version=2)
        features = np.array(extractor.feature_vector(file_data), dtype=np.float32).reshape(1, -1)
        # Load pre-trained model
        model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "ember_model.txt")
        if not os.path.exists(model_path):
            return {"error": f"EMBER model file not found at {model_path}", "score": None, "model": "EMBER LightGBM"}
        
        model = lgb.Booster(model_file=model_path)
        score = float(model.predict(features)[0])
        verdict = "clean" if score < 0.3 else "suspicious" if score < 0.7 else "malicious"
        return {"score": round(score, 4), "verdict": verdict, "model": "EMBER LightGBM"}
    except Exception as e:
        return {"error": f"EMBER scoring failed: {str(e)}", "score": None, "model": "EMBER LightGBM"}

def _heuristic_score(filepath: str) -> dict:
    """Fallback heuristic when EMBER is not available.
    Combines entropy analysis and import danger signals into a 0-1 score."""
    try:
        from tools.entropy import scan_section_entropy
        from tools.imports import analyze_imports
        
        score = 0.0
        reasons = []
        
        # Factor 1: Section entropy (weight: 0.4)
        entropy_result = scan_section_entropy(filepath)
        if "error" not in entropy_result:
            sections = entropy_result.get("sections", [])
            high_entropy_count = sum(1 for s in sections if s["entropy"] > 7.0)
            very_high_count = sum(1 for s in sections if s["entropy"] > 7.5)
            total = len(sections) or 1
            entropy_ratio = high_entropy_count / total
            score += entropy_ratio * 0.4
            if very_high_count > 0:
                score += 0.1
                reasons.append(f"{very_high_count} sections with entropy > 7.5")
            if high_entropy_count > 0:
                reasons.append(f"{high_entropy_count}/{total} sections with high entropy")
        else:
            # If entropy scanning returned error, PE is likely invalid.
            # We flag this in reasons but don't artificially spike score based on invalid PE.
            pass
        
        # Factor 2: Dangerous imports (weight: 0.4)
        imports_result = analyze_imports(filepath)
        if "error" not in imports_result:
            flagged = imports_result.get("flagged", [])
            high_risk = sum(1 for f in flagged if f["risk"] == "high")
            medium_risk = sum(1 for f in flagged if f["risk"] == "medium")
            danger_score = min((high_risk * 0.15 + medium_risk * 0.05), 0.4)
            score += danger_score
            if high_risk > 0:
                reasons.append(f"{high_risk} high-risk API imports")
            if medium_risk > 0:
                reasons.append(f"{medium_risk} medium-risk API imports")
        
        # Factor 3: Small file size is suspicious for PE (weight: 0.1)
        try:
            file_size = os.path.getsize(filepath)
            if file_size < 50000:  # under 50KB
                score += 0.1
                reasons.append("unusually small PE file")
        except Exception:
            pass
        
        score = round(min(score, 1.0), 4)
        verdict = "clean" if score < 0.3 else "suspicious" if score < 0.7 else "malicious"
        
        return {
            "score": score,
            "verdict": verdict,
            "model": "Heuristic (EMBER unavailable)",
            "factors": reasons
        }
    except Exception as e:
        return {"error": f"Heuristic scoring failed: {str(e)}", "score": None, "model": "Heuristic"}
