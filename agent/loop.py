import json
import logging
from agent.model import chat
from agent.prompt import SYSTEM_PROMPT
from tools.pe_info import get_pe_info
from tools.imports import analyze_imports
from tools.entropy import scan_section_entropy
from tools.strings_extractor import extract_strings
from tools.yara_scan import scan_yara
from tools.ml_score import ml_risk_score
from tools.hash_lookup import hash_lookup
from tools.threat_intel import threat_intel_lookup
from tools.visualize import visualize_pe

TOOLS = {
    "get_pe_info":          lambda filepath, args: get_pe_info(filepath),
    "analyze_imports":      lambda filepath, args: analyze_imports(filepath),
    "scan_section_entropy": lambda filepath, args: scan_section_entropy(filepath),
    "extract_strings":      lambda filepath, args: extract_strings(filepath),
    "scan_yara":            lambda filepath, args: scan_yara(filepath),
    "ml_risk_score":        lambda filepath, args: ml_risk_score(filepath),
    "hash_lookup":          lambda filepath, args: hash_lookup(args.get("sha256", "")),
    "threat_intel_lookup":  lambda filepath, args: threat_intel_lookup(args.get("sha256", "")),
    "visualize_pe":         lambda filepath, args: visualize_pe(filepath),
}

MAX_ITERATIONS = 10

logger = logging.getLogger(__name__)

def sanitize_for_llm(data):
    """Recursively clean and truncate data to make it context-safe for the LLM."""
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            if k == "image_base64":
                cleaned[k] = "<base64_png_image_data_placeholder>"
            elif isinstance(v, str) and len(v) > 200:
                cleaned[k] = v[:200] + "... [TRUNCATED FOR CONTEXT]"
            else:
                cleaned[k] = sanitize_for_llm(v)
        return cleaned
    elif isinstance(data, list):
        if len(data) > 10:
            return [sanitize_for_llm(item) for item in data[:10]] + ["... [TRUNCATED LIST FOR CONTEXT]"]
        else:
            return [sanitize_for_llm(item) for item in data]
    elif isinstance(data, str):
        if len(data) > 200:
            return data[:200] + "... [TRUNCATED FOR CONTEXT]"
        return data
    else:
        return data

def run_analysis(filepath: str, step_callback=None) -> dict:
    """Run the full ReAct analysis loop on a PE file.
    
    Args:
        filepath: absolute path to the PE file on disk
        step_callback: optional callable(step_dict) called after each tool execution,
                       used by SSE streaming to push steps to frontend in real time.
    
    Returns:
        {
            "steps": [{"tool": "...", "reason": "...", "result": {...}}, ...],
            "report": {"verdict": "...", "confidence": ..., "summary": "...", ...}
        }
    """
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Analyze the PE file. I have loaded it for you. Begin your investigation."}
    ]
    
    steps = []
    
    for iteration in range(MAX_ITERATIONS):
        print(f"\n--- [AGENT ITERATION {iteration + 1}] ---")
        # Call LLM
        try:
            raw_response = chat(messages)
            print(f"[LLM RAW RESPONSE]:\n{raw_response}\n")
        except Exception as e:
            logger.error(f"LLM call failed at iteration {iteration}: {e}")
            print(f"[LLM FAILED]: {e}")
            return _error_result(steps, f"LLM call failed: {str(e)}")
        
        # Parse JSON and handle LFM2.5 custom tool-call tags/markdown codeblocks
        cleaned_response = raw_response.strip()
        # Remove LFM2.5 tool call wrapper tokens if present
        if "<|tool_call_start|>" in cleaned_response:
            cleaned_response = cleaned_response.split("<|tool_call_start|>")[-1]
        if "<|tool_call_end|>" in cleaned_response:
            cleaned_response = cleaned_response.split("<|tool_call_end|>")[0]
        
        cleaned_response = cleaned_response.strip()
        # Remove markdown JSON code blocks if present
        if cleaned_response.startswith("```"):
            lines = cleaned_response.splitlines()
            if lines[0].startswith("```json") or lines[0] == "```":
                lines = lines[1:]
            if lines and lines[-1] == "```":
                lines = lines[:-1]
            cleaned_response = "\n".join(lines).strip()
            
        try:
            response = json.loads(cleaned_response)
        except json.JSONDecodeError:
            # Model returned invalid JSON — try one more time
            logger.warning(f"Invalid JSON from model, retrying. Raw: {raw_response[:200]}")
            print(f"[PARSING WARNING]: Model returned invalid JSON. Retrying...")
            messages.append({"role": "assistant", "content": raw_response})
            messages.append({"role": "user", "content": "Your response was not valid JSON. Respond with ONLY a JSON object representing a tool_call or a final_report."})
            continue
        
        response_type = response.get("type", "")
        
        # CASE 1: Final report
        if response_type == "final_report":
            print("[AGENT DECISION]: Final Report Produced!")
            report = {
                "verdict": response.get("verdict", "unknown"),
                "confidence": response.get("confidence", 0),
                "summary": response.get("summary", ""),
                "techniques": response.get("techniques", []),
                "iocs": response.get("iocs", [])
            }
            return {"steps": steps, "report": report}
        
        # CASE 2: Tool call
        elif response_type == "tool_call":
            tool_name = response.get("tool", "")
            tool_args = response.get("args", {})
            reason = response.get("reason", "")
            
            print(f"[AGENT TOOL CALL]: {tool_name} with args {tool_args}")
            print(f"[AGENT REASON]: {reason}")
            
            if tool_name not in TOOLS:
                # Unknown tool — tell model and continue
                messages.append({"role": "assistant", "content": raw_response})
                messages.append({"role": "user", "content": f"Unknown tool '{tool_name}'. Available tools: {', '.join(TOOLS.keys())}. Try again."})
                continue
            
            # Execute tool
            try:
                tool_result = TOOLS[tool_name](filepath, tool_args)
            except Exception as e:
                tool_result = {"error": f"Tool '{tool_name}' crashed: {str(e)}"}
            
            print(f"[TOOL OUTCOME]: {json.dumps(tool_result)[:400]}...")
            
            # Log step (with full, untruncated result for frontend/SSE)
            step = {
                "iteration": iteration + 1,
                "tool": tool_name,
                "reason": reason,
                "result": tool_result
            }
            steps.append(step)
            
            # Notify callback (for SSE streaming)
            if step_callback:
                try:
                    step_callback(step)
                except Exception:
                    pass
            
            # Create a sanitized/trimmed version of tool_result for LLM context
            llm_tool_result = sanitize_for_llm(tool_result)
            
            # Add to conversation history
            messages.append({"role": "assistant", "content": raw_response})
            messages.append({"role": "user", "content": f"[Tool result: {json.dumps(llm_tool_result)}]"})
        
        else:
            # Unknown response type — ask model to try again
            messages.append({"role": "assistant", "content": raw_response})
            messages.append({"role": "user", "content": "Invalid response type. Return either a tool_call or final_report JSON object."})
    
    # Hit max iterations — force final report
    messages.append({"role": "user", "content": "You have reached the maximum number of tool calls. You MUST now return a final_report JSON object with your analysis based on all evidence collected so far."})
    
    try:
        raw_response = chat(messages)
        # Handle same cleanup for raw_response
        cleaned_response = raw_response.strip()
        if "<|tool_call_start|>" in cleaned_response:
            cleaned_response = cleaned_response.split("<|tool_call_start|>")[-1]
        if "<|tool_call_end|>" in cleaned_response:
            cleaned_response = cleaned_response.split("<|tool_call_end|>")[0]
        cleaned_response = cleaned_response.strip()
        if cleaned_response.startswith("```"):
            lines = cleaned_response.splitlines()
            if lines[0].startswith("```json") or lines[0] == "```":
                lines = lines[1:]
            if lines and lines[-1] == "```":
                lines = lines[:-1]
            cleaned_response = "\n".join(lines).strip()

        response = json.loads(cleaned_response)
        if response.get("type") == "final_report":
            report = {
                "verdict": response.get("verdict", "unknown"),
                "confidence": response.get("confidence", 0),
                "summary": response.get("summary", ""),
                "techniques": response.get("techniques", []),
                "iocs": response.get("iocs", [])
            }
            return {"steps": steps, "report": report}
    except Exception:
        pass
    
    return _error_result(steps, "Agent failed to produce a final report after maximum iterations.")


def _error_result(steps: list, error_msg: str) -> dict:
    """Generate an error result when the loop fails."""
    return {
        "steps": steps,
        "report": {
            "verdict": "error",
            "confidence": 0,
            "summary": error_msg,
            "techniques": [],
            "iocs": []
        }
    }
