import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.model import chat, get_model_backend
from dotenv import load_dotenv

def test_model_connection():
    load_dotenv(override=True)
    llm_base_url = os.getenv("LLM_BASE_URL", "http://localhost:8080/v1")
    llm_model = os.getenv("LLM_MODEL", "gemma-4-e4b")
    
    print("=== MODEL CLIENT CONFIGURATION ===")
    print(f"  Backend: {get_model_backend()}")
    print(f"  URL:     {llm_base_url}")
    print(f"  Model:   {llm_model}")
    
    print("[TEST] Sending sample chat message to model...")
    try:
        response = chat([
            {"role": "system", "content": "You are a helpful assistant. Respond with the word 'OK' only."},
            {"role": "user", "content": "Hello."}
        ])
        print(f"  ✓ LLM Connection Succeeded! Response: {response.strip()}")
    except Exception as e:
        print(f"  ✕ LLM Connection Failed: {e}")
        print("  (Ensure llama-server is running on port 8080 to resolve this.)")

if __name__ == "__main__":
    print("=== STARTING MODEL CONNECTION TEST ===")
    test_model_connection()
    print("=== MODEL TEST COMPLETE ===\n")
