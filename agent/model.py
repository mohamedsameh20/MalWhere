import os
from openai import OpenAI
from dotenv import load_dotenv

# Dynamic client setup is initialized inside calls to support runtime changes.

def get_model_backend() -> str:
    """Return which backend is active (for /health endpoint)."""
    load_dotenv(override=True)
    return os.getenv("LLM_MODEL", "gemma-4-e4b")

def chat(messages: list[dict]) -> str:
    """Send messages to LLM, return raw content string."""
    load_dotenv(override=True)
    base_url = os.getenv("LLM_BASE_URL", "http://localhost:8080/v1")
    api_key = os.getenv("LLM_API_KEY", "none")
    model = os.getenv("LLM_MODEL", "gemma-4-e4b")
    
    client = OpenAI(
        base_url=base_url,
        api_key=api_key,
    )
    
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0.1,
        max_tokens=1024,
        response_format=None
    )
    return response.choices[0].message.content
