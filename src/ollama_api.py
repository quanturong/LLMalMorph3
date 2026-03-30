import os
import requests
import json

# Try to import ollama for backward compatibility
try:
    import ollama
    from openai import OpenAI
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

API_KEY = os.getenv("MISTRAL_API_KEY")  # lấy từ biến môi trường
BASE_URL = "https://api.mistral.ai/v1/chat/completions"

def ollama_chat_api(model_name, system_prompt, user_prompt, seed=42):
    """
    Gọi Mistral API (Codestral) thay cho Ollama local.
    Maintains backward compatibility with existing code.
    """
    
    print("=>=>=> Using Mistral API (model:", model_name, ", seed:", seed, ")")

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }

    data = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.7,
        "top_p": 0.9,
    }

    response = requests.post(BASE_URL, headers=headers, data=json.dumps(data))

    if response.status_code != 200:
        raise Exception(f"API call failed: {response.status_code}, {response.text}")

    result = response.json()
    return result["choices"][0]["message"]["content"]


def ollama_generate_api(model_name, prompt):
    """
    Generate API - for backward compatibility.
    Uses Mistral API instead of Ollama.
    """
    print('*'*10, f'Generating code using model {model_name}', '*'*10)
    # Use chat API with empty system prompt
    return ollama_chat_api(model_name, "", prompt, seed=42)


def ollama_openai_chat_api(openai_client, model_name, system_prompt, user_prompt):
    """
    OpenAI-compatible API - for backward compatibility.
    Uses Mistral API instead of Ollama.
    """
    print('*'*10, f'Generating with {model_name}', '*'*10)
    return ollama_chat_api(model_name, system_prompt, user_prompt, seed=42)


def print_model_names():
    """
    Mistral API không có list model như Ollama,
    nên bạn chỉ cần gọi thủ công tên model.
    Ví dụ: codestral-2508, codestral-latest
    """
    print("Available models: codestral-2508, codestral-latest")
    
    # Try to list Ollama models if available
    if OLLAMA_AVAILABLE:
        try:
            models = ollama.list()['models']
            print("\nOllama models (if using local Ollama):")
            for model in models:
                print(f"  - {model['name']}")
        except Exception:
            pass

