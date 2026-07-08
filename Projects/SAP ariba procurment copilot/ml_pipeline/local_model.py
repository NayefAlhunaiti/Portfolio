import json
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def extract_json_object(text):
    """Extract JSON object from text."""
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start : index + 1]
                try:
                    json.loads(candidate)
                    return candidate
                except json.JSONDecodeError:
                    return None
    return None


def generate_text(prompt, config, response_format="text"):
    """Call Ollama API for text generation."""
    backend = str(config.get("model_backend", "ollama")).lower()
    if backend != "ollama":
        raise RuntimeError(f"Unsupported model backend: {backend}. Set model_backend to ollama.")

    base_url = str(config.get("ollama_base_url", "http://localhost:11434")).rstrip("/")
    model = str(config.get("ollama_model", "llama3.1:8b"))
    temperature = float(config.get("temperature", 0.3))
    max_new_tokens = int(config.get("max_new_tokens", 512))

    request_data = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": max_new_tokens,
            "top_p": float(config.get("top_p", 0.9)),
            "top_k": int(config.get("top_k", 50)),
            "repeat_penalty": float(config.get("repeat_penalty", 1.05)),
        },
    }
    if response_format in {"json", "structured"}:
        request_data["format"] = "json"

    try:
        req = urllib.request.Request(
            f"{base_url}/api/generate",
            data=json.dumps(request_data).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=int(config.get("generation_max_time", 60))) as response:
            payload = json.loads(response.read().decode())
            text = payload.get("response", "")
            if not isinstance(text, str) or not text.strip():
                raise RuntimeError("Ollama returned an empty response.")
            json_block = extract_json_object(text)
            return json_block or text
    except urllib.error.URLError as e:
        raise RuntimeError(f"Ollama API error: {e}. Ensure Ollama is running at {base_url}")
    except Exception as e:
        raise RuntimeError(f"Error calling Ollama: {e}")
