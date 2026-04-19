# secureprompt-py

Python client for the SecurePrompt LLM security gateway.

Mirrors the openai Python client shape for drop-in substitution:

```python
from secureprompt import SecurePromptClient

client = SecurePromptClient(api_key="sp_...", base_url="https://gateway.example.com")
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello"}],
)
print(response.choices[0].message.content)
```

## Install

```bash
pip install secureprompt-py
```

## Requirements

- Python 3.11+
- httpx >= 0.27.0

## Environment variables

- `SECUREPROMPT_API_KEY` — API key (alternative to passing `api_key=`)
- `SECUREPROMPT_BASE_URL` — Gateway base URL (default: `http://localhost:8080`)
