"""SecurePrompt Python client library.

Mirrors the openai Python client shape for drop-in substitution:
    client = SecurePromptClient(api_key="...", base_url="...")
    response = client.chat.completions.create(model="...", messages=[...])
"""

from secureprompt._client import AsyncSecurePromptClient, SecurePromptClient

__all__ = ["SecurePromptClient", "AsyncSecurePromptClient"]
__version__ = "0.1.0"
