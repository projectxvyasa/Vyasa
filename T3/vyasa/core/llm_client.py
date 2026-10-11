"""
LLM Client Interface for VYASA.
Connects to local OpenAI-compatible endpoints (LM Studio, Bionic, Ollama, etc.).
"""

import json
import logging
from typing import Dict, Any, Optional, List
from openai import OpenAI
from vyasa.core.config import LLMConfig

logger = logging.getLogger("vyasa.llm_client")


class LLMClient:
    """Wrapper around OpenAI-compatible local/remote LLM endpoints."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.client = OpenAI(
            base_url=config.base_url,
            api_key=config.api_key or "local",
            timeout=config.timeout_seconds,
            max_retries=1
        )
        self.model_name = config.model

    def is_available(self) -> bool:
        """Quick pre-flight check if LLM endpoint host/port is accepting connections."""
        import urllib.parse
        import socket
        try:
            parsed = urllib.parse.urlparse(self.config.base_url)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            with socket.create_connection((host, port), timeout=0.8):
                return True
        except Exception:
            return False

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict[str, str]] = None,
        suppress_error_log: bool = False
    ) -> str:
        """Execute a chat completion turn."""
        if not self.is_available():
            raise ConnectionError(f"LLM endpoint at {self.config.base_url} is currently offline or unreachable.")

        temp = temperature if temperature is not None else self.config.temperature
        tokens = max_tokens if max_tokens is not None else self.config.max_tokens

        try:
            kwargs: Dict[str, Any] = {
                "model": self.model_name,
                "messages": messages,
                "temperature": temp,
                "max_tokens": tokens,
            }
            if response_format:
                kwargs["response_format"] = response_format

            response = self.client.chat.completions.create(**kwargs)
            return response.choices[0].message.content or ""
        except Exception as e:
            if not suppress_error_log:
                logger.error(f"Error during LLM chat completion: {e}")
            raise

    def structured_json_completion(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: Optional[float] = 0.1
    ) -> Dict[str, Any]:
        """Request structured JSON output from the model and parse it safely."""
        messages = [
            {"role": "system", "content": system_prompt + "\nIMPORTANT: You must respond ONLY with valid, parsable JSON. No preamble, no markdown wrap."},
            {"role": "user", "content": user_prompt}
        ]

        # Attempt json_object format, but fallback gracefully if local server rejects it (e.g. LM Studio requires json_schema or text)
        try:
            raw_output = self.chat_completion(
                messages=messages,
                temperature=temperature,
                response_format={"type": "json_object"},
                suppress_error_log=True
            )
        except Exception as exc:
            logger.debug(f"response_format=json_object rejected ({exc}), retrying without response_format...")
            raw_output = self.chat_completion(
                messages=messages,
                temperature=temperature,
                response_format=None
            )

        try:
            # Clean common markdown code block wrappings if present
            cleaned = raw_output.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()

            return json.loads(cleaned)
        except json.JSONDecodeError as err:
            logger.warning(f"Failed to parse pure JSON: {err}. Raw output was: {raw_output[:200]}...")
            # Fallback extraction: find first '{' and last '}'
            start = raw_output.find("{")
            end = raw_output.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(raw_output[start:end+1])
                except Exception:
                    pass
            raise ValueError(f"LLM did not return valid JSON: {raw_output}")
