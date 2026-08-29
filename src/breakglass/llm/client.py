"""LLM provider client abstraction, mock client, and production Gemini client."""

from abc import ABC, abstractmethod
from typing import Optional
import os


class LLMClient(ABC):
    """Abstract interface representing an LLM provider client."""

    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Sends the system and user prompts to the LLM and returns the raw response.

        Args:
            system_prompt: Guidelines and security instructions for the LLM.
            user_prompt: Structured repository evidence and context.

        Returns:
            The raw text response from the LLM.
        """
        pass


class MockLLMClient(LLMClient):
    """Mock client returning controlled responses for offline testing."""

    def __init__(self, response_text: str = ""):
        self.response_text = response_text
        self.last_system_prompt = None
        self.last_user_prompt = None

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        self.last_system_prompt = system_prompt
        self.last_user_prompt = user_prompt
        return self.response_text


class GeminiLLMClient(LLMClient):
    """Production LLM client utilizing the Google Gemini API."""

    def __init__(self, api_key: Optional[str] = None, model_name: str = "gemini-1.5-pro"):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Gemini API API key is missing. Please set either GEMINI_API_KEY or GOOGLE_API_KEY "
                "in your environment variables to use LLM-assisted reasoning."
            )
        self.model_name = model_name

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        import google.generativeai as genai
        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel(
            model_name=self.model_name,
            system_instruction=system_prompt
        )
        response = model.generate_content(user_prompt)
        return response.text
