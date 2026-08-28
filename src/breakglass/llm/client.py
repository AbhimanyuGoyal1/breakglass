"""LLM provider client abstraction and mock client implementation."""

from abc import ABC, abstractmethod


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
