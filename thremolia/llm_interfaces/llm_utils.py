import os
from typing import Literal

from thremolia.llm_interfaces.llm_interface import LLMInterface
from thremolia.llm_interfaces.ollama_interface import OllamaInterface
from thremolia.llm_interfaces.openai_interface import (
    AzureOpenAIInterface,
    ChatGPTInterface,
    OpenAICompatibleInterface,
)

LLM_FRAMEWORKS = [
    "ChatGPT",
    "Ollama",
    "OpenAICompatible",
    "AzureOpenAI",
]
LLM_FRAMEWORKS_LOOKUP = {name.casefold(): name for name in LLM_FRAMEWORKS}
REASONING = ["Default", "Low", "Medium", "High"]


class UnknownInterfaceError(Exception):
    def __init__(self, client_type: str) -> None:
        super().__init__(f"Unknown client type: {client_type}")


def create_llm_client(
    client_type: Literal[
        "chatgpt",
        "ollama",
        "openaicompatible",
        "azureopenai",
    ]
    | None = None,
    model: str | None = None,
    host: str | None = None,
) -> LLMInterface:
    if not client_type:
        client_type = os.getenv("DEFAULT_LLM_INTERFACE")
    if client_type == "chatgpt":
        return ChatGPTInterface(model=model)
    if client_type == "azureopenai":
        return AzureOpenAIInterface(model=model, host=host)
    if client_type == "openaicompatible":
        return OpenAICompatibleInterface(model=model, host=host)
    if client_type == "ollama":
        return OllamaInterface(model=model, host=host)
    raise UnknownInterfaceError(client_type)
