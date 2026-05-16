from os import getenv

from ollama import ChatResponse, Message
from ollama import Client as OllamaClient
from pydantic import BaseModel

from thremolia.llm_interfaces.llm_interface import IMG_PROMPT, LLMInterface
from thremolia.llm_interfaces.tools import TOOLS_WITHOUT_REPORT_UPDATE, call_function
from thremolia.utils import logger

OLLAMA_HOST = "http://localhost:11434"
EMBEDDING_MODEL_CONTEXT = 8192


class OllamaInterface(LLMInterface):
    def __init__(
        self,
        model: str | None = None,
        host: str | None = None,
    ) -> None:
        if not host:
            host = getenv("OLLAMA_HOST", OLLAMA_HOST)
        if not model:
            model = getenv("OLLAMA_MODEL")

        self.client = OllamaClient(host)

        self.embeddings_model = getenv("OLLAMA_EMBEDDINGS_MODEL")
        self.img_to_text_model = getenv("OLLAMA_VISION_MODEL", model)
        self.validation_model = getenv("OLLAMA_VALIDATION_MODEL", model)

        self.reasoning = getenv("DEFAULT_REASONING_EFFORT", "default")

        super().__init__(model, host)

    def _embed(self, data: str) -> list[float]:
        response = self.client.embeddings(
            model=self.embeddings_model,
            prompt=data,
            options={
                "num_ctx": EMBEDDING_MODEL_CONTEXT,
            },
        )
        return response["embedding"]

    def _send_chat(
        self,
        message: list[dict],
        response_format: dict | type[BaseModel] | None = None,
        model: str | None = None,
    ) -> str:
        if response_format and issubclass(response_format, BaseModel):
            response_format = response_format.model_json_schema()

        model = model if model else self.model

        thinking = False
        if "gpt-oss" in model:
            thinking = self.reasoning
        elif self.reasoning != "default":
            thinking = True

        response: ChatResponse = self.client.chat(
            model=model,
            messages=message,
            format=response_format,
            stream=False,
            think=thinking,
        )
        return response.message.content

    def _send_chat_tool(
        self,
        message: list[dict],
        tools: list[dict],
        model: str | None = None,
    ) -> Message:
        model = model if model else self.model

        thinking = False
        if "gpt-oss" in model:
            thinking = self.reasoning
        elif self.reasoning != "default":
            thinking = True

        response: ChatResponse = self.client.chat(
            model=model,
            messages=message,
            format=Message.model_json_schema(),
            tools=tools,
            stream=False,
            think=thinking,
        )
        return response.message

    def _image(self, base64_image: str) -> str:
        response = self.client.generate(
            model=self.img_to_text_model,
            prompt=IMG_PROMPT,
            images=[base64_image],
            stream=False,
        )
        return response.response

    def _handle_tool_calls(
        self,
        tool_calls: list[Message.ToolCall],
    ) -> bool:
        """Executes all tool calls in the list."""
        report_changed = False
        for tool_call in tool_calls:
            result = call_function(
                tool_call.function.name,
                tool_call.function.arguments,
            )

            if tool_call.function.name not in TOOLS_WITHOUT_REPORT_UPDATE:
                report_changed = True

            self.message_history.append(
                {
                    "role": "tool",
                    "content": str(result),
                    "tool_name": tool_call.function.name,
                },
            )
            logger.debug(f"Tool call executed: {result}")

        return report_changed

    def get_llm_type(self) -> str:
        return "Ollama"

    def list_models(self) -> list[str]:
        return [model.model for model in self.client.list().models]

    def check_api(self) -> tuple[bool, str]:
        try:
            self.client.list()
        except Exception as e:
            return False, e.args[0]
        return True, ""
