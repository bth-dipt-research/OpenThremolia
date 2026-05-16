import copy
from os import getenv

from openai import AzureOpenAI, OpenAI
from openai._types import NOT_GIVEN
from openai.types.chat import ChatCompletionMessage, ChatCompletionMessageToolCall
from pydantic import BaseModel

from thremolia.llm_interfaces.llm_interface import IMG_PROMPT, LLMInterface
from thremolia.llm_interfaces.tools import TOOLS_WITHOUT_REPORT_UPDATE, call_function
from thremolia.threat import Message
from thremolia.utils import get_required_env, logger

OPENAI_MODEL = "gpt-5.1"
OPENAI_EMBEDDINGS_MODEL = "text-embedding-3-small"
AVAILABLE_MODELS = [
    "gpt-5.2",
    "gpt-5.1",
    "gpt-5",
    "gpt-5-mini",
    "gpt-5-nano",
    "gpt-4.1",
]

AZURE_OPENAI_API_VERSION = "2024-06-01"


class OpenAIInterface(LLMInterface):
    client: OpenAI | AzureOpenAI

    def __init__(
        self,
        model: str | None = None,
        host: str | None = None,
    ) -> None:
        self.reasoning = getenv("DEFAULT_REASONING_EFFORT", "default")
        super().__init__(model, host)

    def _embed(self, data: str) -> list[float]:
        try:
            response = self.client.embeddings.create(
                input=data,
                model=self.embeddings_model,
            )
            return response.data[0].embedding
        except Exception as e:
            logger.error(f"Error in _embed: {e}")
            raise

    def _send_chat(
        self,
        message: list[dict],
        response_format: dict | type[BaseModel] | None = None,
        model: str | None = None,
    ) -> str:
        try:
            response = self.client.beta.chat.completions.parse(
                model=model or self.model,
                messages=message,
                response_format=response_format or NOT_GIVEN,
                reasoning_effort=self.reasoning
                if self.reasoning != "default"
                else NOT_GIVEN,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Error in _send_chat: {e}")
            raise

    def _send_chat_tool(
        self,
        message: list[dict],
        tools: list[dict],
        model: str | None = None,
    ) -> ChatCompletionMessage:
        try:
            response = self.client.beta.chat.completions.parse(
                model=model or self.model,
                messages=message,
                tools=tools,
                response_format=Message,
                reasoning_effort=self.reasoning
                if self.reasoning != "default"
                else NOT_GIVEN,
            )
            return response.choices[0].message
        except Exception as e:
            logger.error(f"Error in _send_chat_tool: {e}")
            raise

    def _image(self, base64_image: str) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.img_to_text_model,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": IMG_PROMPT,
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{base64_image}",
                                },
                            },
                        ],
                    },
                ],
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Error in _image: {e}")
            raise

    def _handle_tool_calls(
        self,
        tool_calls: list[ChatCompletionMessageToolCall],
    ) -> tuple[bool, list]:
        """Executes all tool calls in the list."""
        report_changed = False
        tool_calls_message = {
            "role": "assistant",
            "tool_calls": [],
        }
        tool_results = []
        display_tool_calls = []

        for tool_call in tool_calls:
            if tool_call.type != "function":
                continue

            # potentially can be replaced with simple append of tool_calls list
            # but streamlit can't serialize ChatCompletionMessageToolCall when saving the file for some reason
            tool_info = {
                "id": tool_call.id,
                "type": tool_call.type,
                "function": {
                    "name": tool_call.function.name,
                    "arguments": tool_call.function.arguments,
                },
            }

            result = call_function(
                tool_call.function.name,
                tool_call.function.arguments,
            )

            if tool_call.function.name not in TOOLS_WITHOUT_REPORT_UPDATE:
                report_changed = True

            tool_calls_message["tool_calls"].append(tool_info)
            tool_results.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": str(result),
                },
            )
            display_tool_calls.append(
                {
                    **tool_info,
                    "result": str(result),
                },
            )
            logger.debug(f"Tool call executed: {result}")

        tool_messages = [copy.deepcopy(tool_calls_message), *tool_results]
        self.message_history.extend(tool_messages)

        tool_calls_message["tool_calls"] = display_tool_calls

        return report_changed, [tool_calls_message]

    def list_models(self) -> list[str]:
        models_list = self.client.models.list()
        return [model.id for model in models_list.data]

    def check_api(self) -> tuple[bool, str]:
        try:
            self.client.models.list()
        except Exception as e:
            return False, e.args[0]
        return True, ""


class ChatGPTInterface(OpenAIInterface):
    def __init__(
        self,
        model: str | None = None,
        host: str | None = None,
    ) -> None:
        api_key = get_required_env("OPENAI_API_KEY")
        if not model:
            model = getenv("OPENAI_MODEL", OPENAI_MODEL)

        self.embeddings_model = getenv(
            "OPENAI_EMBEDDINGS_MODEL",
            OPENAI_EMBEDDINGS_MODEL,
        )
        self.img_to_text_model = getenv(
            "OPENAI_VISION_MODEL",
            model,
        )
        self.validation_model = getenv(
            "OPENAI_VALIDATION_MODEL",
            model,
        )
        self.client = OpenAI(api_key=api_key, base_url=host)
        super().__init__(model, host)

    def list_models(self) -> list[str]:
        # sadly official api currently returns a mess of models (deprecated, text-to-img, embeddings),
        # so we return a manually curated list of suitable ones
        return AVAILABLE_MODELS

    def get_llm_type(self) -> str:
        return "ChatGPT"


class OpenAICompatibleInterface(OpenAIInterface):
    def __init__(
        self,
        model: str | None = None,
        host: str | None = None,
    ) -> None:
        api_key = getenv("THIRD_PARTY_API_KEY")
        if not model:
            model = getenv("THIRD_PARTY_MODEL")
        if not host:
            host = get_required_env("THIRD_PARTY_HOST")

        self.embeddings_model = getenv(
            "THIRD_PARTY_EMBEDDINGS_MODEL",
            OPENAI_EMBEDDINGS_MODEL,
        )
        self.img_to_text_model = getenv("THIRD_PARTY_VISION_MODEL", model)
        self.validation_model = getenv("THIRD_PARTY_VALIDATION_MODEL", model)

        self.client = OpenAI(api_key=api_key, base_url=host)
        super().__init__(model, host)

    def get_llm_type(self) -> str:
        return "OpenAICompatible"


class AzureOpenAIInterface(OpenAIInterface):
    def __init__(
        self,
        model: str | None = None,
        host: str | None = None,
    ) -> None:
        api_key = get_required_env("AZURE_OPENAI_API_KEY")
        endpoint = get_required_env("AZURE_OPENAI_ENDPOINT")
        api_version = getenv("AZURE_OPENAI_API_VERSION", AZURE_OPENAI_API_VERSION)

        if not model:
            model = get_required_env("AZURE_OPENAI_MODEL")

        self.embeddings_model = getenv(
            "AZURE_OPENAI_EMBEDDINGS_MODEL",
            OPENAI_EMBEDDINGS_MODEL,
        )
        self.img_to_text_model = getenv("AZURE_OPENAI_VISION_MODEL", model)
        self.validation_model = getenv("AZURE_OPENAI_VALIDATION_MODEL", model)

        self.client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=api_key,
            api_version=api_version,
        )

        super().__init__(model, host)

    def get_llm_type(self) -> str:
        return "AzureOpenAI"
