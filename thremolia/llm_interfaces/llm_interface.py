import abc
import base64
from os import getenv
from typing import Literal

import chromadb
import chromadb.errors
import pandas as pd
from chromadb.config import Settings
from PIL import Image
from pydantic import BaseModel, ValidationError
from pydantic_core import from_json

from thremolia.llm_interfaces.tools import TOOLSET
from thremolia.threat import (
    THREAT_MODELS_DATA,
    ElementCount,
    Message,
    Report,
    ReportScore,
)
from thremolia.utils import PROMPTS_PATH, ROOT_PATH, logger

LLM_GENERATION_LIMITER = int(getenv("LLM_GENERATION_LIMITER", "30"))
DB_PATH = ROOT_PATH / "db" / "chroma"
EMBEDDINGS_PER_COLLECTION = 2

SYSTEM_PROMPT = (PROMPTS_PATH / "system_prompt_v4.md").read_text()
IMG_PROMPT = (PROMPTS_PATH / "image_recognition.md").read_text()
HEALTH_PROMPT = (PROMPTS_PATH / "health_check.md").read_text()
DEPLOYMENT_PROMPT = (PROMPTS_PATH / "deployment_recognition.md").read_text()
REQUIREMENTS_PROMPT = (PROMPTS_PATH / "requirements_summarization.md").read_text()


def create_tm_data() -> dict:
    tm_dict = {
        "STRIDE": (PROMPTS_PATH / "STRIDE_matrix.md").read_text(),
    }
    for cfg in THREAT_MODELS_DATA:
        tm_dict[cfg.name] = cfg.prompt

    return tm_dict


THREAT_MODEL_DATA = create_tm_data()


class LLMInterface(abc.ABC):
    def __init__(
        self,
        model: str | None = None,
        host: str | None = None,
        message_history: list[dict] | None = None,
        reasoning: Literal["default", "low", "medium", "high"] = "none",
    ) -> None:
        self.model = model
        if not self.img_to_text_model:
            self.img_to_text_model = model
        if not self.validation_model:
            self.validation_model = model

        self.host = host
        self.type = self.get_llm_type()

        self.dbclient = chromadb.PersistentClient(
            path=str(DB_PATH),
            settings=Settings(anonymized_telemetry=False),
        )  # disabled chroma telemetry
        self.dbclient.heartbeat()

        if message_history is None:
            self.message_history = []
        else:
            self.message_history = message_history

        self.system_prompt = SYSTEM_PROMPT
        self.generate_system_prompt()

        self.collection_names = [
            f"{tm.threat_field.upper()}_{self.type}" for tm in THREAT_MODELS_DATA
        ]
        if not self.reasoning:
            self.reasoning = reasoning

    @abc.abstractmethod
    def _embed(self, data: str) -> list[float]:
        """Converts input data into embedded vector."""

    @abc.abstractmethod
    def _send_chat(
        self,
        message: list[dict],
        response_format: dict | type[BaseModel] | None = None,
        model: str | None = None,
    ) -> str:
        """Sends message to the llm chat."""

    @abc.abstractmethod
    def _image(self, base64_image: str) -> str:
        """Sends image to the llm."""

    @abc.abstractmethod
    def check_api(self) -> bool:
        """Check if API is accessible"""

    @abc.abstractmethod
    def list_models(self) -> list[str]:
        """Returns list of available models."""

    @abc.abstractmethod
    def get_llm_type(self) -> str:
        """Returns the type of the LLM interface (e.g., OpenAI, Ollama, LiteLLM)."""

    @abc.abstractmethod
    def _send_chat_tool(
        self,
        message: list[dict],
        tools: list[dict],
        response_format: dict | type[BaseModel] | None = None,
        model: str | None = None,
    ) -> dict:
        """Sends message to the llm chat."""

    @abc.abstractmethod
    def _handle_tool_calls(
        self,
        tool_calls: list,
    ) -> tuple[bool, list]:
        """Executes all tool calls in the list."""

    def set_models(
        self,
        main_model: str,
        img_to_text_model: str,
        validation_model: str,
        embeddings_model: str | None = None,
    ) -> None:
        """
        Sets the models for different tasks.

        Args:
            main_model (str): The main LLM model.
            img_to_text_model (str): The model used for image to text conversion.
            validation_model (str): The model used for report validation tasks.
            embeddings_model (str): The model used for embeddings generation.

        """
        self.model = main_model
        self.img_to_text_model = img_to_text_model
        self.validation_model = validation_model

        if embeddings_model:
            self.embeddings_model = embeddings_model

    def set_reasoning(
        self,
        reasoning: Literal["none", "low", "medium", "high"] = "none",
    ) -> None:
        """Sets the reasoning effort for the LLM."""
        self.reasoning = reasoning

    def create_default_collections(self) -> None:
        """
        Creates default collections from the provided csvs if they do not exist.
        """
        logger.info("create_default_collections called")
        for collection_name, data in zip(
            self.collection_names,
            [tm.dataset for tm in THREAT_MODELS_DATA],
            strict=True,
        ):
            try:
                self.dbclient.get_collection(name=collection_name)
            except chromadb.errors.NotFoundError:
                collection = self.dbclient.create_collection(
                    name=collection_name,
                    metadata={"type": self.type, "threat_model": collection_name},
                )
                documents, metadatas = self.construct_chroma_data(data)
                self.generate_embeddings(documents, metadatas, collection)

    def check_collections(self) -> bool:
        for collection_name in self.collection_names:
            try:
                self.dbclient.get_collection(name=collection_name)
            except chromadb.errors.NotFoundError:
                return False
        return True

    @staticmethod
    def construct_chroma_data(data: pd.DataFrame) -> tuple[list[str], list[dict]]:
        """
        Constructs data for chromadb from the provided csv file.
        """
        documents = data["Document"].to_list()
        metadatas = data.drop(columns=["Document"]).to_dict(orient="records")
        return documents, metadatas

    def generate_embeddings(
        self,
        docs: list[str],
        metadatas: list[dict],
        collection: chromadb.Collection,
    ) -> None:
        """
        Generates new embeddings from the provided docs and stores them in the provided collection.

        Args:
            docs (list[str]): The list of strings to be transformed into embeddings.
            metadatas (list[dict]): The list of dictionaries containing metadata for each doc.
            collection (chromadb.Collection): The collection where the embeddings will be stored.

        """
        for index, data in enumerate(docs):
            embedding = self._embed(data)
            collection.add(
                ids=[str(index)],
                embeddings=[embedding],
                documents=[data],
                metadatas=[metadatas[index]],
            )

    def retrieve_embeddings(
        self,
        prompt: str,
        collections: list[str],
        n_results: int = 10,
        where: dict | None = None,
    ) -> pd.DataFrame:
        """
        Uses the input prompt to retrieve the first <n_results> most relevant docs from the chromadb collections.
        The input prompt is converted to embedding for the search.

        Args:
            prompt (str): The input prompt.
            collections (list[str]): List of collections names for the data to be retrieved from.
            n_results (int, optional): The number of results per collection to return. Defaults to 10.
            where (dict, optional): A dictionary specifying the filtering criteria for the query. Defaults to None.

        Return:
            pd.DataFrame: A DataFrame containing the retrieved data.

        """
        response = self._embed(prompt)
        dataframes = []
        for collection_name in collections:
            collection = self.dbclient.get_collection(name=collection_name)
            results = collection.query(
                query_embeddings=[response],
                n_results=n_results,
                where=where,
            )
            dataframes.append(
                pd.DataFrame(
                    {
                        "ids": results["ids"][0],
                        "documents": results["documents"][0],
                        "distances": results["distances"][0],
                        "metadatas": results["metadatas"][0],
                    },
                ),
            )
        return pd.concat(dataframes)

    def send_chat_message(
        self,
        prompt: str,
        response_format: dict | type[BaseModel] | None = None,
    ) -> Report | str:
        """
        Sends the prompt to the LLM with message history.

        Stores the input prompt and the full response for future use.

        Args:
            prompt (str): The input prompt.
            response_format (dict[str, Any], optional): A dictionary specifying formatting options for the model's response. Defaults to None.

        Return:
            Report | str: The response from the LLM either in Report or in str format.

        """
        logger.debug(f"Message sent to LLM: {prompt}")
        self.message_history.append({"role": "user", "content": prompt})

        response = self._send_chat(self.message_history, response_format)
        logger.debug(f"LLM response: {response}")
        self.message_history.append({"role": "assistant", "content": response})

        if response_format:
            try:
                return response_format.model_validate(
                    from_json(response, allow_partial=True),
                )
            except ValidationError:
                logger.exception("An error occurred: ValidationError")
        return response

    def chat_with_embeddings(
        self,
        prompt: str,
        collections: list[str] | None = None,
    ) -> str:
        """
        Sends the prompt extended with embedding data to the LLM.
        """
        if not collections:
            collections = self.collection_names

        embeddings_df = self.retrieve_embeddings(
            prompt,
            collections,
            n_results=EMBEDDINGS_PER_COLLECTION,
        )
        embeddings = "\n ".join(embeddings_df["documents"].to_list())
        response = self.send_chat_message(
            f"User input:\n{prompt}\n\nUseful information:\n{embeddings}",
            Message,
        )
        return response.message

    def describe_image(self, image: Image.Image | str) -> str:
        """
        Sends image to the LLM and returns its text description.
        """
        logger.info("describe_image called")
        logger.debug(f"Image: {image}")

        if isinstance(image, str):
            response = self._image(image)
        else:
            response = self._image(base64.b64encode(image.read()).decode("utf-8"))

        logger.debug(f"LLM image description: {response}")
        return response

    def generate_report(
        self,
        description: str,
        selected_models: list[str],
        extra_requirements: str | None = None,
    ) -> Report:
        logger.info("generate_report called")
        logger.debug(f"Models selected: {selected_models}")
        self.generate_system_prompt(selected_models, extra_requirements)

        complete_report = self.send_chat_message(description, Report)

        if not complete_report.is_final:
            generations = 0
            while generations < LLM_GENERATION_LIMITER:
                report = self.send_chat_message("**CONTINUE**", Report)
                complete_report.add_part(report)
                generations += 1
                if report.is_final:
                    break

        complete_report.calculate_cvss()
        complete_report.fix_categories()
        return complete_report

    def extend_report(
        self,
        report: Report,
        selected_models: list[str],
        missing_threats: list,
    ) -> Report:
        """
        Asks LLM to extend the report with missing threats.
        """
        logger.info("extend_report called")
        if not missing_threats:
            logger.info("No missing threats provided")
            return report

        logger.debug(f"Categories to extend: {missing_threats}")

        missing_threats_str = "\n - " + ";\n - ".join(missing_threats)
        prompt = f"""
We have identified some missing threats in the report. Please extend the report with the missing threats.

# **Missing threats:**
{missing_threats_str}

- Continue the original threat ID order.
- For ATLAS and OWASP missing threats please select proper elements of occurrence and don't forget to fill STRIDE category.
- Use ATLAS threats only if applicable to the system.
- If you reach a limit of the response size, fill the **is_final** field with **False** to indicate that there are more threats and not all of them made it to this report part.
- When asked to **CONTINUE**, provide other threats that did not made it to the previous report part. In this case in the message field you can also provide some summary regarding previous report part.
- Do not ask any additional questions, simply provide required threats.
"""
        # empty message field to avoid duplication in the chat history
        report.message = ""
        report.add_part(self.generate_report(prompt, selected_models))
        return report

    def fix_report(
        self,
        report: Report,
        selected_models: list[str],
        mistakes: pd.DataFrame,
    ) -> Report:
        """
        Asks LLM to fix the report using list of mistakes.
        """
        logger.info("fix_report called")

        if mistakes.empty:
            logger.info("No mistakes to fix")
            return report

        valid_mistakes = (
            mistakes[mistakes["valid"]]
            .loc[:, ["id", "description"]]
            .to_string(index=False)
        )
        logger.debug(f"Selected models: {selected_models}")
        logger.debug(f"Mistakes to fix: {valid_mistakes}")

        prompt = f"""
Please fix the following mistakes in the report.

# **Mistakes:**
{valid_mistakes}

- Your answer must contain only fixed threats from the list above.
- Retain the original threat ID and Element/Dataflow name.
- If you reach a limit of the response size, fill the **is_final** field with **False** to indicate that there are more threats and not all of them made it to this report part.
- When asked to **CONTINUE**, provide other threats that did not made it to the previous report part. In this case in the message field you can also provide some summary regarding previous report part.
- Do not ask any additional questions, simply provide required threats.
"""
        fixed_threats = self.generate_report(prompt, selected_models)
        report.message = ""
        report.replace_part(fixed_threats)
        return report

    def get_element_count(self, description: str) -> tuple[int, int]:
        messages = [
            {
                "role": "system",
                "content": "Analyze the following system description and provide the total number of elements and dataflows present in the system.",
            },
            {
                "role": "user",
                "content": description,
            },
        ]

        response = self._send_chat(messages, ElementCount)
        score = ElementCount.model_validate_json(response)

        return score.element_count, score.dataflow_count

    def score_report(
        self,
        description: str,
        report: Report,
        prompt: str = "",
    ) -> tuple[str, int]:
        messages = [
            {
                "role": "system",
                "content": prompt if prompt else HEALTH_PROMPT,
            },
            {
                "role": "user",
                "content": f"""
                # **System description:**
                {description}
                # **Threat Modeling Report:**
                {report.model_dump()}
                """,
            },
        ]
        response = self._send_chat(messages, ReportScore, self.validation_model)
        score = ReportScore.model_validate_json(response)

        return score.justification, score.report_score

    def generate_system_prompt(
        self,
        selected_threat_models: list[str] | None = None,
        extra_data: str | None = None,
    ) -> None:
        """
        Generates system prompt based on inputs and automatically adds it to
        the message history or replaces existing with a new one.

        Args:
            selected_threat_models (list[str], optional): A list of Threat Modeling Frameworks to be used. Supported values: "OWASP TOP 10 for LLM", "STRIDE", "MITRE ATLAS"
            extra_data (str, optional): A string with extra data that will be added at the end of system prompt.

        """
        unselected_models = set(THREAT_MODEL_DATA.keys())
        unselected_models_prompt = ""
        selected_models_prompt = ""

        # includes/excludes information about selected threat modeling frameworks
        if selected_threat_models:
            for model in selected_threat_models:
                if model in THREAT_MODEL_DATA:
                    selected_models_prompt += THREAT_MODEL_DATA[model] + "\n"
                    unselected_models.discard(model)

        if unselected_models:
            unselected_models_prompt = f"Leave fields corresponding to {', '.join(unselected_models)} threat modeling frameworks threats empty."

        threats_context = f"\n\n{selected_models_prompt}\n\n{unselected_models_prompt}"

        prompt = self.system_prompt.replace("<threats_context>", threats_context)

        if extra_data:
            prompt += "\n\n" + extra_data

        system_prompt = {
            "role": "system",
            "content": prompt,
        }

        if not self.message_history:
            self.message_history.append(system_prompt)
        else:
            self.message_history[0] = system_prompt

    def summarize_requirements(self, chunks: list[str]) -> str:
        """
        Sends text to the LLM and returns summarized variant with explicitly stated cybersecurity requirements.
        """
        logger.info("summarize_requirements called")
        message_history = [
            {"role": "system", "content": REQUIREMENTS_PROMPT},
        ]
        chunk_summaries = []

        for chunk in chunks:
            logger.debug(f"Source chunk: {chunk}")

            message_history.append(
                {"role": "user", "content": f"Summarize this text: {chunk}"},
            )
            response = self._send_chat(message_history, model=self.img_to_text_model)
            message_history.append({"role": "assistant", "content": response})
            chunk_summaries.append(response)
            logger.debug(f"LLM chunk summarization: {response}")

        # for cases with more than 1 chunk we perform a final summarization
        if len(chunk_summaries) > 1:
            logger.info("Performing final summarization for all chunks")
            response = self._send_chat(
                [
                    {"role": "system", "content": REQUIREMENTS_PROMPT},
                    {
                        "role": "user",
                        "content": f"Summarize this text: {' '.join(chunk_summaries)}",
                    },
                ],
                model=self.img_to_text_model,
            )
            logger.debug(f"Final LLM document summarization: {response}")

        return response

    def describe_deployment(self, file: str) -> str:
        """
        Sends deployment file to the LLM and returns its text description.
        """
        logger.info("describe_deployment")
        logger.debug(f"Conf file: {file}")
        response = self._send_chat(
            [{"role": "user", "content": DEPLOYMENT_PROMPT + f"{file}"}],
        )
        logger.debug(f"LLM conf file description: {response}")
        return response

    def chat_with_tools(self, prompt: str) -> tuple[str, bool, list]:
        embeddings_df = self.retrieve_embeddings(
            prompt,
            self.collection_names,
            n_results=EMBEDDINGS_PER_COLLECTION,
        )
        embeddings = "\n ".join(embeddings_df["documents"].to_list())
        message = f"User input:\n{prompt}\n\nUseful information:\n{embeddings}"
        logger.debug(f"Message sent to LLM: {message}")
        self.message_history.append({"role": "user", "content": message})
        response = self._send_chat_tool(self.message_history, TOOLSET)

        return self.handle_tool_calls(response)

    def handle_tool_calls(self, response: BaseModel) -> tuple[str, bool, list]:
        if not response.tool_calls:
            logger.debug(f"No tool calls in the response: {response.content}")
            self.message_history.append(
                {"role": "assistant", "content": response.content},
            )
            return response.content, False, []

        logger.debug(f"LLM response contains tool calls: {response}")

        report_changed, messages = self._handle_tool_calls(response.tool_calls)

        next_response = self._send_chat_tool(self.message_history, TOOLSET)
        logger.debug(f"LLM final response: {next_response}")

        # Rare case: LLM might decide to call tools again
        final_response, recursive_changed, new_messages = self.handle_tool_calls(
            next_response,
        )
        messages.extend(new_messages)

        # Return True if report was changed in any recursion step
        return final_response, recursive_changed or report_changed, messages
