import base64
import io
import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st
from pydantic import BaseModel

from thremolia.report_validation import ManualValidationReport, ValidationReport
from thremolia.threat import Report
from thremolia.utils import ROOT_PATH, logger

CHAT_HISTORY_PATH = ROOT_PATH / "recent_chats"

VALID_LIST = [
    "valid_mistakes",
    "text",
    "manual_validation_report",
    "validation_report",
    "valid_threats",
    "file",
    "report",
    "chat_history",
    "message_history",
    "valid_mistakes",
    "tm_requirements",
    "tm_requirements_files",
]

SAVE_VERSION = "1.1"


def save_chat() -> io.BytesIO:
    logger.info("Updating save data...")

    state_dict = construct_save_file(st.session_state)
    buffer = io.BytesIO()
    buffer.write(json.dumps(state_dict, indent=4).encode("utf-8"))
    buffer.seek(0)
    logger.info("Save data updated successfully.")
    return buffer


def construct_save_file(session_state: dict) -> dict:
    state_dict = {
        "metadata": {
            "date": datetime.now().strftime("%d-%m-%Y %H-%M-%S"),
            "author": session_state.get("name", "Unknown"),
            "save_version": SAVE_VERSION,
            "used_models": {
                "main_model": session_state.llm_interface.model,
                "img_to_text_model": session_state.llm_interface.img_to_text_model,
                "validation_model": session_state.llm_interface.validation_model,
            },
        },
    }

    for key, value in session_state.items():
        if key not in VALID_LIST or key.isdigit():
            continue
        if isinstance(value, BaseModel):
            state_dict[key] = value.model_dump()
        elif isinstance(value, pd.DataFrame):
            state_dict[key] = value.to_dict(orient="records")
        elif key == "file":
            encoded_content = base64.b64encode(value.getvalue()).decode(
                "utf-8",
            )
            state_dict[key] = {
                "file_name": value.name,
                "content_base64": encoded_content,
            }
        else:
            state_dict[key] = value

    state_dict["message_history"] = [
        message
        for message in session_state["llm_interface"].message_history
        if isinstance(message, dict)
    ]

    return state_dict


def load_chat(path: str) -> None:
    logger.info(f"Loading chat history from {path.name}...")
    load_dict = json.load(path)

    # if (
    #         "metadata" not in load_dict
    #         or load_dict["metadata"].get("save_version") != SAVE_VERSION
    # ):
    #     load_dict = remake_old_save(path, load_dict)

    for i in load_dict:
        if i == "valid_threats":
            st.session_state[i] = pd.DataFrame(load_dict[i])
        elif i == "report":
            st.session_state["report"] = Report.from_dict(load_dict[i])
        elif i == "validation_report":
            st.session_state["validation_report"] = ValidationReport.from_dict(
                load_dict[i],
            )
        elif i == "message_history":
            st.session_state.llm_interface.message_history = load_dict[i]
        elif i == "file":
            decoded_content = base64.b64decode(load_dict[i]["content_base64"])
            st.session_state["file"] = io.BytesIO(decoded_content)
            st.session_state["file"].name = load_dict[i]["file_name"]
        elif i == "manual_validation_report":
            st.session_state["manual_validation_report"] = (
                ManualValidationReport.model_construct(
                    **load_dict["manual_validation_report"],
                )
            )
        else:
            st.session_state[i] = load_dict[i]

    logger.info("Chat history loaded.")


def clean_chat_btn() -> None:
    if st.button(
        "Clear chat history",
        icon=":material/delete:",
        width="stretch",
    ):
        clear_session()
        st.rerun()


def save_chat_btn() -> None:
    file_name: str

    if "file" in st.session_state:
        file_name = Path(st.session_state["file"].name).stem
    else:
        file_name = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")

    st.download_button(
        label="Save chat history",
        icon=":material/save:",
        data=save_chat(),
        file_name=f"{file_name}.thremolia",
        width="stretch",
    )


def chat_save_load() -> None:
    st.divider()
    save_load_cols = st.columns(2, vertical_alignment="bottom")
    with save_load_cols[0]:
        clean_chat_btn()
    with save_load_cols[1]:
        save_chat_btn()


def clear_session(exceptions: list[str] | None = None) -> None:
    logger.info("Clearing chat history...")
    if exceptions is None:
        exceptions = []
    for i in st.session_state:
        if i in VALID_LIST and i not in exceptions:
            del st.session_state[i]

    st.session_state.chat_history = []
    st.session_state.llm_interface.message_history = []
    logger.info("Chat history cleared.")


def remake_old_save(path: str, load_dict: dict) -> dict:
    logger.info("Old save detected. Remaking save with new format...")

    for i in load_dict:  # noqa: PLC0206
        load_dict[i] = json.loads(load_dict[i])

    load_dict["metadata"] = {
        "save_name": path,
        "date": datetime.now().strftime("%d-%m-%Y %H-%M-%S"),
        "author": load_dict.get("name", "Unknown"),
        "save_version": SAVE_VERSION,
        "used_models": {
            "main_model": "Unknown",
            "img_to_text_model": "Unknown",
            "validation_model": "Unknown",
        },
    }

    with open(CHAT_HISTORY_PATH / path, "w", encoding="utf-8") as f:
        json.dump(load_dict, f, indent=4)

    logger.info("Old save updated successfully.")

    return load_dict
