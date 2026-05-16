import json
from os import getenv

import pandas as pd
import streamlit as st

from thremolia.report_validation import Mistake
from thremolia.streamlit_gui.llm_config_dialog import llm_selector
from thremolia.streamlit_gui.save_load import clear_session, load_chat
from thremolia.threat import THREAT_MODELS, THREAT_MODELS_DATA, Report
from thremolia.utils import DATASETS_PATH, load_json

DEFAULT_SETTINGS = {
    "selected_models": json.loads(
        getenv("DEFAULT_THREAT_MODELS", json.dumps(THREAT_MODELS)),
    ),
    "selected_llm": getenv("DEFAULT_LLM_INTERFACE", "ChatGPT"),
    "reasoning": getenv("DEFAULT_REASONING_EFFORT", "default"),
}


def init() -> None:
    """
    Initializes the Streamlit session state with default values.
    """
    if "app_settings" not in st.session_state:
        st.session_state["app_settings"] = DEFAULT_SETTINGS
    if "file_uploader_key" not in st.session_state:
        st.session_state["file_uploader_key"] = 0
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []
    if "custom_metrics" not in st.session_state:
        st.session_state["custom_metrics"] = load_json(
            DATASETS_PATH / "custom_metrics.json",
        )
    if "valid_threats" not in st.session_state:
        st.session_state["valid_threats"] = get_report_df(None)
    if "tm_requirements" not in st.session_state:
        st.session_state["tm_requirements"] = ""
    if "tm_requirements_files" not in st.session_state:
        st.session_state["tm_requirements_files"] = ""
    if "llm_interface" not in st.session_state:
        llm_selector()


def sidebar_fix() -> None:
    """
    Moves chat to the bottom of the window and adds background to hide overlapping text
    Currently unused, awaits streamlit theme detection functionality
    # https://github.com/streamlit/streamlit/issues/5009
    """
    if st.context.theme.type == "light":
        st.markdown(
            """
            <style>
            [data-testid="stSidebar"] [data-testid="stElementContainer"]:has(> [data-testid="stChatInput"]) {
            position: sticky;
            bottom: 0;
            z-index: 2;
            background-color: rgb(240, 242, 246);
            padding-bottom: 2rem;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )
    elif st.context.theme.type == "dark":
        st.markdown(
            """
            <style>
            [data-testid="stSidebar"] [data-testid="stElementContainer"]:has(> [data-testid="stChatInput"]) {
            position: sticky;
            bottom: 0;
            z-index: 2;
            background-color: rgb(38, 39, 48);
            padding-bottom: 2rem;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )


def format_matrix(matrix: dict | list[dict]) -> pd.DataFrame:
    if isinstance(matrix, dict):
        return pd.DataFrame.from_dict(matrix, orient="index")
    return pd.DataFrame.from_records(matrix)


def get_report_df(report: Report | None) -> pd.DataFrame:
    if report and report.threats:
        dataframe = pd.DataFrame.from_records(
            [threat.model_dump() for threat in report.threats],
        )
    else:
        dataframe = pd.DataFrame(
            columns=get_column_list(),
        )

    # return dataframe.style.map(style_df, subset=["source"])
    return dataframe


def get_mistakes_df(mistakes_list: list[Mistake] | None = None) -> pd.DataFrame:
    if mistakes_list:
        return pd.DataFrame.from_records(
            [mistake.model_dump() for mistake in mistakes_list],
        )
    return pd.DataFrame(
        columns=["id", "description", "type", "valid"],
    )


def file_uploader() -> None:
    uploaded_file = st.file_uploader(
        "Upload Data Flow Diagram",
        type=["png", "jpg", "jpeg", "thremolia", "tf", "json", "bicep"],
        accept_multiple_files=False,
        key=st.session_state["file_uploader_key"],
        help="Upload your DFD or deployment file to be described by the LLM.",
    )

    if uploaded_file and (
        "file" not in st.session_state or uploaded_file != st.session_state["file"]
    ):
        st.session_state["file"] = uploaded_file
        clear_session(exceptions=["file", "tm_requirements", "tm_requirements_files"])

        with st.spinner("Analyzing your file...", show_time=True):
            if uploaded_file.name.endswith(".thremolia"):
                clear_session()
                llm_selector()
                load_chat(uploaded_file)
            elif uploaded_file.name.endswith((".tf", ".json", ".bicep")):
                deployment_content = uploaded_file.read().decode("utf-8")
                st.session_state["text"] = (
                    st.session_state.llm_interface.describe_deployment(
                        deployment_content,
                    )
                )
            else:
                with st.container(horizontal=True, horizontal_alignment="center"):
                    st.image(st.session_state["file"], caption="Uploaded DFD")
                st.session_state["text"] = (
                    st.session_state.llm_interface.describe_image(uploaded_file)
                )
        st.session_state["file_uploader_key"] += 1
        st.rerun()

    elif (
        not uploaded_file
        and "file" in st.session_state
        and not st.session_state["file"].name.endswith((".json", ".tf"))
    ):
        with st.container(horizontal=True, horizontal_alignment="center"):
            st.image(st.session_state["file"], caption="Uploaded DFD")

    elif "text" not in st.session_state:
        st.session_state["text"] = ""


def style_df(val: str) -> str:
    if val == "llm":
        return "background-color: lightgreen"
    if val == "manual":
        return "background-color: lightyellow"
    return ""


def get_column_list() -> list:
    return [
        "id",
        "element",
        "threat_description",
        "element_type",
        "stride",
        *[tm.threat_field for tm in THREAT_MODELS_DATA],
        "mitigation",
        "SDL_stage",
        "cvss_vector",
        "cvss_score",
        "threat_source",
        "validation",
        "justification",
        "mitigated",
    ]


def get_column_config() -> dict:
    # we use two dicts to retain correct order of columns in the ui
    config_start = {
        "id": "Id",
        "element": "Element/Dataflow",
        "threat_description": "Threat Description",
        "element_type": "Element Type",
        "stride": "STRIDE",
    }

    for tm in THREAT_MODELS_DATA:
        config_start[tm.threat_field] = tm.name

    config_end = {
        "mitigation": "Mitigation",
        "SDL_stage": "SDL Stage",
        "cvss_vector": "CVSS Vector",
        "cvss_score": "CVSS Score",
        "threat_source": st.column_config.TextColumn(
            "Threat Source",
            default="manual",
        ),
        "validation": st.column_config.CheckboxColumn(
            "Validation",
            default=False,
        ),
        "justification": "Justification",
        "mitigated": st.column_config.CheckboxColumn(
            "Mitigated",
            default=False,
        ),
    }

    return {**config_start, **config_end}


def get_extension_options_list() -> list:
    return [
        "STRIDE coverage",
        *[f"{tm.name} coverage" for tm in THREAT_MODELS_DATA],
        "Fix Mistakes",
    ]
