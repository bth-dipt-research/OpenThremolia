import streamlit as st

from thremolia.llm_interfaces import LLMInterface
from thremolia.llm_interfaces.llm_utils import (
    LLM_FRAMEWORKS,
    LLM_FRAMEWORKS_LOOKUP,
    REASONING,
    create_llm_client,
)
from thremolia.threat import THREAT_MODELS
from thremolia.utils import logger


def llm_selector() -> None:
    if st.session_state["app_settings"]["selected_llm"] is None:
        st.warning(
            "Warning! No LLM framework selected! Please select one before continuing.",
            icon="⚠️",
        )
        st.stop()

    st.session_state.llm_interface = switch_llm_interface(
        st.session_state["app_settings"]["selected_llm"],
    )

    if st.session_state.llm_interface is not None:
        api_state, error = st.session_state.llm_interface.check_api()
        if api_state is False:
            st.error(
                f"Selected API interface is inaccessible! Error: {error}",
                icon="🚨",
            )
            st.stop()

        init_default_embeddings()


def switch_llm_interface(selected_llm: str | None = None) -> LLMInterface | None:
    if not selected_llm:
        return None

    selected_llm = selected_llm.lower()

    if (
        "llm_interface" in st.session_state
        and selected_llm == st.session_state.llm_interface.get_llm_type().lower()
    ):
        return st.session_state.llm_interface

    return create_llm_client(selected_llm)


def init_default_embeddings() -> None:
    """Checks if default embeddings exist and if not - creates them."""
    if not st.session_state.llm_interface.embeddings_model:
        st.warning(
            """
            You do not seem to have an embedding model selected.
            Some functionality may not work as intended and have impact on the llm results!
            Please select the model from the **:material/settings: Settings** menu.
            """,
            icon="⚠️",
        )
        return
    if not st.session_state.llm_interface.check_collections():
        with st.spinner("Generating default embeddings...", show_time=True):
            logger.info("Generating default embeddings...")
            st.session_state.llm_interface.create_default_collections()
            logger.info("Default embeddings generated.")


@st.dialog("LLM Configuration", dismissible=True, on_dismiss="ignore", width="medium")
def llm_config(
    current_llm: str,
    current_reasoning: str,
    current_threat_models: list[str],
) -> None:
    st.session_state["app_settings"]["selected_llm"] = st.segmented_control(
        "LLM framework",
        LLM_FRAMEWORKS,
        selection_mode="single",
        default=current_llm,
        help="Select the LLM framework you want to use. Api key and host are set in the .env file.",
    )

    llm_selector()

    st.write("Select models for different tasks:")
    model_list = st.session_state.llm_interface.list_models()
    llm_type = st.session_state.llm_interface.get_llm_type()
    main_model = st.selectbox(
        "Main LLM model",
        model_list,
        index=get_model_index(model_list, st.session_state.llm_interface.model),
        help="Select the main LLM model for threat modeling tasks.",
    )
    img_to_text_model = st.selectbox(
        "Img-to-text model",
        model_list,
        index=get_model_index(
            model_list,
            st.session_state.llm_interface.img_to_text_model,
        ),
        help="Select the LLM model for image to text conversion. gpt-4o-mini is sufficient for most DFDs.",
    )
    validation_model = st.selectbox(
        "Validation model",
        model_list,
        index=get_model_index(
            model_list,
            st.session_state.llm_interface.validation_model,
        ),
        help="Select the LLM model used for report validation tasks.",
    )

    embeddings_model = None

    if llm_type not in ("ChatGPT", "AzureOpenAI"):
        embeddings_model = st.selectbox(
            "Embeddings model",
            model_list,
            index=get_model_index(
                model_list,
                st.session_state.llm_interface.embeddings_model,
            ),
            help="Select the LLM model used for generating embeddings.",
        )

    st.session_state["app_settings"]["reasoning"] = st.segmented_control(
        "LLM reasoning effort",
        REASONING,
        selection_mode="single",
        default=current_reasoning.title(),
        help="""Select the reasoning effort for the LLM. Heavily affects response time and cost.   
        If you don't know model reasoning capabilities, leave at 'Default'.   
        For ollama models that do not support different reasoning levels any level other than 'Default' will suffice.""",
    ).casefold()

    st.session_state["app_settings"]["selected_models"] = st.pills(
        "Threat Modeling Frameworks",
        THREAT_MODELS,
        selection_mode="multi",
        default=current_threat_models,
        help="Select the threat modeling frameworks you want to use in the report.",
    )

    if st.button("Submit", icon=":material/check:", width="stretch"):
        prev_embedding_model = st.session_state.llm_interface.embeddings_model
        st.session_state.llm_interface.set_models(
            main_model=main_model,
            img_to_text_model=img_to_text_model,
            validation_model=validation_model,
            embeddings_model=embeddings_model,
        )
        st.session_state.llm_interface.set_reasoning(
            st.session_state["app_settings"]["reasoning"],
        )
        if prev_embedding_model != embeddings_model:
            init_default_embeddings()
        st.rerun()


def llm_config_button() -> None:
    if st.button(
        ":material/settings:",
        type="secondary",
    ):
        selected_llm = st.session_state["app_settings"]["selected_llm"]
        selected_reasoning = st.session_state["app_settings"]["reasoning"]
        selected_threat_models = st.session_state["app_settings"]["selected_models"]
        llm_config(
            LLM_FRAMEWORKS_LOOKUP.get(selected_llm.casefold()),
            selected_reasoning,
            selected_threat_models,
        )


def get_model_index(model_list: list, model: str) -> int:
    if model in model_list:
        return model_list.index(model)
    return 0
