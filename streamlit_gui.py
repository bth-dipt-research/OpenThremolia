import streamlit as st

from thremolia.streamlit_gui.llm_config_dialog import llm_config_button
from thremolia.streamlit_gui.metrics import metrics
from thremolia.streamlit_gui.report_generation import (
    chat_handler,
    extend_report,
    run_manual_validation,
    run_modeling,
)
from thremolia.streamlit_gui.requirements_dialog import requirements_uploader
from thremolia.streamlit_gui.save_load import chat_save_load
from thremolia.streamlit_gui.streamlit_funcs import (
    file_uploader,
    get_column_config,
    get_column_list,
    get_extension_options_list,
    get_report_df,
    init,
    sidebar_fix,
)

st.set_page_config(
    page_title="ThreMoLIA Modeling",
    layout="wide",
    page_icon=":material/graph_5:",
)

sidebar_fix()

header = st.columns([5, 1], vertical_alignment="center")
header[0].title(":material/graph_5: ThreMoLIA Modeling")

with header[1], st.container(horizontal=True, horizontal_alignment="right"):
    llm_config_button()


init()

if st.session_state.llm_interface.model is None:
    st.warning(
        """
        **Warning!** You do not have your LLM models selected!
        Please choose one from the **:material/settings: Settings** menu in the
        top right corner, or set default ones in the **.env** file and restart the app.
        """,
        icon="⚠️",
    )
with st.expander(
    "Upload project description",
    icon=":material/upload_file:",
):
    requirements_uploader()

file_uploader()

text_dfd = st.text_area(
    "Text description of Data Flow Diagram",
    key="text",
    height=350,
)

if text_dfd and text_dfd != st.session_state["text"]:
    st.session_state["text"] = text_dfd


button_style = "secondary" if "report" in st.session_state else "primary"

if st.button(
    "Run modeling",
    width="stretch",
    icon=":material/play_circle:",
    type=button_style,
):
    run_modeling(text_dfd)

if "report" in st.session_state and len(st.session_state["report"].threats) > 0:
    st.header("Threat Modeling Report", divider=True)

    st.session_state["valid_threats"] = st.data_editor(
        get_report_df(st.session_state.get("report")),
        width="stretch",
        hide_index=True,
        column_order=get_column_list(),
        column_config=get_column_config(),
        num_rows="dynamic",
        disabled=["source"],
    )

    run_manual_validation()

    if "report" in st.session_state and st.session_state["report"].threats:
        extension_options = st.pills(
            "Extension options",
            get_extension_options_list(),
            selection_mode="multi",
            help="""Choose the extension options you want to apply to the report:  
            - Coverage options: extend the report with missing threats from the selected coverage matrix.  
            - Fix Mistakes: ask LLM to fix the mistakes displayed in the mistakes list.  
            See respective tabs below for detailed info.""",  # noqa: W291 Double spaces are used for newlines in markdown
        )
        if st.button(
            "Extend report",
            width="stretch",
            icon=":material/docs_add_on:",
            type="primary",
            help="Ask LLM to extend the report with missing threats from STRIDE coverage matrix.",
        ):
            extend_report(text_dfd, extension_options)

metrics(text_dfd)

chat_save_load()

with st.sidebar:
    st.subheader("Chat with AI")
    messages_container = st.container(key="msg_container")
    for msg in st.session_state.chat_history:
        if msg["role"] in ("user", "assistant") and msg.get("content"):
            messages_container.chat_message(msg["role"]).write(msg["content"])
        elif msg["role"] == "assistant":
            with messages_container.expander(
                f"Tool calls: {len(msg['tool_calls'])}",
                icon=":material/handyman:",
            ):
                for index, tool_call in enumerate(msg["tool_calls"]):
                    st.markdown(f"**Tool used**: {tool_call['function']['name']}")
                    st.markdown(
                        f"**Arguments**: :small[{tool_call['function']['arguments']}]",
                    )
                    if tool_call["result"].startswith("Success."):
                        st.success(
                            tool_call["result"],
                            icon=":material/done_outline:",
                        )
                    elif tool_call["result"].startswith("Error."):
                        st.warning(
                            tool_call["result"],
                            icon=":material/warning:",
                        )
                    if index < len(msg["tool_calls"]) - 1:
                        st.divider()
        elif msg["role"] == "validation":
            with messages_container.expander(
                f"Validation score: {msg.get('score')}",
                icon=":material/data_check:",
            ):
                st.markdown(msg["content"])

    if chat_input := st.chat_input("Enter message..."):
        messages_container.chat_message("user").write(chat_input)
        response = chat_handler(chat_input, text_dfd, messages_container)
        st.rerun()  # required for automatic spreadsheet update on LLM tool calls
