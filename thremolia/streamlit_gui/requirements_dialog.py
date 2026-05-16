import streamlit as st

from thremolia.summarizer import summarize_pdf, summarize_text


def requirements_uploader() -> None:
    uploaded_files = st.file_uploader(
        "Upload project description",
        type=["txt", "json", "pdf"],
        accept_multiple_files=True,
        help="Upload file with additional project description. It will be summarized and used during threat modeling.",
    )

    requirements_analyzer(uploaded_files)

    tm_requirements = st.text_area(
        "Extracted project security information",
        key="tm_requirements",
        height=500,
        help="Note, that texts shorter than 5000 symbols won't be summarized.",
    )

    if tm_requirements and tm_requirements != st.session_state["tm_requirements"]:
        st.session_state["tm_requirements"] = tm_requirements


def requirements_analyzer(uploaded_files: list) -> None:
    if not uploaded_files:
        st.session_state["tm_requirements_files"] = []
        return

    with st.spinner("Summarizing your files...", show_time=True):
        for uploaded_file in uploaded_files:
            if not any(
                req_file["name"] == uploaded_file.name
                for req_file in st.session_state["tm_requirements_files"]
            ):
                if uploaded_file.name.endswith((".txt", ".json")):
                    content = uploaded_file.read().decode("utf-8")
                    requirements = summarize_text(
                        content,
                        st.session_state.llm_interface,
                    )
                else:
                    requirements = summarize_pdf(
                        uploaded_file,
                        st.session_state.llm_interface,
                    )

                st.session_state["tm_requirements_files"].append(
                    {
                        "name": uploaded_file.name,
                        "content": requirements,
                    },
                )

    st.session_state["tm_requirements_files"] = requirements_deleter(
        st.session_state["tm_requirements_files"],
        uploaded_files,
    )

    st.session_state["tm_requirements"] = construct_requirements(
        st.session_state["tm_requirements_files"],
    )


def requirements_deleter(tm_requirements_files: list, uploaded_files: list) -> list:
    """Checks if previously uploaded file not in currently uploaded ones and removes it."""
    for file in tm_requirements_files[:]:
        if not any(
            uploaded_file.name == file["name"] for uploaded_file in uploaded_files
        ):
            tm_requirements_files.remove(file)
    return tm_requirements_files


def construct_requirements(requirements: list[dict]) -> str:
    output = "Additional project description:"
    for requirement in requirements:
        output += f"\n\n{requirement['name']} file content:\n\n{requirement['content']}"
    return output


def requirements_uploader_button() -> None:
    if st.button(
        "Upload additional project description.",
        width="stretch",
        icon=":material/upload_file:",
        type="secondary",
        help="Upload file with extra security requirements. It will be summarized and used during threat modeling.",
    ):
        requirements_uploader()
