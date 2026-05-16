import json

import pandas as pd
import streamlit as st
from streamlit.delta_generator import DeltaGenerator

from thremolia.report_validation import ManualValidationReport, ValidationReport
from thremolia.threat import Message, Report
from thremolia.utils import logger

# TODO: maybe try to minimize usage of session state wherever possible and pass required data as arguments.


def run_modeling(text_dfd: str | None) -> None:
    """
    Generates basic report based on the provided description and selected models.

    Args:
        text_dfd (str | None): System description in natural language.

    """
    if not text_dfd:
        return

    with st.spinner("Generating report...", show_time=True):
        logger.info("Generating report...")

        report = st.session_state.llm_interface.generate_report(
            text_dfd,
            st.session_state["app_settings"]["selected_models"],
            st.session_state["tm_requirements"],
        )
        logger.info("Generation completed.")

    display_report(report)
    validate_report(report, text_dfd)


def run_manual_validation() -> None:
    """
    Validates the report based on the individual threats validation.
    """
    if "validation_report" not in st.session_state:
        return

    with st.spinner("Validating report...", show_time=True):
        logger.info("Running manual report validation...")
        if "manual_validation_report" not in st.session_state:
            st.session_state["manual_validation_report"] = ManualValidationReport(
                st.session_state["valid_threats"],
                st.session_state["validation_report"].non_generated_threats,
            )
        else:
            st.session_state["manual_validation_report"].update(
                st.session_state["valid_threats"],
                st.session_state["validation_report"].non_generated_threats,
            )
        logger.info("Manual validation completed.")


def extend_report(
    text_dfd: str | None,
    options: list[str],
) -> None:
    """
    Extends the report using the provided list of missing threads and fixing mistakes found previously.

    Args:
        text_dfd (str | None): System description in natural language.
        options (list[str]): List of selected extension options. Supported options are: "STRIDE coverage", "<TM_name> coverage", "Fix Mistakes".

    """
    # we remove manual_validation_report for correct calculations of non-generated threats
    if "manual_validation_report" in st.session_state:
        del st.session_state["manual_validation_report"]

    if "report" not in st.session_state:
        return

    with st.spinner("Extending report...", show_time=True):
        logger.info(f"Extending report with selected options: {options}")
        report: Report = st.session_state.llm_interface.extend_report(
            st.session_state["report"],
            st.session_state["app_settings"]["selected_models"],
            st.session_state["validation_report"].get_missing_threats(options),
        )
        if "Fix Mistakes" in options:
            prev_message = report.message
            report = st.session_state.llm_interface.fix_report(
                report,
                st.session_state["app_settings"]["selected_models"],
                st.session_state["valid_mistakes"],
            )
            report.message = prev_message + "\n\n" + report.message
        logger.info("Extension completed.")

    display_report(report)
    validate_report(report, text_dfd)
    st.rerun()


def display_report(report: Report) -> None:
    """
    Adds the report to the session state and updates the chat history.
    Also creates a DataFrame of the threats in the report.

    Args:
        report (Report): The report object containing the generated report.

    """
    st.session_state["report"] = report
    st.session_state.chat_history.append(
        {"role": "assistant", "content": report.message},
    )
    update_valid_threats(report)


def validate_report(report: Report, text_dfd: str | None) -> None:
    """
    Validates the report using the ValidationReport class and stores the validation report in the session state.

    Args:
        report (Report): The report object containing the generated report.
        text_dfd (str | None): System description in natural language.

    """
    logger.info("Validating report...")

    with st.spinner("Validating report...", show_time=True):
        validation_report = ValidationReport(
            report,
            text_dfd,
            st.session_state.llm_interface,
            custom_metrics=st.session_state.custom_metrics,
        )
        st.session_state.chat_history.append(
            {
                "role": "validation",
                "content": validation_report.justification,
                "score": validation_report.llm_score,
            },
        )
        st.session_state["validation_report"] = validation_report
        run_manual_validation()
    logger.info("Validation completed.")


# TODO: questionable method that doesn't do anything most of the times
def update_valid_threats(report: Report) -> None:
    """Updates valid_threats in session state with new threats."""
    if report.threats and (
        "valid_threats" not in st.session_state
        or st.session_state["valid_threats"].empty
    ):
        st.session_state["valid_threats"] = pd.DataFrame(
            [threat.model_dump() for threat in report.threats],
        )


def chat_handler(prompt: str, text_dfd: str, container: DeltaGenerator) -> str:
    st.session_state.chat_history.append({"role": "user", "content": prompt})
    with container, st.spinner("Thinking...", show_time=True):
        response, report_changed, tool_messages = (
            st.session_state.llm_interface.chat_with_tools(prompt)
        )
    st.session_state.chat_history.extend(tool_messages)

    if not report_changed and '"message":' not in response:
        st.session_state.chat_history.append(
            {"role": "assistant", "content": response},
        )
        return response

    if report_changed:
        logger.info("LLM used tool calls.")
        report: Report = st.session_state.get("report")

        if "manual_validation_report" in st.session_state:
            del st.session_state["manual_validation_report"]

        # TODO: questionable method that doesn't do anything most of the times
        update_valid_threats(report)
        with container:
            validate_report(report, text_dfd)

    # if report in the response
    if '"message":' in response and '"threats":' in response:
        logger.info("LLM respond with new report")
        report = Report.from_dict(json.loads(response))
        previous_report: Report = st.session_state.get("report")

        if report.threats[0].id == previous_report.threats[0].id:
            st.session_state["report"] = report
        else:
            st.session_state["report"].add_part(report)

        response = report.message

        if "manual_validation_report" in st.session_state:
            del st.session_state["manual_validation_report"]

        # TODO: questionable method that doesn't do anything most of the times
        update_valid_threats(report)
        with container:
            validate_report(report, text_dfd)
    elif '"message":' in response:
        logger.info("LLM respond with json")
        message: Message = Message.model_validate_json(response)
        response = message.message

    st.session_state.chat_history.append(
        {"role": "assistant", "content": response},
    )

    return response
