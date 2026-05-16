from typing import TYPE_CHECKING

import streamlit as st

from thremolia.streamlit_gui.report_generation import extend_report
from thremolia.streamlit_gui.streamlit_funcs import (
    format_matrix,
    get_mistakes_df,
)
from thremolia.threat import THREAT_MODELS_DATA

if TYPE_CHECKING:
    from thremolia.report_validation import ManualValidationReport, ValidationReport


def health_metrics() -> None:
    val_report: ValidationReport = st.session_state["validation_report"]

    st.subheader("Basic metrics", divider=True)
    st.metric(
        "LLM Score",
        f"{val_report.llm_score}%",
        help="Report accuracy according to LLM.",
        border=True,
    )
    st.metric(
        "Health Score",
        f"{val_report.health_score}%",
        help="Report accuracy based on the overall"
        " amount of mistakes and threats generated.",
        border=True,
    )
    st.metric(
        "Mistakes",
        val_report.mistakes,
        help="Overall amount of mistakes in the report.",
        border=True,
        height=125,
    )


def risk_metrics() -> None:
    val_report: ValidationReport = st.session_state["validation_report"]
    manual_val_report: ManualValidationReport = st.session_state[
        "manual_validation_report"
    ]

    st.subheader("Risk metrics", divider=True)
    st.metric(
        "Aggregated CVSS",
        val_report.aggregated_cvss,
        help="Aggregated CVSS score of all threats.",
        border=True,
    )
    st.metric(
        "Mitigated threats percentage",
        f"{manual_val_report.mitigated_threats_percentage}%",
        help="Percentage of mitigated threats.",
        border=True,
    )
    st.metric(
        "Aggregated residual CVSS",
        manual_val_report.aggregated_residual_cvss,
        delta=round(
            manual_val_report.aggregated_residual_cvss - val_report.aggregated_cvss,
            2,
        ),
        delta_color="inverse",
        help="Aggregated residual CVSS score of non-mitigated threats.",
        border=True,
        height=125,
    )


def accuracy_metrics() -> None:
    manual_val_report: ManualValidationReport = st.session_state[
        "manual_validation_report"
    ]

    st.subheader("Accuracy metrics", divider=True)

    accuracy_cols = st.columns(3, vertical_alignment="center")
    with accuracy_cols[0]:
        st.metric(
            "Valid threats percentage",
            f"{manual_val_report.valid_threats_percentage}%",
            help="Percentage of valid threats.",
            border=True,
        )
        st.metric(
            "Valid threats",
            manual_val_report.valid_threats,
            help="Amount of valid threats. True Positive.",
            border=True,
        )
        st.metric(
            "Invalid threats",
            manual_val_report.invalid_threats,
            help="Amount of invalid threats. False Positive.",
            border=True,
            height=125,
        )

    with accuracy_cols[1]:
        st.metric(
            "Accuracy",
            f"{manual_val_report.accuracy}%",
            help="Binary accuracy of the report.",
            border=True,
        )
        st.metric(
            "Manually added threats",
            manual_val_report.manual_threats,
            help="Amount of manually added threats. True Negative.",
            border=True,
        )
        st.metric(
            "Non-generated threats",
            manual_val_report.non_generated_threats,
            help="Amount of non-generated threats. False Negative.",
            border=True,
            height=125,
        )
    with accuracy_cols[2]:
        st.metric(
            "Precision",
            f"{manual_val_report.precision}%",
            help="Binary precision of the report.",
            border=True,
        )
        st.metric(
            "Recall",
            f"{manual_val_report.recall}%",
            help="Binary recall of the report.",
            border=True,
        )
        st.metric(
            "F1 Score",
            f"{manual_val_report.f1_score}%",
            help="Binary F1 score of the report.",
            border=True,
            height=125,
        )


def coverage_metrics() -> None:
    val_report: ValidationReport = st.session_state["validation_report"]

    st.subheader("Coverage", divider=True)
    st.metric(
        "STRIDE coverage:",
        val_report.stride_coverage,
        help="Relation of generated to maximum possible threats according to STRIDE-per-element.",
        border=True,
    )
    st.metric(
        "STRIDE coverage percent:",
        f"{val_report.stride_percentage}%",
        help="Percentage threats in the report in relation to maximum possible amount of threats according to STRIDE-per-element.",
        border=True,
    )
    st.metric(
        "OWASP coverage percent:",
        f"{val_report.owasp_top_10_for_llm_percentage}%",
        help="Percentage of OWASP TOP 10 for LLM threats that are present in the report.",
        border=True,
        height=125,
    )


def display_coverage(name: str, percentage: int, matrix: dict) -> None:
    st.subheader(name)
    st.metric("Coverage percent:", f"{percentage}%")
    st.dataframe(matrix, width="stretch")


def coverage_report(text_dfd: str) -> None:
    val_report: ValidationReport = st.session_state["validation_report"]

    st.subheader("Coverage metrics", divider=True)
    with st.container(border=True):
        st.subheader("STRIDE coverage")
        stride = st.columns(3, vertical_alignment="center")
        stride[0].metric(
            "Coverage:",
            val_report.stride_coverage,
        )
        stride[1].metric(
            "Coverage percent:",
            f"{val_report.stride_percentage}%",
        )
        if stride[2].button(
            "Extend STRIDE coverage",
            width="stretch",
            type="primary",
            icon=":material/docs_add_on:",
            help="Ask LLM to extend the report with missing threats from STRIDE coverage matrix.",
        ):
            extend_report(text_dfd, ["STRIDE coverage"])
        st.dataframe(
            format_matrix(val_report.stride_matrix),
            width="stretch",
        )

    tm_count = len(THREAT_MODELS_DATA)
    chunk_size = tm_count // 3  # Integer division
    tm_part1 = THREAT_MODELS_DATA[:chunk_size]
    tm_part2 = THREAT_MODELS_DATA[chunk_size : 2 * chunk_size]
    tm_part3 = THREAT_MODELS_DATA[2 * chunk_size : tm_count]
    cols = st.columns(3, border=True)
    with cols[0]:
        for tm in tm_part1:
            display_coverage(
                tm.name,
                getattr(val_report, f"{tm.threat_field}_percentage"),
                getattr(val_report, f"{tm.threat_field}_matrix"),
            )
    with cols[1]:
        for tm in tm_part2:
            display_coverage(
                tm.name,
                getattr(val_report, f"{tm.threat_field}_percentage"),
                getattr(val_report, f"{tm.threat_field}_matrix"),
            )
    with cols[2]:
        for tm in tm_part3:
            display_coverage(
                tm.name,
                getattr(val_report, f"{tm.threat_field}_percentage"),
                getattr(val_report, f"{tm.threat_field}_matrix"),
            )


def mistakes_tab(text_dfd: str) -> None:
    val_report: ValidationReport = st.session_state["validation_report"]

    st.subheader("Mistakes found", divider=True)
    st.session_state["valid_mistakes"] = st.data_editor(
        get_mistakes_df(
            val_report.mistakes_list,
        ),
        width="stretch",
        hide_index=True,
        column_config={
            "id": st.column_config.Column(
                "Threat Id",
                width="small",
                help="Id of the threat where the mistake was found.",
            ),
            "type": st.column_config.TextColumn(
                "Type",
                width="small",
                help="Type of the mistake. Supported types: 'Categorization', 'CVSS', 'Embedding', 'General', 'Custom'.",
                default="Custom",
            ),
            "description": st.column_config.Column(
                "Description",
                width="large",
                help="Description of the mistake.",
            ),
            "valid": st.column_config.CheckboxColumn(
                "Valid",
                width="small",
                help="Checkbox to mark the mistake as valid.",
                default=False,
            ),
        },
        num_rows="dynamic",
    )
    if st.button(
        "Fix mistakes ",
        width="stretch",
        type="primary",
        icon=":material/build:",
        help="Ask LLM to fix the mistakes displayed in the mistakes list.",
    ):
        extend_report(text_dfd, ["Fix Mistakes"])


def custom_metrics() -> None:
    st.subheader("Custom metrics", divider=True)

    options = st.multiselect(
        "Selected custom metrics",
        [metric["title"] for metric in st.session_state["custom_metrics"]],
    )

    for metric in st.session_state["custom_metrics"]:
        if metric["title"] in options:
            metric["selected"] = True
        else:
            metric["selected"] = False

    template_col, title_col, condition_col, enter_col = st.columns(
        [1, 1, 2, 1],
        vertical_alignment="bottom",
    )

    with template_col:
        template = st.selectbox(
            "Template",
            ["New"]  # Empty
            + [metric["title"] for metric in st.session_state["custom_metrics"]],
            index=0,
        )

    health_title_value = ""
    health_condition_value = ""

    if template != "New":  # Empty
        for metric in st.session_state["custom_metrics"]:
            if metric["title"] == template:
                health_title_value = metric["title"]
                health_condition_value = metric["condition"]
                break

    with title_col:
        health_title = st.text_input(
            "Metric title",
            value=health_title_value,
            placeholder="Metric title",
        )

    with condition_col:
        health_condition = st.text_input(
            "Metric condition",
            value=health_condition_value,
            placeholder="Metric condition",
        )

    with enter_col:
        if (
            st.button(
                "Add Metric",
                width="stretch",
                type="primary",
                icon=":material/add:",
            )
            and health_title
            and health_condition
        ):
            st.session_state["custom_metrics"].append(
                {
                    "title": health_title,
                    "condition": health_condition,
                    "selected": True,
                },
            )
            st.rerun()

    if (
        "validation_report" in st.session_state
        and st.session_state["validation_report"].custom_metrics
    ):
        st.dataframe(
            format_matrix(st.session_state["validation_report"].custom_metrics),
            width="stretch",
        )


def metrics(text_dfd: str) -> None:
    if "report" in st.session_state:
        st.header("Report Health Metrics", divider=True)
        metric_tabs = st.tabs(
            [
                ":material/bar_chart: Validation",
                ":material/warning: Mistakes",
                ":material/data_usage: Coverage",
                ":material/add_chart: Custom metrics",
            ],
        )
        with metric_tabs[0]:
            validation_cols = st.columns([1, 1, 3, 1], vertical_alignment="top")
            with validation_cols[0]:
                health_metrics()
            with validation_cols[1]:
                risk_metrics()
            with validation_cols[2]:
                accuracy_metrics()
            with validation_cols[3]:
                coverage_metrics()
        with metric_tabs[1]:
            mistakes_tab(text_dfd)
        with metric_tabs[2]:
            coverage_report(text_dfd)
        with metric_tabs[3]:
            custom_metrics()
    else:
        custom_metrics()
