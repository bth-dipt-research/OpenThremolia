from thremolia.report_validation import Mistake
from thremolia.streamlit_gui import streamlit_funcs

CORRECT_REPORT_COLUMN_LIST = [
    "id",
    "element",
    "threat_description",
    "element_type",
    "stride",
    "mitre_atlas",
    "owasp_top_10_for_llm",
    "linddun",
    "mitigation",
    "cvss_vector",
    "cvss_score",
    "threat_source",
    "validation",
    "justification",
    "mitigated",
]

CORRECT_MISTAKES_COLUMN_LIST = [
    "id",
    "description",
    "type",
    "valid",
]


def test_get_report_df_empty(report_factory):
    report = report_factory()
    dataframe = streamlit_funcs.get_report_df(report)
    assert list(dataframe) == CORRECT_REPORT_COLUMN_LIST


def test_get_report_df(report_factory):
    threats = [
        {"id": 1},
        {"id": 2},
        {"id": 3},
        {"id": 4},
        {"id": 5},
    ]
    report = report_factory(threats=threats)
    dataframe = streamlit_funcs.get_report_df(report)

    assert list(dataframe) == CORRECT_REPORT_COLUMN_LIST
    assert len(dataframe.index) == len(threats)


def test_get_mistakes_df_empty():
    dataframe = streamlit_funcs.get_mistakes_df()
    assert list(dataframe) == CORRECT_MISTAKES_COLUMN_LIST


def test_get_mistakes_df():
    mistakes = [
        Mistake(id=1, description="test", type="test"),
        Mistake(id=2, description="test", type="test"),
        Mistake(id=3, description="test", type="test"),
    ]
    dataframe = streamlit_funcs.get_mistakes_df(mistakes)
    assert list(dataframe) == CORRECT_MISTAKES_COLUMN_LIST
    assert len(dataframe.index) == len(mistakes)
