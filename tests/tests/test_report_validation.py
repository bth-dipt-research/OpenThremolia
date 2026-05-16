import pandas as pd
import pytest

from thremolia.report_validation import (
    CVSS_WEIGHTS,
    ManualValidationReport,
    ValidationReport,
)
from thremolia.threat import Report, Threat


@pytest.mark.parametrize(
    ("stride"),
    [
        "spoofing",
        "tampering",
        "rePudiation",
        "information disclosure",
        "Denial Of Service",
        "elevation of privilege",
        None,
    ],
)
def test_validate_threat_stride(threat_factory, stride):
    threat = threat_factory(stride=stride)

    validation_report = ValidationReport.model_construct()
    validation_report._validate_threat_stride(threat)

    assert validation_report.mistakes == 0


@pytest.mark.parametrize(
    ("stride"),
    [
        "s",
        "P",
        "cat",
        "Denials of Servers",
        "",
    ],
)
def test_validate_threat_stride_invalid(threat_factory, stride):
    validation_report = ValidationReport.model_construct()
    validation_report._validate_threat_stride(threat_factory(stride=stride))

    assert validation_report.mistakes == 1


@pytest.mark.parametrize(
    ("owasp"),
    [
        "LLM01",
        "2025 Prompt Injection",
        "LLM10: 2025 Unbounded Consumption",
        None,
    ],
)
def test_validate_threat_owasp(threat_factory, owasp):
    # the test would work the same for ATLAS, LINDDUN and any other threat modeling framework with a list of threats
    validation_report = ValidationReport.model_construct()
    validation_report._validate_threat_model_fields(
        threat_factory(owasp_top_10_for_llm=owasp),
    )

    assert validation_report.mistakes == 0


@pytest.mark.parametrize(
    ("owasp"),
    [
        "LLM0001",
        "LLM11",
        "cat",
        "Denials of Servers",
        "",
    ],
)
def test_validate_threat_owasp_invalid(threat_factory, owasp):
    # the test would work the same for ATLAS, LINDDUN and any other threat modeling framework with a list of threats
    validation_report = ValidationReport.model_construct()
    validation_report._validate_threat_model_fields(
        threat_factory(owasp_top_10_for_llm=owasp)
    )

    assert validation_report.mistakes == 1


@pytest.mark.parametrize(
    ("atlas"),
    [
        "AML.T0042",
        "Verify Attack",
        "AML.T0042: Verify Attack",
        None,
    ],
)
def test_validate_threat_atlas(threat_factory, atlas):
    # the test would work the same for ATLAS, LINDDUN and any other threat modeling framework with a list of threats
    validation_report = ValidationReport.model_construct()
    validation_report._validate_threat_model_fields(threat_factory(mitre_atlas=atlas))

    assert validation_report.mistakes == 0


@pytest.mark.parametrize(
    ("atlas"),
    [
        "AML.T1234",
        "cat",
        "Do not verify Attack",
        "",
    ],
)
def test_validate_threat_atlas_invalid(threat_factory, atlas):
    # the test would work the same for ATLAS, LINDDUN and any other threat modeling framework with a list of threats
    validation_report = ValidationReport.model_construct()
    validation_report._validate_threat_model_fields(threat_factory(mitre_atlas=atlas))

    assert validation_report.mistakes == 1


def test_validate_threat_uncategorized(threat_factory):
    validation_report = ValidationReport.model_construct()
    validation_report._validate_threat_uncategorized(threat_factory())

    assert validation_report.mistakes == 1


@pytest.mark.parametrize(("cvss_score"), [0, 0.1, 1, 3.6, 9.9, 10])
def test_validate_threat_cvss(threat_factory, cvss_score):
    validation_report = ValidationReport.model_construct()
    validation_report._validate_threat_cvss(threat_factory(cvss_score=cvss_score))

    assert validation_report.mistakes == 0


@pytest.mark.parametrize(("cvss_score"), [-1, None, 12, 10.1, -0.1])
def test_validate_threat_cvss_invalid(threat_factory, cvss_score):
    validation_report = ValidationReport.model_construct()
    validation_report._validate_threat_cvss(threat_factory(cvss_score=cvss_score))

    assert validation_report.mistakes == 1


def report_stride(defaults: list[tuple[str, str, str]]) -> Report:
    threats = [
        Threat.model_construct(
            id=0,
            element=element,
            element_type=element_type,
            stride=stride,
        )
        for element, element_type, stride in defaults
    ]

    return Report(message="", threats=threats, is_final=True)


def test_stride_matrix():
    test_data = [
        ("Website", "Process", "Spoofing"),
        ("Website", "Process", "Denial of Service"),
        ("HTTP", "Data Flow", "Denial of Service"),
        ("User", "External Entity", "Repudiation"),
        ("Dataflow", "Data Flow", ""),
        ("Dataflow", "Data Flow", None),
    ]

    correct_stride_matrix = {
        "Website [Process]": {
            "S": True,
            "T": False,
            "R": False,
            "I": False,
            "D": True,
            "E": False,
        },
        "HTTP [Data Flow]": {
            "S": None,
            "T": False,
            "R": None,
            "I": False,
            "D": True,
            "E": None,
        },
        "User [External Entity]": {
            "S": False,
            "T": None,
            "R": True,
            "I": None,
            "D": None,
            "E": None,
        },
        "Dataflow [Data Flow]": {
            "S": None,
            "T": False,
            "R": None,
            "I": False,
            "D": False,
            "E": None,
        },
    }

    validation_report = ValidationReport.model_construct()
    validation_report._stride_matrix(report_stride(test_data))

    assert validation_report.stride_matrix == correct_stride_matrix


def test_stride_matrix_mistakes():
    test_data = [
        ("USB port", "Hardware", "Misconfiguration"),
        ("Database", "Data Store", "Spoofing"),
        ("Database", "Data Store", "Elevation of privilege"),
        ("HTTP", "Data Flow", "Repudiation"),
        ("User", "External Entity", "Tampering"),
    ]

    validation_report = ValidationReport.model_construct()
    validation_report._stride_matrix(report_stride(test_data))

    assert validation_report.mistakes == len(test_data)


def test_stride_coverage_full():
    test_data = [
        ("Website", "Process", "spoofing"),
        ("Website", "Process", "tampering"),
        ("Website", "Process", "repudiation"),
        ("Website", "Process", "information disclosure"),
        ("Website", "Process", "denial of service"),
        ("Website", "Process", "elevation of privilege"),
        ("User", "External Entity", "spoofing"),
        ("User", "External Entity", "repudiation"),
    ]

    max_threats = len(test_data)

    validation_report = ValidationReport.model_construct()
    validation_report._stride_matrix(report_stride(test_data))
    validation_report._stride_coverage()

    assert validation_report.stride_max_threats == max_threats
    assert validation_report.stride_coverage == f"{max_threats}/{max_threats}"
    assert validation_report.stride_percentage == 100  # noqa: PLR2004
    assert validation_report.non_generated_threats == 0
    assert validation_report.missing_threats == []


def test_stride_coverage_partial():
    test_data = [
        ("Website", "Process", "spoofing"),
        ("Website", "Process", "tampering"),
        ("Website", "Process", "elevation of privilege"),
        ("User", "External Entity", "spoofing"),
        ("Dataflow", "Data Flow", ""),
        ("Dataflow", "Data Flow", None),
    ]

    max_threats = 11  # 6 for Process + 2 for EE + 3 for DF
    covered_threats = 4
    correct_percentage = int(covered_threats / max_threats * 100)
    correct_non_generated_threats = max_threats - covered_threats
    correct_missing_threats = [
        "Element Website [Process]: REPUDIATION.",
        "Element Website [Process]: INFORMATION DISCLOSURE.",
        "Element Website [Process]: DENIAL OF SERVICE.",
        "Element User [External Entity]: REPUDIATION.",
        "Element Dataflow [Data Flow]: TAMPERING.",
        "Element Dataflow [Data Flow]: INFORMATION DISCLOSURE.",
        "Element Dataflow [Data Flow]: DENIAL OF SERVICE.",
    ]

    validation_report = ValidationReport.model_construct()
    validation_report._stride_matrix(report_stride(test_data))
    validation_report._stride_coverage()

    assert validation_report.stride_max_threats == max_threats
    assert validation_report.stride_coverage == f"{covered_threats}/{max_threats}"
    assert validation_report.stride_percentage == correct_percentage
    assert validation_report.non_generated_threats == correct_non_generated_threats
    assert validation_report.missing_threats == correct_missing_threats


def test_stride_coverage_empty():
    validation_report = ValidationReport.model_construct()
    validation_report._stride_coverage()

    assert validation_report.stride_coverage == "0/0"
    assert validation_report.stride_percentage == 0


def test_owasp_coverage(threat_factory):
    test_data = [
        ("Website", "LLM01"),
        ("Website", "LLM02"),
        ("Website", "LLM03"),
        ("User", "LLM04"),
        ("User", "LLM05"),
        ("User", "LLM06"),
        ("Database", "LLM07"),
        ("Database", "LLM08"),
        ("Database", "LLM09"),
        ("Database", "LLM10"),
        ("Dataflow", ""),
        ("Dataflow", None),
    ]
    correct_matrix = {
        "LLM01": True,
        "LLM02": True,
        "LLM03": True,
        "LLM04": True,
        "LLM05": True,
        "LLM06": True,
        "LLM07": True,
        "LLM08": True,
        "LLM09": True,
        "LLM10": True,
    }
    threats = [
        threat_factory(element=element, owasp_top_10_for_llm=owasp)
        for element, owasp in test_data
    ]
    report = Report(message="", threats=threats, is_final=True)

    validation_report = ValidationReport.model_construct()
    validation_report._compute_all_coverages(report)

    assert validation_report.owasp_top_10_for_llm_percentage == 100  # noqa: PLR2004
    assert validation_report.owasp_top_10_for_llm_matrix == correct_matrix


def test_owasp_coverage_partial(threat_factory):
    test_data = [
        ("Website", "LLM01"),
        ("Website", "LLM02"),
        ("User", "LLM04"),
        ("User", "LLM06"),
        ("Database", "LLM07"),
        ("Database", "LLM10"),
        ("Dataflow", ""),
        ("Dataflow", None),
    ]
    correct_percentage = 60
    correct_matrix = {
        "LLM01": True,
        "LLM02": True,
        "LLM03": False,
        "LLM04": True,
        "LLM05": False,
        "LLM06": True,
        "LLM07": True,
        "LLM08": False,
        "LLM09": False,
        "LLM10": True,
    }

    threats = [
        threat_factory(element=element, owasp_top_10_for_llm=owasp)
        for element, owasp in test_data
    ]
    report = Report(message="", threats=threats, is_final=True)

    validation_report = ValidationReport.model_construct()
    validation_report._compute_all_coverages(report)

    assert validation_report.owasp_top_10_for_llm_percentage == correct_percentage
    assert validation_report.owasp_top_10_for_llm_matrix == correct_matrix


def test_aggregated_cvss():
    test_data = [5, 5, 5, 5, 5, 5, 5, 5, 10]

    correct_value = round(50 * CVSS_WEIGHTS["Process"], 2)

    threats = [
        Threat.model_construct(
            element_type="Process",
            cvss_score=cvss_score,
        )
        for cvss_score in test_data
    ]
    report = Report(message="", threats=threats, is_final=True)

    validation_report = ValidationReport.model_construct()
    validation_report._aggregated_cvss(report)

    assert validation_report.aggregated_cvss == correct_value


def test_manual_validation_report_clean():
    data = [
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
    ]
    dataframe = pd.DataFrame.from_records(
        data,
        columns=["validation", "mitigated", "cvss_score", "threat_source"],
    )
    mvr = ManualValidationReport(dataframe, non_generated_threats=0)
    assert mvr.valid_threats == len(data)
    assert mvr.invalid_threats == 0
    assert mvr.manual_threats == 0
    assert mvr.valid_threats_coverage == f"{len(data)}/{len(data)}"
    assert mvr.valid_threats_percentage == 100  # noqa: PLR2004
    assert mvr.mitigated_threats_percentage == 0
    assert mvr.aggregated_residual_cvss == len(data)  # each cvss is 1
    assert mvr.accuracy == 100  # noqa: PLR2004


def test_manual_validation_report_two_parts():
    data = [
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
    ]
    dataframe = pd.DataFrame.from_records(
        data,
        columns=["validation", "mitigated", "cvss_score", "threat_source"],
    )
    mvr = ManualValidationReport(dataframe, non_generated_threats=0)

    data.extend(
        [
            (True, False, 1, "manual"),
            (True, False, 1, "manual"),
        ],
    )
    dataframe_2 = pd.DataFrame.from_records(
        data,
        columns=["validation", "mitigated", "cvss_score", "threat_source"],
    )
    mvr.update(dataframe_2, non_generated_threats=0)

    assert mvr.valid_threats == len(data)
    assert mvr.invalid_threats == 0
    assert mvr.manual_threats == 2  # noqa: PLR2004
    assert mvr.valid_threats_coverage == f"{len(data)}/{len(data)}"
    assert mvr.valid_threats_percentage == 100  # noqa: PLR2004
    assert mvr.mitigated_threats_percentage == 0
    assert mvr.aggregated_residual_cvss == len(data)  # each cvss is 1
    assert mvr.accuracy == 100  # noqa: PLR2004


def test_manual_validation_report_invalid():
    data = [
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (False, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (False, False, 1, "llm"),
        (False, False, 1, "llm"),
        (True, False, 1, "llm"),
    ]
    valid_threats = 7
    dataframe = pd.DataFrame.from_records(
        data,
        columns=["validation", "mitigated", "cvss_score", "threat_source"],
    )
    mvr = ManualValidationReport(dataframe, non_generated_threats=0)

    assert mvr.valid_threats == valid_threats
    assert mvr.invalid_threats == len(data) - valid_threats
    assert mvr.manual_threats == 0
    assert mvr.valid_threats_coverage == f"{valid_threats}/{len(data)}"
    assert mvr.valid_threats_percentage == 70  # noqa: PLR2004
    assert mvr.mitigated_threats_percentage == 0
    assert mvr.aggregated_residual_cvss == valid_threats  # each cvss is 1
    assert mvr.accuracy == 70  # noqa: PLR2004


def test_manual_validation_report_mitigated():
    data = [
        (True, False, 1, "llm"),
        (True, False, 1, "llm"),
        (False, False, 1, "llm"),
        (True, False, 1, "llm"),
        (True, True, 1, "llm"),
        (True, True, 1, "llm"),
        (True, True, 1, "llm"),
        (False, False, 1, "llm"),
        (False, False, 1, "llm"),
        (True, False, 1, "llm"),
    ]
    valid_threats = 7
    mitigated_threats = 3
    dataframe = pd.DataFrame.from_records(
        data,
        columns=["validation", "mitigated", "cvss_score", "threat_source"],
    )
    mvr = ManualValidationReport(dataframe, non_generated_threats=0)

    assert mvr.valid_threats == valid_threats
    assert mvr.invalid_threats == len(data) - valid_threats
    assert mvr.manual_threats == 0
    assert mvr.valid_threats_coverage == f"{valid_threats}/{len(data)}"
    assert mvr.valid_threats_percentage == 70  # noqa: PLR2004
    assert mvr.mitigated_threats_percentage == 30  # noqa: PLR2004
    assert mvr.aggregated_residual_cvss == valid_threats - mitigated_threats
    assert mvr.accuracy == 70  # noqa: PLR2004
