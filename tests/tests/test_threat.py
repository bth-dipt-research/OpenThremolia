import pytest

from thremolia.threat import Report, Threat


@pytest.mark.parametrize(
    ("cvss_vector", "expected_score"),
    [
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:L", 2.7),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:N/I:L/A:H", 5.8),
        ("CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:H", 6.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
        ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:L", 1.0),
        ("AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:H/VA:N/SC:L/SI:N/SA:L", 4.3),
        ("CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:H/VA:L/SC:H/SI:L/SA:H", 6.0),
        ("CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:L/VI:H/VA:L/SC:H/SI:L/SA:H", 7.3),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
        ("", None),
    ],
)
def test_threat_calculate_cvss_score(threat_factory, cvss_vector, expected_score):
    threat_obj: Threat = threat_factory(cvss_vector=cvss_vector)
    threat_obj.calculate_cvss()
    assert threat_obj.cvss_score == expected_score


@pytest.mark.parametrize(
    ("cvss_vector", "expected_vector"),
    [
        (
            "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        ),
        (
            "AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:H/VA:N/SC:L/SI:N/SA:L",
            "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:H/VA:N/SC:L/SI:N/SA:L",
        ),
        ("", ""),
    ],
)
def test_threat_calculate_cvss_prefix_fix(
    threat_factory,
    cvss_vector,
    expected_vector,
):
    threat_obj: Threat = threat_factory(cvss_vector=cvss_vector)
    threat_obj.calculate_cvss()
    assert threat_obj.cvss_vector == expected_vector


@pytest.mark.parametrize(
    ("cvss_vector", "expected_score"),
    [
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/", None),
        ("CVSS:4.0/AV:G/AC:H/AT:P/PR:H/UI:A/VC:L/VI:H/VA:N/SC:L/SI:N/SA:L", None),
    ],
)
def test_threat_calculate_cvss_broken_vector(
    threat_factory,
    cvss_vector,
    expected_score,
):
    threat_obj: Threat = threat_factory(cvss_vector=cvss_vector)
    threat_obj.calculate_cvss()
    assert threat_obj.cvss_score == expected_score


@pytest.mark.parametrize(
    ("cvss_vector", "expected_error"),
    [
        (
            "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/",
            'Invalid CVSS vector: Malformed CVSS3 vector, trailing "/"',
        ),
        (
            "CVSS:4.0/AV:G/AC:H/AT:P/PR:H/UI:A/VC:L/VI:H/VA:N/SC:L/SI:N/SA:L",
            'Invalid CVSS vector: Invalid metric value in CVSS4 vector "AV:G"',
        ),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:L", ""),
    ],
)
def test_threat_get_cvss_error(threat_factory, cvss_vector, expected_error):
    threat_obj: Threat = threat_factory(cvss_vector=cvss_vector)
    assert threat_obj.get_cvss_error() == expected_error


@pytest.mark.parametrize(
    ("owasp_id", "expected_category"),
    [
        ("LLM01: 2025 Prompt Injection", "LLM01: 2025 Prompt Injection"),
        ("Prompt Injection", "Prompt Injection"),
        ("", ""),
        (None, None),
        ("LLM01", "LLM01: 2025 Prompt Injection"),
        ("LLM09", "LLM09: 2025 Misinformation"),
        ("LLM45", "LLM45"),
        ("cat", "cat"),
    ],
)
def test_threat_fix_category_owasp(threat_factory, owasp_id, expected_category):
    threat_obj: Threat = threat_factory(owasp_top_10_for_llm=owasp_id)
    threat_obj.fix_categories()
    assert threat_obj.owasp_top_10_for_llm == expected_category


@pytest.mark.parametrize(
    ("atlas_id", "expected_category"),
    [
        ("AML.T0042: Verify Attack", "AML.T0042: Verify Attack"),
        ("", ""),
        (None, None),
        ("AML.T0042", "AML.T0042: Verify Attack"),
        ("AML.T0006", "AML.T0006: Active Scanning"),
        ("AML.T12345", "AML.T12345"),
        ("cat", "cat"),
    ],
)
def test_threat_fix_category_atlas(threat_factory, atlas_id, expected_category):
    threat_obj: Threat = threat_factory(mitre_atlas=atlas_id)
    threat_obj.fix_categories()
    assert threat_obj.mitre_atlas == expected_category


def test_report_add_part(threat_factory):
    threats = [threat_factory(id=i) for i in range(3)]
    report = Report(
        message="Part 1",
        threats=threats,
        is_final=False,
    )
    extra_threats = [threat_factory(id=i) for i in range(3, 6)]
    extra_report = Report(
        message="Part 2",
        threats=extra_threats,
        is_final=False,
    )
    report.add_part(extra_report)

    expected_threats = [threat_factory(id=i) for i in range(6)]

    assert report.message == "Part 1\n\nPart 2"
    assert report.threats == expected_threats


def test_report_replace_part(threat_factory):
    threats = [threat_factory(id=i, element="original") for i in range(6)]
    report = Report(
        message="Part 1",
        threats=threats,
        is_final=False,
    )
    new_threats = [threat_factory(id=i, element="new") for i in range(3, 8)]
    new_report = Report(
        message="Part 1 New",
        threats=new_threats,
        is_final=False,
    )
    report.replace_part(new_report)

    expected_threats = []
    for i in range(6):
        element = "original" if i < 3 else "new"  # noqa: PLR2004
        expected_threats.append(threat_factory(id=i, element=element))

    assert report.message == "Part 1\n\nPart 1 New"
    assert report.threats == expected_threats


def test_report_calculate_cvss(threat_factory) -> None:
    threat1 = threat_factory(cvss_vector="CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:L")
    threat2 = threat_factory(cvss_vector="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:N/I:L/A:H")
    threat3 = threat_factory(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    report = Report(
        message="test",
        threats=[threat1, threat2, threat3],
        is_final=False,
    )

    report.calculate_cvss()

    assert threat1.cvss_score is not None
    assert threat2.cvss_score is not None
    assert threat3.cvss_score is not None


def test_report_fix_categories(threat_factory) -> None:
    threat1 = threat_factory(owasp_top_10_for_llm="LLM01")
    threat2 = threat_factory(owasp_top_10_for_llm="LLM09")
    threat3 = threat_factory(mitre_atlas="AML.T0042")
    report = Report(
        message="test",
        threats=[threat1, threat2, threat3],
        is_final=False,
    )

    report.fix_categories()

    assert threat1.owasp_top_10_for_llm == "LLM01: 2025 Prompt Injection"
    assert threat2.owasp_top_10_for_llm == "LLM09: 2025 Misinformation"
    assert threat3.mitre_atlas == "AML.T0042: Verify Attack"
