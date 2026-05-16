from math import isnan
from typing import Literal

import pandas as pd
from pydantic import BaseModel, Field

from thremolia.llm_interfaces import LLMInterface
from thremolia.threat import THREAT_MODELS_DATA, Report, Threat

STRIDE_CATEGORIES = [
    "spoofing",
    "tampering",
    "repudiation",
    "information disclosure",
    "denial of service",
    "elevation of privilege",
]

STRIDE_MATRIX = {
    "External Entity": {
        "S": False,
        "T": None,
        "R": False,
        "I": None,
        "D": None,
        "E": None,
    },
    "Process": {
        "S": False,
        "T": False,
        "R": False,
        "I": False,
        "D": False,
        "E": False,
    },
    "Data Flow": {
        "S": None,
        "T": False,
        "R": None,
        "I": False,
        "D": False,
        "E": None,
    },
    "Data Store": {
        "S": None,
        "T": False,
        "R": False,
        "I": False,
        "D": False,
        "E": None,
    },
}

CVSS_WEIGHTS = {
    "External Entity": 1,
    "Process": 1,
    "Data Flow": 1,
    "Data Store": 1,
}

THREAT_THRESHOLD = 5
EMBEDDINGS_THRESHOLD = 5


class Mistake(BaseModel):
    id: int = Field(description="ID of the threat.")
    description: str | None = Field(
        default=None,
        description="Description of the mistake.",
    )
    type: str | None = Field(
        default=None,
        description="Type of the mistake. Possible values: 'Categorization', 'CVSS', 'Embedding', 'General'.",
    )
    valid: bool = Field(default=True, description="True if the mistake is valid.")


class ValidationReport(BaseModel):
    justification: str | None = Field(default=None)
    llm_score: int = Field(default=0, ge=0, le=100)
    health_score: int = Field(default=100, ge=0, le=100)
    mistakes: int = Field(default=0, ge=0)
    mistakes_list: list[Mistake] = Field(default=[])

    stride_coverage: str = Field(default="")
    stride_percentage: int = Field(default=0, ge=0, le=100)
    stride_matrix: dict = Field(default={})
    stride_max_threats: int = Field(
        default=0,
        ge=0,
    )  # used for accuracy in manual validation
    missing_threats: list = Field(default=[])
    non_generated_threats: int = Field(default=0, ge=0)

    owasp_top_10_2025_percentage: int = Field(default=0, ge=0, le=100)
    owasp_top_10_2025_matrix: dict = Field(default={})

    mitre_attack_percentage: int = Field(default=0, ge=0, le=100)
    mitre_attack_matrix: dict = Field(default={})

    mitre_atlas_percentage: int = Field(
        default=0,
        ge=0,
        le=100,
        alias="atlas_percentage",
    )
    mitre_atlas_matrix: dict = Field(default={}, alias="atlas_matrix")

    owasp_top_10_for_llm_percentage: int = Field(
        default=0,
        ge=0,
        le=100,
        alias="owasp_percentage",
    )
    owasp_top_10_for_llm_matrix: dict = Field(default={}, alias="owasp_matrix")

    linddun_percentage: int = Field(default=0, ge=0, le=100)
    linddun_matrix: dict = Field(default={})

    owasp_ml_sec_top_10_2023_percentage: int = Field(default=0, ge=0, le=100)
    owasp_ml_sec_top_10_2023_matrix: dict = Field(default={})

    # Add additional percentage and coverage fields for new threat modeling frameworks below in a format:
    # <threat_model_name>_percentage: int = Field(default=0, ge=0, le=100)
    # <threat_model_name>_matrix: dict = Field(default={})

    custom_metrics: list = Field(default=[])

    aggregated_cvss: float = Field(default=0.0, ge=0.0)

    # currently not used:
    element_count: int = Field(default=0, ge=0)
    dataflow_count: int = Field(default=0, ge=0)

    def __init__(
        self,
        report: Report,
        description: str,
        client: LLMInterface,
        custom_metrics: list[dict] | None = None,
        *,
        validate_distances: bool = True,
        **kwargs: dict,
    ) -> None:
        """
        Performs a set of basic logical checks with the report to determine amount of mistakes in it.
        Calculates a total report Health Score based on overall amount of mistakes.

        Args:
            report (Report): The input report.
            description (str): The system description.
            client (LLMInterface): The LLM client.
            custom_metrics (list[dict] | None): List of custom metrics to be calculated.
            validate_distances (bool): Flag that enables or disables distance validation for threat descriptions using RAG.
            **kwargs: Additional keyword arguments.

        """
        super().__init__(**kwargs)
        self._validate(report, client, validate_distances=validate_distances)
        self._llm_score(report, description, client)
        self._custom_metrics(report, description, client, custom_metrics)
        self._aggregated_cvss(report)

    @classmethod
    def from_dict(cls, report_dict: dict) -> "ValidationReport":
        report_dict["mistakes_list"] = [
            Mistake.model_construct(**mistake)
            for mistake in report_dict["mistakes_list"]
        ]
        return ValidationReport.model_construct(**report_dict)

    def _validate(
        self,
        report: Report,
        client: LLMInterface,
        *,
        validate_distances: bool = True,
    ) -> None:
        """
        Validates the report and calculates the health score.
        """
        self._validate_threats(report)
        self._matrixes(report)
        if validate_distances:
            self._distances(client, report)

        # calculates total percentage of mistakes across all the metrics checked
        # (6 per threat: STRIDE, OWASP, ATLAS, CVSS, uncategorized, embeddings distance)
        fields_checked = len(report.threats) * 6
        if fields_checked == 0:
            self.health_score = 0
        else:
            self.health_score = int(100 - (self.mistakes * 100) / fields_checked)

        # halves max score if the amount of threats is too low
        if not len(report.threats) > THREAT_THRESHOLD:
            self.health_score /= 2
            self._add_mistake(
                0,
                f"Total amount of threats is below the threshold of {THREAT_THRESHOLD}",
                "General",
            )

    def _validate_threats(self, report: Report) -> None:
        for threat in report.threats:
            self._validate_threat_stride(threat)
            self._validate_threat_model_fields(threat)
            self._validate_threat_cvss(threat)
            self._validate_threat_uncategorized(threat)

    def _add_mistake(
        self,
        threat_id: int,
        mistake_info: str,
        mistake_type: Literal["Categorization", "CVSS", "Embedding", "General"],
    ) -> None:
        """Adds a mistake to the report."""
        self.mistakes += 1
        mistake = Mistake(
            id=threat_id,
            description=mistake_info,
            type=mistake_type,
        )
        self.mistakes_list.append(mistake)

    def _validate_threat_cvss(self, threat: Threat) -> None:
        if threat.cvss_score is None or not 0 <= threat.cvss_score <= 10:  # noqa: PLR2004
            self._add_mistake(threat.id, threat.get_cvss_error(), "CVSS")

    def _validate_threat_stride(self, threat: Threat) -> None:
        if threat.stride is None:
            return
        if not any(category in threat.stride.lower() for category in STRIDE_CATEGORIES):
            self._add_mistake(threat.id, "Incorrect STRIDE category", "Categorization")

    def _validate_threat_model_fields(self, threat: Threat) -> None:
        for cfg in THREAT_MODELS_DATA:
            if not ValidationReport._with_dataframe(
                getattr(threat, cfg.threat_field),
                cfg.dataset,
            ):
                self._add_mistake(
                    threat.id,
                    f"Incorrect {cfg.name} category",
                    "Categorization",
                )

    def _validate_threat_uncategorized(self, threat: Threat) -> None:
        """Checks if all fields with categories are empty."""
        if not threat.stride and all(
            not getattr(threat, cfg.threat_field) for cfg in THREAT_MODELS_DATA
        ):
            self._add_mistake(threat.id, "All categories are empty", "Categorization")

    @staticmethod
    def _with_json(value: str, json: list[dict], keys: list[str]) -> bool:
        """
        Checks if the value is in the provided JSON data.

        Args:
            value (str): The value to check.
            json (list[dict]): The JSON data to compare against.
            keys (list[str]): The keys to compare against.

        """
        if value is None:
            return True
        return any(
            threat[keys[0]] in value or threat[keys[1]] in value for threat in json
        )

    @staticmethod
    def _with_dataframe(
        value: str,
        dataframe: pd.DataFrame,
        keys: tuple[str, str] = ("ID", "Title"),
    ) -> bool:
        """
        Checks if the value is in the provided dataframe.

        Args:
            value (str): The value to check.
            dataframe (pd.DataFrame): The data to compare against.
            keys (list[str]): The keys to compare against. Defaults to 'ID', 'Title'.

        """
        if value is None:
            return True

        col1_match = dataframe[keys[0]].astype(str).apply(lambda x: x in value)
        col2_match = dataframe[keys[1]].astype(str).apply(lambda x: x in value)

        return (col1_match | col2_match).any()

    def _stride_matrix(self, report: Report) -> None:
        """
        Constructs a STRIDE matrix for the report and checks coverage for each threat.
        """
        for threat in report.threats:
            if threat.element_type not in STRIDE_MATRIX:
                self._add_mistake(
                    threat.id,
                    "Unsupported element type",
                    "Categorization",
                )
                continue

            key = f"{threat.element} [{threat.element_type}]"
            if key not in self.stride_matrix:
                self.stride_matrix[key] = dict(STRIDE_MATRIX[threat.element_type])

            if not threat.stride:
                continue

            stride_category = threat.stride[0].upper()
            if stride_category in self.stride_matrix[key]:
                if self.stride_matrix[key][stride_category] is not None:
                    self.stride_matrix[key][stride_category] = True
                else:
                    self._add_mistake(
                        threat.id,
                        "Impossible STRIDE threat category according to STRIDE per Element.",
                        "Categorization",
                    )

    def _stride_coverage(self) -> None:
        """
        Calculates the STRIDE coverage and percentage for the report.
        """
        if not self.stride_matrix:
            self.stride_coverage = "0/0"
            self.stride_percentage = 0
            return

        covered = 0
        total_categories = 0
        for element in self.stride_matrix:
            for category in self.stride_matrix[element]:
                if self.stride_matrix[element][category] is None:
                    continue
                if self.stride_matrix[element][category]:
                    total_categories += 1
                    covered += 1
                else:
                    total_categories += 1
                    self.missing_threats.append(
                        f"Element {element}: {ValidationReport._get_stride_category(category)}.",
                    )
                    self.non_generated_threats += 1

        self.stride_max_threats = total_categories
        self.stride_coverage = f"{covered}/{total_categories}"
        self.stride_percentage = int(covered / total_categories * 100)

    @staticmethod
    def _get_stride_category(category: str) -> str:
        for stride_category in STRIDE_CATEGORIES:
            if category.lower() == stride_category[0]:
                return stride_category.upper()
        return category

    @staticmethod
    def _coverage(
        report: Report,
        report_field: str,
        dataframe: pd.DataFrame,
        key_field: str = "ID",
    ) -> tuple[dict, int]:
        """
        Constructs a coverage matrix for the report and calculates the percentage of coverage.

        Args:
            report (Report): The input report.
            report_field (str): The field to check in the report.
            dataframe (pd.DataFrame): The data to compare against.
            key_field (str): The key field to compare against. Defaults to 'ID'.

        Returns:
            tuple: The coverage matrix and percentage.

        """
        # automatically constructs coverage matrix
        matrix = dict.fromkeys(dataframe[key_field], False)
        amount_covered = 0

        threats = report.model_dump()["threats"]
        for threat in threats:
            if threat[report_field] is None:
                continue
            for element in matrix:
                if element in threat[report_field] and not matrix[element]:
                    matrix[element] = True
                    amount_covered += 1
                    break

        percentage = int(amount_covered / len(matrix) * 100)

        return (matrix, percentage)

    def _compute_all_coverages(self, report: Report) -> None:
        """Uses THREAT_MODELS_DATA to compute coverages and matrixes for all provided fields."""
        for cfg in THREAT_MODELS_DATA:
            matrix, percentage = ValidationReport._coverage(
                report,
                cfg.threat_field,
                cfg.dataset,
            )
            setattr(self, f"{cfg.threat_field}_matrix", matrix)
            setattr(self, f"{cfg.threat_field}_percentage", percentage)

    def _matrixes(self, report: Report) -> None:
        self._stride_matrix(report)
        self._stride_coverage()
        self._compute_all_coverages(report)

    def _distances(self, client: LLMInterface, report: Report) -> None:
        """
        Checks the distances between the report threats and the provided ATLAS/OWASP categories.
        Counts as a mistake if the threat is not in the first EMBEDDINGS_THRESHOLD results.
        """
        for threat in report.threats:
            embeddings_df = client.retrieve_embeddings(
                threat.threat_description,
                collections=client.collection_names,
                n_results=EMBEDDINGS_THRESHOLD,
                where={"Type": {"$in": ["Description", "Technique"]}},
            )
            for tm in THREAT_MODELS_DATA:
                classification = getattr(threat, tm.threat_field)
                if not self._check_df(classification, embeddings_df):
                    self._add_mistake(
                        threat.id,
                        f"Potentially unrelated {tm.name} category",
                        "Embedding",
                    )

    def _check_df(self, field: str | None, df: pd.DataFrame) -> bool:
        """
        Checks if the threat ATLAS and/or OWASP categories are in the provided dataframe.
        """
        for _, row in df.iterrows():
            if not field:
                return True
            if row["metadatas"]["ID"] in field:
                return True
        return False

    def _llm_score(
        self,
        report: Report,
        description: str,
        client: LLMInterface,
    ) -> None:
        self.justification, self.llm_score = client.score_report(description, report)

    # currently not used
    def _get_element_count(self, description: str, client: LLMInterface) -> None:
        """Asks the LLM for the number of elements and dataflows in the system description."""
        self.element_count, self.dataflow_count = client.get_element_count(description)

    def _custom_metrics(
        self,
        report: Report,
        description: str,
        client: LLMInterface,
        custom_metrics: list[dict] | None = None,
    ) -> None:
        if custom_metrics is None:
            return
        for custom_metric in custom_metrics:
            if custom_metric["selected"]:
                custom_metric["justification"], custom_metric["value"] = (
                    client.score_report(description, report, custom_metric["condition"])
                )
                self.custom_metrics.append(custom_metric)

    def _aggregated_cvss(self, report: Report) -> None:
        aggregated_cvss = 0
        for threat in report.threats:
            if threat.cvss_score and not isnan(threat.cvss_score):
                weight = CVSS_WEIGHTS.get(threat.element_type, 1)
                aggregated_cvss += threat.cvss_score * weight
        self.aggregated_cvss = round(aggregated_cvss, 2)

    def get_missing_threats(
        self,
        options: list,
    ) -> list:
        """Generates a list of missing threats based on the selected options."""
        missing_threats = []
        for option in options:
            if option == "Fix Mistakes":
                continue
            if option == "STRIDE coverage":
                missing_threats += self.missing_threats
                continue

            short_option = option.removesuffix(" coverage")
            tm_name = next(
                (
                    tm.threat_field
                    for tm in THREAT_MODELS_DATA
                    if tm.name == short_option
                ),
                None,
            )
            if tm_name:
                missing_threats += [
                    category
                    for category, status in getattr(self, f"{tm_name}_matrix").items()
                    if status is False
                ]
        return missing_threats


class ManualValidationReport(BaseModel):
    generated_threats: int = Field(default=0, ge=0)

    valid_threats: int = Field(default=0, ge=0)  # true positive
    invalid_threats: int = Field(default=0, ge=0)  # false positive
    manual_threats: int = Field(default=0, ge=0)  # true negative
    non_generated_threats: int = Field(default=0, ge=0)  # false negative

    valid_threats_coverage: str = Field(default="0/0")
    valid_threats_percentage: int = Field(default=0, ge=0, le=100)
    mitigated_threats_percentage: int = Field(default=0, ge=0, le=100)

    aggregated_residual_cvss: float = Field(default=0.0, ge=0.0)

    accuracy: float = Field(default=0.0, ge=0.0)
    precision: float = Field(default=0.0, ge=0.0)
    recall: float = Field(default=0.0, ge=0.0)
    f1_score: float = Field(default=0.0, ge=0.0)

    def __init__(
        self,
        threats: pd.DataFrame,
        non_generated_threats: int,
        **kwargs: dict,
    ) -> None:
        super().__init__(**kwargs)

        self.update(threats, non_generated_threats)

    def update(self, threats: pd.DataFrame, non_generated_threats: int) -> None:
        if threats.empty:
            return

        total_threats = len(threats)

        self.generated_threats = len(threats.loc[threats["threat_source"] == "llm"])
        self.non_generated_threats = non_generated_threats

        valid_threats = threats[threats["validation"]]

        self.valid_threats = len(valid_threats.index)
        self.invalid_threats = total_threats - self.valid_threats
        self.manual_threats = total_threats - self.generated_threats

        self.valid_threats_coverage = f"{self.valid_threats}/{total_threats}"
        self.valid_threats_percentage = int(
            self.valid_threats / total_threats * 100,
        )

        mitigated_threats = threats[threats["mitigated"]]
        self.mitigated_threats_percentage = int(
            len(mitigated_threats.index) / total_threats * 100,
        )
        self._aggregated_residual_cvss(threats)
        self._calc_binary_metrics()

    def _aggregated_residual_cvss(self, threats: pd.DataFrame) -> None:
        # select threats where mitigated is False
        valid_threats = threats[
            (threats["validation"]) & (threats["mitigated"] == False)  # noqa: E712
        ]
        self.aggregated_residual_cvss = round(valid_threats["cvss_score"].sum(), 2)

    def _calc_binary_metrics(self) -> None:
        self._calc_accuracy()
        self._calc_precision()
        self._calc_recall()
        self._calc_f1_score()

    def _calc_accuracy(self) -> None:
        # binary accuracy function: (TP + TN) / (TP + TN + FP + FN)
        accuracy = (self.valid_threats + self.manual_threats) / (
            self.valid_threats
            + self.manual_threats
            + self.invalid_threats
            + self.non_generated_threats
        )
        self.accuracy = int(accuracy * 100)

    def _calc_precision(self) -> None:
        # binary precision function: TP / (TP + FP)
        precision = self.valid_threats / (self.valid_threats + self.invalid_threats)
        self.precision = int(precision * 100)

    def _calc_recall(self) -> None:
        # binary recall function: TP / (TP + FN)
        recall = self.valid_threats / (self.valid_threats + self.non_generated_threats)
        self.recall = int(recall * 100)

    def _calc_f1_score(self) -> None:
        # binary f1 function: 2 * (precision * recall) / (precision + recall)
        f1_score = 2 * ((self.precision * self.recall) / (self.precision + self.recall))
        self.f1_score = int(f1_score)
