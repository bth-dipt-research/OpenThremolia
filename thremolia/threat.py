from typing import Literal

import pandas as pd
from cvss import CVSS3, CVSS4, CVSS3Error, CVSS4Error
from pydantic import BaseModel, ConfigDict, Field
from pydantic.json_schema import SkipJsonSchema

from thremolia.utils import DATASETS_PATH, PROMPTS_PATH, logger


class ThreatModelConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    threat_field: str
    dataset: pd.DataFrame
    id_len: int
    prompt: str


# If you are adding a new threat modeling frameworks, don't forget to add extra fields to the ValidationReport and Threat classes!
THREAT_MODELS_DATA = [
    ThreatModelConfig(
        name="OWASP Top 10 2025",
        threat_field="owasp_top_10_2025",
        dataset=pd.read_csv(DATASETS_PATH / "OWASP_Top10_2025.csv", sep=";"),
        id_len=10,
        prompt=(PROMPTS_PATH / "OWASP_Top10_2025.md").read_text(),
    ),
    ThreatModelConfig(
        name="MITRE ATT&CK",
        threat_field="mitre_attack",
        dataset=pd.read_csv(DATASETS_PATH / "MITRE_ATT&CK_techniques.csv", sep=";"),
        id_len=10,
        prompt=(PROMPTS_PATH / "MITRE_ATT&CK.md").read_text(),
    ),
    ThreatModelConfig(
        name="OWASP TOP 10 for LLM",
        threat_field="owasp_top_10_for_llm",
        dataset=pd.read_csv(DATASETS_PATH / "OWASP_2025.csv", sep=";"),
        id_len=6,
        prompt=(PROMPTS_PATH / "OWASP_TOP_10_for_LLMs_2025_threat_list.md").read_text(),
    ),
    ThreatModelConfig(
        name="MITRE ATLAS",
        threat_field="mitre_atlas",
        dataset=pd.read_csv(DATASETS_PATH / "MITRE_ATLAS.csv", sep=";"),
        id_len=10,
        prompt=(PROMPTS_PATH / "MITRE_ATLAS_threat_list.md").read_text(),
    ),
    ThreatModelConfig(
        name="LINDDUN",
        threat_field="linddun",
        dataset=pd.read_csv(DATASETS_PATH / "LINDDUN.csv", sep=";"),
        id_len=12,
        prompt=(PROMPTS_PATH / "LINDDUN_threat_list.md").read_text(),
    ),
    ThreatModelConfig(
        name="OWASP ML Security Top 10 2023",
        threat_field="owasp_ml_sec_top_10_2023",
        dataset=pd.read_csv(DATASETS_PATH / "OWASP_ML_Sec_Top10_2023.csv", sep=";"),
        id_len=10,
        prompt=(PROMPTS_PATH / "OWASP_ML_Sec_Top10_2023.md").read_text(),
    ),
]

THREAT_MODELS = ["STRIDE", *[tm.name for tm in THREAT_MODELS_DATA]]


class Message(BaseModel):
    message: str = Field(
        description="Formatting re-enabled — please use Markdown **bold**, _italics_, and header tags to **improve the readability** of your responses.",
    )


class Threat(BaseModel):
    id: int = Field(title="ID", description="Item ID.")
    element: str = Field(
        description="Element name or name of connection between elements where the threat is present (e.g. Element1 -> Element2).",
    )
    threat_description: str = Field(description="Short threat description.")
    element_type: str = Field(
        description="Supported element types are: External Entity, Process, Data Flow, Data Store.",
    )
    stride: str | None = Field(description="Threat category according to STRIDE.")
    mitre_attack: str | None = Field(
        alias="Mitre ATT&CK",
        description="Threat category according to MITRE ATT&CK.",
    )
    owasp_top_10_2025: str | None = Field(
        alias="OWASP Top 10 2025",
        description="Threat category according to OWASP TOP 10 2025.",
    )
    mitre_atlas: str | None = Field(
        description="Threat category according to MITRE ATLAS.",
    )
    owasp_top_10_for_llm: str | None = Field(
        description="Threat category according to OWASP TOP 10 for LLM.",
    )
    linddun: str | None = Field(
        description="Threat category according to LINDDUN.",
    )
    owasp_ml_sec_top_10_2023: str | None = Field(
        description="Threat category according to OWASP ML Security Top 10 2023",
    )
    mitigation: str = Field(description="Short description of possible mitigation(s).")
    SDL_stage: Literal[
        "Requirements",
        "Design",
        "Implementation",
        "Verification",
        "Maintenance",
    ] = Field(description="SDL stage where threat should be mitigated.")
    cvss_vector: str = Field(
        description="Vector String of the treat according to CVSS 3.1",
    )
    # Excluded from JSON schema fields:
    cvss_score: SkipJsonSchema[float | None] = Field(default=None)
    threat_source: SkipJsonSchema[str | None] = Field(
        default="llm",
        description="Source of the threat. Can be 'llm' or 'manual'.",
    )
    validation: SkipJsonSchema[bool] = Field(default=True)
    justification: SkipJsonSchema[str | None] = Field(default=None)
    mitigated: SkipJsonSchema[bool] = Field(default=False)

    model_config = ConfigDict(json_schema_extra={"additionalProperties": False})

    def calculate_cvss(self) -> None:
        """Calculates CVSS score from vector using cvss module"""
        if not self.cvss_vector:
            return

        # basic vector version validation
        if not ("CVSS:3.1/" in self.cvss_vector or "CVSS:4.0/" in self.cvss_vector):
            # Attack Requirements (AT) are only present in CVSS 4.0
            if "/AT:" in self.cvss_vector:
                self.cvss_vector = "CVSS:4.0/" + self.cvss_vector
            else:
                self.cvss_vector = "CVSS:3.1/" + self.cvss_vector

        try:
            if "CVSS:4.0/" in self.cvss_vector:
                score = CVSS4(self.cvss_vector)
            else:
                score = CVSS3(self.cvss_vector)
            if score.base_score != self.cvss_score:
                self.cvss_score = float(score.base_score)
        except (CVSS3Error, CVSS4Error) as error:
            logger.warning(error)
        return

    def get_cvss_error(self) -> str:
        """
        Validates CVSS vector.

        Returns:
            str: Error message if the vector is invalid, empty string otherwise.

        """
        try:
            if "CVSS:4.0/" in self.cvss_vector:
                CVSS4(self.cvss_vector)
            else:
                CVSS3(self.cvss_vector)
        except (CVSS3Error, CVSS4Error) as error:
            return f"Invalid CVSS vector: {error}"
        return ""

    def fix_categories(self) -> None:
        for cfg in THREAT_MODELS_DATA:
            category = Threat._fix_category(
                getattr(self, cfg.threat_field),
                cfg.id_len,
                cfg.dataset,
            )
            setattr(self, cfg.threat_field, category)

    @staticmethod
    def _fix_category(
        category: str | None,
        length_threshold: int,
        dataframe: pd.DataFrame,
        keys: list[str] = ("ID", "Title"),
    ) -> str | None:
        """
        Compares the provided category with categories from dataframe by ID
        and returns extended category in a form of `<ID>: <Title>`
        or the same category if no matches were found.

        Args:
            category (str | None): The threat ID.
            length_threshold (int): Max possible length of ID.
            dataframe (pd.DataFrame): Dataframe with list of threats.
            keys (tuple[str, str], optional): Column names in dataframe to use.
                Defaults to ("ID", "Title").

        Returns:
            str | None: Extended category in a form of `<ID>: <Title>` or the
            same category if no matches were found.

        """
        if not category or category in {"", " ", "-", "None", "N/A", "NaN", "null"}:
            return None

        if len(category) <= length_threshold:
            result = dataframe.loc[dataframe[keys[0]].str.contains(category), keys]
            new_category = result.iloc[0, 0] if not result.empty else None
            title = result.iloc[0, 1] if not result.empty else None
            if title:
                return f"{new_category}: {title}"
        return category


class ReportScore(BaseModel):
    justification: str = Field(
        description="Brief justification of report accuracy and final score. Supports Markdown.",
    )
    report_score: int = Field(
        description="Accuracy score from 0 to 100 of how accurate the resulting report is.",
    )


class ElementCount(BaseModel):
    message: str = Field(description="Your initial thought process. Supports Markdown.")
    element_count: int = Field(description="Amount of elements in the description.")
    dataflow_count: int = Field(description="Amount of dataflows in the system.")


class Report(BaseModel):
    message: str = Field(
        description="Your initial thought process. Supports Markdown. **!!!DO NOT PUT THREATS HERE!!!**",
    )
    threats: list[Threat] = Field(
        description="List of threats that are present in the described system.",
    )
    is_final: bool = Field(
        description="Is True if this is the final part of the report.",
    )

    @classmethod
    def from_dict(cls, report_dict: dict) -> "Report":
        report_dict["threats"] = [
            Threat.model_construct(**threat) for threat in report_dict["threats"]
        ]
        return cls.model_construct(**report_dict)

    def calculate_cvss(self) -> None:
        """Calculates CVSS scores from vectors using cvss module."""
        for threat in self.threats:
            threat.calculate_cvss()

    def add_part(self, part: "Report") -> None:
        """Combines two reports into one."""
        self.message = self.message + "\n\n" + part.message
        self.threats.extend(part.threats)

    def replace_part(self, part: "Report") -> None:
        """Replaces threats in the report with new ones."""
        self.message = self.message + "\n\n" + part.message
        for new_threat in part.threats:
            for i in range(len(self.threats)):
                if self.threats[i].id == new_threat.id:
                    self.threats[i] = new_threat
                    break

    def fix_categories(self) -> None:
        """Fixes threat categories names."""
        for threat in self.threats:
            threat.fix_categories()
