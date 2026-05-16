import json
from collections import OrderedDict
from collections.abc import Callable
from typing import Literal, get_type_hints

import streamlit as st
from pydantic import BaseModel, ConfigDict, Field, create_model

from thremolia.threat import Report, Threat
from thremolia.utils import logger


class ThreatUpdate(BaseModel):
    action: Literal["update", "add", "delete"] = Field(
        description="Action to be performed with this thread. Allowed actions: 'update', 'add', 'delete'",
    )
    threat_id: int = Field(
        description="ID of existing or new threat.",
    )
    threat: Threat | None = Field(
        description="New or modified threat to be used in the updated report.",
    )

    model_config = ConfigDict(json_schema_extra={"additionalProperties": False})


def get_threat(threat_id: int) -> str:
    """Returns threat by its ID as a string."""
    logger.info(f"Toolset MCP: get_threat called. {threat_id =}")
    report: Report = st.session_state.get("report")
    if report is None:
        return "Error. No report found."

    for threat in report.threats:
        if threat.id == threat_id:
            return f"Success. Threat: {threat.model_dump_json()}"

    return f"Error. No threat found with id {threat_id}"


def update_threat(
    threat_id: int,
    fields: list[str],
    new_values: list[str],
) -> str:
    """
    Updates selected threat fields with new values.
    Returns updated threat.
    """
    logger.info(
        f"Toolset MCP: update_threat called. {threat_id =} {fields =} {new_values =}"
    )
    report: Report = st.session_state.get("report")
    if report is None:
        return "Error. No report found."

    for threat in report.threats:
        if threat.id == threat_id:
            update_data = dict(zip(fields, new_values, strict=True))
            updated_threat = threat.model_copy(update=update_data)

            updated_threat.calculate_cvss()
            updated_threat.fix_categories()
            report.threats[report.threats.index(threat)] = updated_threat

            return f"Success. Updated threat {threat.id}"

    return f"Error. No threat found with id {threat_id}"


def delete_threat(threat_id: int) -> str:
    """Deletes selected threat from the report by its ID."""
    logger.info(f"Toolset MCP: delete_threat called. {threat_id =}")
    report: Report = st.session_state.get("report")
    if report is None:
        return "Error. No report found."

    for threat in report.threats:
        if threat.id == threat_id:
            report.threats.pop(report.threats.index(threat))
            return f"Success. Threat with id {threat_id} deleted."

    return f"Error. No threat found with id {threat_id}"


def add_threat(threat: Threat) -> str:
    """Adds a new threat to the report."""
    logger.info(f"Toolset MCP: add_threat called. {threat =}")
    report: Report = st.session_state.get("report")
    if report is None:
        return "Error. No report found."

    if isinstance(threat, dict):
        threat = Threat(**threat)

    threat.calculate_cvss()
    threat.fix_categories()
    report.threats.append(threat)
    return f"Success. Threat {threat.id} was added."


def update_report(threat_updates: list[ThreatUpdate]) -> str:
    logger.info(f"Toolset MCP: update_report called. {threat_updates =}")
    report: Report = st.session_state.get("report")
    if report is None:
        return "Error. No report found."

    threats_by_id = OrderedDict((t.id, t) for t in report.threats)
    response = ""

    for threat_update in threat_updates:
        if isinstance(threat_update, dict):
            update = ThreatUpdate.model_construct(**threat_update)
        else:
            update = threat_update
        update.threat.calculate_cvss()
        update.threat.fix_categories()
        if update.action == "add":
            threats_by_id[update.threat.id] = update.threat
            response += f"Threat {update.threat.id} added\n"
        elif update.action == "update" and update.threat.id in threats_by_id:
            threats_by_id[update.threat.id] = update.threat
            response += f"Threat {update.threat.id} updated\n"
        elif update.action == "delete":
            threats_by_id.pop(update.threat_id, None)
            response += f"Threat {update.threat.id} deleted\n"
        else:
            logger.warning(
                f"Toolset MCP: update_report: unsupported action {update.action =}",
            )
            response += f"Threat {update.threat.id} unsupported action!\n"

    report.threats = list(threats_by_id.values())

    return f"Success. Report was updated. \n {response}"


def construct_schema(func: Callable) -> dict:
    hints = get_type_hints(func)
    dynamic_model = create_model(
        f"{func.__name__}Params",
        __config__=ConfigDict(extra="forbid"),
        **{k: (v, ...) for k, v in hints.items() if k != "return"},
    )
    return {
        "type": "function",
        "function": {
            "name": func.__name__,
            "description": func.__doc__,
            "parameters": dynamic_model.model_json_schema(),
            "strict": True,
        },
    }


def construct_schemas(funcs: list[Callable]) -> list[dict]:
    return [construct_schema(func) for func in funcs]


TOOLSET = construct_schemas(
    [
        get_threat,
        add_threat,
        update_threat,
        delete_threat,
        update_report,
    ],
)

TOOLS_WITHOUT_REPORT_UPDATE = [
    "get_threat",
]  # used to check if the report was changed during the tool execution


def call_function(name: str, args: str | dict) -> str:
    if isinstance(args, str):
        args = json.loads(args)

    if name == "get_threat":
        return get_threat(**args)
    if name == "update_threat":
        return update_threat(**args)
    if name == "delete_threat":
        return delete_threat(**args)
    if name == "add_threat":
        return add_threat(**args)
    if name == "update_report":
        return update_report(**args)

    return f"Error. No function found with the name {name}."
